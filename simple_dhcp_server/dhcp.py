import collections
import socket
import struct
import time
import traceback
from ssl import SOL_SOCKET

from _socket import inet_aton, SO_REUSEADDR, SOCK_DGRAM, SO_BROADCAST
from scapy.sendrecv import AsyncSniffer
from scapy.all import DHCP, BOOTP, IP

from simple_dhcp_server.configuration import DHCPServerConfiguration
from simple_dhcp_server.decoders import ReadBootProtocolPacket, get_host_ip_addresses, macpack, WriteBootProtocolPacket
from simple_dhcp_server.delay_worker import DelayWorker
from simple_dhcp_server.host_database import HostDatabase, Host
from simple_dhcp_server.log import log
from simple_dhcp_server.transaction import Transaction
from simple_dhcp_server.utils import get_interface_by_ip, ether_client_id, sorted_hosts, GREATER


class DHCPServer(object):

    def __init__(self, configuration=None):
        if configuration is None:
            configuration = DHCPServerConfiguration()
        self.configuration = configuration
        self.delay_worker = DelayWorker()
        self.closed = False
        self.transactions = collections.defaultdict(lambda: Transaction(self))  # id: transaction
        self.hosts = HostDatabase(self.configuration.host_file)

        self.time_started = time.time()

        log.debug(f"Binding to IP {self.configuration.bind_address}")
        iface = get_interface_by_ip(self.configuration.bind_address)
        log.debug(f"Using iface {iface}")
        self.sniffer = AsyncSniffer(
            prn=self.packet_handler,
            filter="udp and port 67",
            store=False,  # sniffer.results unused
            iface=iface
        )

    def start(self):
        self.closed = False
        self.sniffer.start()

    def close(self):
        log.debug("Closing DHCP server...")

        for transaction in list(self.transactions.values()):
            transaction.close()

        self.closed = True
        self.delay_worker.close()

        log.debug("Stopping packet sniffer...")
        if self.sniffer is not None and getattr(self.sniffer, "running", False):
            self.sniffer.stop()  # stops even if no packets are coming

        log.debug("Waiting for delay worker thread to finish...")
        #self.delay_worker.thread.join()

    def packet_handler(self, packet):
        if self.closed:
            return
        try:
            if packet.haslayer(DHCP) and packet[DHCP].options[0][1] == 1:  # DHCPDISCOVER
                log.debug(f"DHCPDISCOVER packet received from {packet[IP].src}")
            log.debug('received:\n {}'.format(str(packet).replace('\n', '\n\t')))
            packet_dec = ReadBootProtocolPacket(packet[BOOTP].original)

            log.debug('Decoded:\n {}'.format(str(packet_dec).replace('\n', '\n\t')))

            self.received(packet_dec)

            for transaction_id, transaction in list(self.transactions.items()):
                if transaction.is_done():
                    transaction.close()
                    self.transactions.pop(transaction_id)

        except:  # noqa acceptable
            log.debug(traceback.format_exc())

    def received(self, packet):
        """
        Handle a received DHCP packet.
        """
        if not self.transactions[packet.transaction_id].receive(packet):
            log.debug('received:\n {}'.format(str(packet).replace('\n', '\n\t')))

    def client_has_chosen(self, packet):
        """
        Update the host database when a client has chosen an IP address.
        """
        log.debug('client_has_chosen:\n {}'.format(str(packet).replace('\n', '\n\t')))
        host = Host.from_packet(packet)
        if not host.has_valid_ip():
            return
        self.hosts.replace(host)

    def get_ip_address(self, packet):
        """
        Determine the IP address to assign to the client based on the packet and known hosts.
        Parameters
        ----------
        packet : str
            The DHCP packet received from the client.

        Returns
        -------
        str :
            The IP address to assign to the client.
            1. If the client is known, choose its known IP address.
            2. If the client requested a valid IP address, choose that.
            3. Choose a new, free IP address from the pool.
            4. If no free IP addresses are available, reuse the oldest valid IP address.
        """
        mac_address = packet.client_mac_address
        requested_ip_address = packet.requested_ip_address
        known_hosts = self.hosts.get(mac=mac_address)
        assigned_addresses = set(host.ip for host in self.hosts.get())
        ip = None

        # If IP already previously assigned in DHCP server, assign it to same Ip again.
        if known_hosts:
            for host in known_hosts:
                if self.configuration.is_valid_client_address(host.ip):
                    ip = host.ip
            log.debug(f'known ip: {ip}')

        # If ip is not already known, check if the requested IP is available
        if ip is None and self.configuration.is_valid_client_address(requested_ip_address) and ip not in assigned_addresses:
            ip = requested_ip_address
            log.debug(f'valid ip: {ip}')

        # If IP is not known or available, get an new IP
        if ip is None:
            chosen = False

            # Get devices already assigned
            network_hosts = self.hosts.get(ip=self.configuration.network_filter())

            # Get all IP combinations
            for ip in self.configuration.all_ip_addresses():
                if not any(host.ip == ip for host in network_hosts):
                    chosen = True
                    break

            # Workaround for not having support for cleaning up the leased hosts.
            # Todo make DHCP clean up old leases if expired and remove this.
            if not chosen:
                log.info("NO more IPS available, reuses last used IP which may already be used")
                if len(network_hosts) == 0:
                    log.error("CONFIGURATION ERROR! No IPs has been assigned but no IPs was available.")
                network_hosts.sort(key=lambda host: host.last_used)
                ip = network_hosts[0].ip
                if not self.configuration.is_valid_client_address(ip):
                    raise Exception("Assigned IP is not valid")
            else:
                log.info(f"New IP assigned: {ip}")

        if not any([host.ip == ip for host in known_hosts]):
            log.debug(f'add {mac_address} {ip} {packet.host_name}')
            self.hosts.replace(Host(mac_address, ip, packet.host_name or '', time.time()))
        return ip

    @property
    def server_identifiers(self):
        return get_host_ip_addresses()

    def broadcast(self, packet):
        log.debug('broadcasting:\n {}'.format(str(packet).replace('\n', '\n\t')))
        for addr in self.server_identifiers:
            broadcast_socket = socket.socket(type=SOCK_DGRAM)
            broadcast_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            broadcast_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            packet.server_identifier = addr
            broadcast_socket.bind((addr, 67))
            try:
                data = packet.to_bytes()
                broadcast_socket.sendto(data, ('255.255.255.255', 68))
                broadcast_socket.sendto(data, (addr, 68))
            except:
                log.debug(traceback.format_exc())
            finally:
                broadcast_socket.close()

    def get_all_hosts(self):
        return sorted_hosts(self.hosts.get())

    def get_current_hosts(self):
        return sorted_hosts(self.hosts.get(last_used=GREATER(self.time_started)))
