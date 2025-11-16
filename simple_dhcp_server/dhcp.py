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

    def is_valid_client_address(self, address: None | str):
        """
        Check if the given address is a valid client address within the configured network.
        Parameters
        ----------
        address : str
            The IP address to check.
            If None, returns False.
        Returns
        -------
        bool :
            True if the address is valid for a client, False otherwise.
        """
        if address is None:
            return False
        a = address.split('.')
        s = self.configuration.subnet_mask.split('.')
        n = self.configuration.network.split('.')
        return all(s[i] == '0' or a[i] == n[i] for i in range(4))

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
        if known_hosts:
            # 1. choose known ip address
            for host in known_hosts:
                if self.is_valid_client_address(host.ip):
                    ip = host.ip
            log.debug(f'known ip: {ip}')
        if ip is None and self.is_valid_client_address(requested_ip_address) and ip not in assigned_addresses:
            # 2. choose valid requested ip address
            ip = requested_ip_address
            log.debug(f'valid ip: {ip}')
        if ip is None:
            # 3. choose new, free ip address
            chosen = False
            network_hosts = self.hosts.get(ip=self.configuration.network_filter())
            for ip in self.configuration.all_ip_addresses():
                if not any(host.ip == ip for host in network_hosts):
                    chosen = True
                    break
            if not chosen:
                # 4. reuse old valid ip address
                network_hosts.sort(key=lambda host: host.last_used)
                ip = network_hosts[0].ip
                assert self.is_valid_client_address(ip)
            log.debug(f'new ip: {ip}')
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

    def debug_clients(self):
        for line in self.ips.all():
            line = '\t'.join(line)
            if line:
                log.debug(line)

    def get_all_hosts(self):
        return sorted_hosts(self.hosts.get())

    def get_current_hosts(self):
        return sorted_hosts(self.hosts.get(last_used=GREATER(self.time_started)))

    def release_ip(self, address: str):
        """
        Release the given IP address from DHCP.
        """
        raise NotImplementedError("Function is not working.")
        # Find the host associated with the IP address
        hosts_to_remove = [host for host in self.hosts.get() if host.ip == address]
        if not hosts_to_remove:
            log.debug(f"No host found with IP address {address} to release.")
            return

        host = hosts_to_remove[0]

        # Construct the DHCPRELEASE packet
        release_packet = WriteBootProtocolPacket(self.configuration)

        release_packet.client_mac_address = host.mac  # Client MAC address in binary
        release_packet.client_ip_address = host.ip  # Client IP address
        release_packet.transaction_id = int(time.time())  # Transaction ID
        release_packet.dhcp_message_type = 'DHCPRELEASE'
        self.broadcast(release_packet)


        # Remove the host from the database
        self.hosts.delete(host)
        log.debug(f"Released IP {address} and removed host {host.mac} from the database.")