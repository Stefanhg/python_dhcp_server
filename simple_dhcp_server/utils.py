import socket
import struct

import psutil
from _socket import inet_aton
from scapy.all import show_interfaces


def get_interfaces():
    ifaces = show_interfaces()
    print(ifaces)
    return ifaces


def get_interface_by_ip(ip_address):
    # Get all network interfaces
    addrs = psutil.net_if_addrs()

    # Iterate over the interfaces and check the associated IP address
    for iface, iface_info in addrs.items():
        for addr in iface_info:
            if addr.family == socket.AF_INET and addr.address == ip_address:
                return iface
    return None


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(':', ''))


def ether_client_id(mac: str) -> bytes:
    # RFC 2132: type 1 (Ethernet) + 6 bytes MAC
    return bytes([0x01]) + mac_bytes(mac)


def is_ip_in_network(ip, network, subnet_mask):
    """Check if an IP address belongs to a specific network."""
    subnet_mask_int = struct.unpack('>I', socket.inet_aton(subnet_mask))[0]
    network_int = struct.unpack('>I', socket.inet_aton(network))[0]
    ip_int = struct.unpack('>I', socket.inet_aton(ip))[0]
    return ip_int & subnet_mask_int == network_int


def ip_addresses(network, subnet_mask):
    subnet_mask = struct.unpack('>I', socket.inet_aton(subnet_mask))[0]
    network = struct.unpack('>I', socket.inet_aton(network))[0]
    network = network & subnet_mask
    start = network + 1
    end = (network | (~subnet_mask & 0xffffffff))
    return (socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end))


class ALL(object):
    def __eq__(self, other):
        return True

    def __repr__(self):
        return self.__class__.__name__


ALL = ALL()


class GREATER(object):
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return type(self.value)(other) > self.value


class NETWORK(object):
    def __init__(self, network, subnet_mask):
        self.subnet_mask = struct.unpack('>I', inet_aton(subnet_mask))[0]
        self.network = struct.unpack('>I', inet_aton(network))[0]

    def __eq__(self, other):
        ip = struct.unpack('>I', inet_aton(other))[0]
        return ip & self.subnet_mask == self.network and \
            ip - self.network and \
            ip - self.network != ~self.subnet_mask & 0xffffffff


def sorted_hosts(hosts):
    hosts = list(hosts)
    hosts.sort(key=lambda host: (host.hostname.lower(), host.mac.lower(), host.ip.lower()))
    return hosts
