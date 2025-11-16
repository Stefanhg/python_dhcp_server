from simple_dhcp_server.decoders import get_host_ip_addresses
from simple_dhcp_server.utils import NETWORK, ip_addresses


class DHCPServerConfiguration(object):
    dhcp_offer_after_seconds = 0
    """Time to wait before sending DHCPOFFER (in seconds). Can be used to simulate network delay."""
    dhcp_acknowledge_after_seconds = 0
    """Time to wait before sending DHCPACK (in seconds). Can be used to simulate network delay."""
    length_of_transaction = 40
    """Length of transaction in seconds. If no progress is made in this time, the transaction is removed."""

    bind_address = ''
    """IP address to bind the DHCP server to. If empty, binds to all interfaces."""
    network = '192.168.173.0'
    """Network address. Used to determine the range of IP addresses to assign."""
    broadcast_address = '255.255.255.255'
    """Broadcast address."""
    subnet_mask = '255.255.255.0'
    """Subnet mask."""
    router = None
    """Router (default gateway) IP address(es). If None, no router is provided."""
    # 1 day is 86400
    ip_address_lease_time = 300  # seconds
    """IP address lease time in seconds."""
    domain_name_server = None
    """Domain Name Server (DNS) IP address(es). If None, no DNS is provided."""

    host_file = 'hosts.csv'
    """Path to the host database file."""

    def load(self, file):
        with open(file) as f:
            exec(f.read(), self.__dict__)

    def load_yaml(self, file: str):
        """Load a yaml file."""
        import yaml
        with open(file) as f:
            self.__dict__.update(yaml.safe_load(f))

    def adjust_if_this_computer_is_a_router(self):
        ip_addresses = get_host_ip_addresses()
        for ip in reversed(ip_addresses):
            if ip.split('.')[-1] == '1':
                self.router = [ip]
                self.domain_name_server = [ip]
                self.network = '.'.join(ip.split('.')[:-1] + ['0'])
                self.broadcast_address = '.'.join(ip.split('.')[:-1] + ['255'])
                # self.ip_forwarding_enabled = True
                # self.non_local_source_routing_enabled = True
                # self.perform_mask_discovery = True

    def all_ip_addresses(self):
        ips = ip_addresses(self.network, self.subnet_mask)
        for i in range(5):
            next(ips)
        return ips

    def network_filter(self):
        return NETWORK(self.network, self.subnet_mask)
