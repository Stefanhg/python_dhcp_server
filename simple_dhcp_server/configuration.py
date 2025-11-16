from simple_dhcp_server.decoders import get_host_ip_addresses
from simple_dhcp_server.utils import NETWORK, ip_addresses


class DHCPServerConfiguration(object):
    dhcp_offer_after_seconds = 10
    dhcp_acknowledge_after_seconds = 10
    length_of_transaction = 40

    bind_address = ''
    network = '192.168.173.0'
    broadcast_address = '255.255.255.255'
    subnet_mask = '255.255.255.0'
    router = None  # list of ips
    # 1 day is 86400
    ip_address_lease_time = 300  # seconds
    domain_name_server = None  # list of ips

    host_file = 'hosts.csv'

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
