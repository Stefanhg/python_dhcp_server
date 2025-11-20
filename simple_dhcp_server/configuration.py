from typing import List

from simple_dhcp_server.decoders import get_host_ip_addresses
from simple_dhcp_server.utils import NETWORK, ip_addresses, ip_to_int


class DHCPServerConfiguration(object):
    dhcp_offer_after_seconds = 0
    """Time to wait before sending DHCPOFFER (in seconds). Can be used to simulate network delay."""
    dhcp_acknowledge_after_seconds = 0
    """Time to wait before sending DHCPACK (in seconds). Can be used to simulate network delay."""
    length_of_transaction = 40
    """Length of transaction in seconds. If no progress is made in this time, the transaction is removed."""

    ip_ranges = [
        # Start, End
        ("192.168.137.10", "192.168.137.100"),
        ("192.168.137.120", "192.168.137.150"),
    ]
    """Range of the IPs. Supports specifying multiple ranges"""

    bind_address = ''
    """IP address to bind the DHCP server to. If empty, binds to all interfaces."""
    network = '192.168.137.0'
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

    @staticmethod
    def filter_ips_within(ips: List[str], ip_min: str, ip_max: str) -> List[str]:
        """
        Return the IPs from ``ips`` that fall between ``ip_min`` and ``ip_max`` (inclusive).

        Parameters
        ----------
        ips : list[str]
            List of IPs, e.g. ["192.168.0.13", "192.168.0.15"].
        ip_min : str
            Lower bound of the range, e.g. "192.168.0.12".
        ip_max : str
            Upper bound of the range, e.g. "192.168.0.15".

        Returns
        -------
        list[str]
            IPs from ``ips`` such that ip_min <= ip <= ip_max.
        """

        lo = ip_to_int(ip_min)
        hi = ip_to_int(ip_max)

        # In case user swaps min/max by mistake
        if lo > hi:
            lo, hi = hi, lo

        return [ip for ip in ips if lo <= ip_to_int(ip) <= hi]

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
        s = self.subnet_mask.split('.')
        n = self.network.split('.')
        ip_valid = all(s[i] == '0' or a[i] == n[i] for i in range(4))

        if ip_valid:
            return len(self.filter_ips_within_ip_range([address])) != 0
        return False

    def filter_ips_within_ip_range(self, ips: list[str]):
        # Filter IPs not within self.ip_ranges

        collected: list[str] = []
        for ip_min, ip_max in self.ip_ranges:
            collected.extend(self.filter_ips_within(ips, ip_min=ip_min, ip_max=ip_max))

        # Deduplicate while preserving order
        seen: set[str] = set()
        result: list[str] = []
        for ip in collected:
            if ip not in seen:
                seen.add(ip)
                result.append(ip)
        return result

    def all_ip_addresses(self):
        """
        Generator for all IP addresses in the configured network, skipping the first 5 addresses.
        """
        ips = ip_addresses(self.network, self.subnet_mask)

        # Skip the first 5 addresses (network address, router, DHCP server, and two reserved addresses)
        for i in range(5):
            next(ips)

        # Filter IPs not within self.ip_ranges
        ips = self.filter_ips_within_ip_range(ips)
        return ips

    def network_filter(self):
        return NETWORK(self.network, self.subnet_mask)
