import pytest

from simple_dhcp_server.configuration import DHCPServerConfiguration


class TestsIpRange:

    @pytest.mark.parametrize("test_data", [
            (["192.168.15.0"], "192.168.15.0", "192.168.15.0", ["192.168.15.0"]),
            (["192.168.15.0"], "192.168.15.1", "192.168.15.2", []),
            (["192.168.15.3"], "192.168.15.1", "192.168.15.2", []),
            (["192.168.15.1", "192.168.15.2", "192.168.15.3"], "192.168.15.0", "192.168.15.6", ["192.168.15.1", "192.168.15.2", "192.168.15.3"]),
            (["192.168.15.1", "192.168.15.2", "192.168.15.7"], "192.168.15.0", "192.168.15.6", ["192.168.15.1", "192.168.15.2"]),
        ])
    def test_filter_ips_within(self, test_data):
        ips, ip_min, ip_max, res = test_data
        func_res = DHCPServerConfiguration().filter_ips_within(
            ips=ips,
            ip_min=ip_min, ip_max=ip_max
        )
        assert func_res == res

    @pytest.mark.parametrize("test_data", [
        ("192.168.137.9", False),
        ("192.168.137.10", True),
        ("192.168.137.11", True),
        ("192.168.137.14", True),
        ("192.168.136.13", False),  # Sub address
        ("192.168.138.13", False),  # Sub address
        ("192.168.137.15", True),
        ("192.168.137.16", False),
    ])
    def test_is_valid_client_address(self, test_data):
        ip, res = test_data
        inst = DHCPServerConfiguration()
        inst.ip_ranges = [["192.168.137.10", "192.168.137.15"]]
        assert inst.is_valid_client_address(ip) == res
