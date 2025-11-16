import time

from simple_dhcp_server.configuration import DHCPServerConfiguration
from simple_dhcp_server.server import DHCPServer


def main():
    """Run a DHCP server from the command line."""
    configuration = DHCPServerConfiguration()
    configuration.adjust_if_this_computer_is_a_router()
    configuration.ip_address_lease_time = 60
    configuration.load_yaml("simple-dhcp-server-qt.yml")
    server = DHCPServer(configuration)
    try:
        server.start()
        while True:
            time.sleep(1)  # keep main thread alive
    except KeyboardInterrupt:
        server.close()

    for ip in server.configuration.all_ip_addresses():
        assert ip == server.configuration.network_filter()


if __name__ == '__main__':
    main()
