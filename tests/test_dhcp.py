import logging
import subprocess
import sys
import time

import pytest

from simple_dhcp_server.dhcp import DHCPServer, DHCPServerConfiguration

nic_dhcp = "Ethernet 2"
nic_client = "Ethernet 3"


class NicControl:

    def __init__(self, nic_name):
        self.nic_name = nic_name

    def renew(self):
        print("Renewing IP for NIC: {}".format(self.nic_name))
        # subprocess.run(['ipconfig', '/renew', self.nic_name], check=True)
        # Run command and print output while executing
        process = subprocess.Popen(['ipconfig', '/renew', self.nic_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in process.stdout:
            print(line, end='')
        process.wait()
        print("Renewed IP for NIC: {}".format(self.nic_name))

    def get_current_ip(self):
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        capture = 0
        for line in lines:
            print("Capture: {}; Line: {}".format(capture, line))
            if self.nic_name in line:
                capture = 2

            if capture and 'IPv4 Address' in line:
                ip_address = line.split(':')[-1].strip().split('(')[0].strip()
                return ip_address
            if capture and line.strip() == '':
                capture -= 1  # First line after Nic name is empty, so ignore first thus allows capture enter here twice
        return None

    def release(self):
        print("Releasing IP for NIC: {}".format(self.nic_name))
        subprocess.run(['ipconfig', '/release', self.nic_name], check=True)
        print("Released IP for NIC: {}".format(self.nic_name))

    def wait_ip_assigned(self, timeout=10):
        start_time = time.time()
        while time.time() - start_time < timeout:
            ip = self.get_current_ip()
            if ip is not None:
                return ip
            time.sleep(1)
        return None


@pytest.fixture
def nic_control():
    yield NicControl(nic_client)


@pytest.fixture
def dhcp():
    conf = DHCPServerConfiguration()

    conf.network = "192.168.137.0"
    conf.bind_address = "192.168.137.1"
    inst = DHCPServer(conf)
    # Configure logging for the DHCP server
    logger = logging.getLogger("simple_dhcp_server")
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    inst.start()
    yield inst
    inst.close()


def test_assign_ip(dhcp, nic_control):
    """Test that the NIC can get an IP assigned"""
    nic_control.release()
    nic_control.renew()
    assigned_ip = nic_control.wait_ip_assigned(timeout=15)
    assert assigned_ip is not None
    assert assigned_ip.startswith('192.168.137.')

