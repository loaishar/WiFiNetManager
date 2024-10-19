import random

def scan_network():
    # Placeholder function for network scanning
    # In a real implementation, this would use a library like scapy to scan the network
    devices = []
    for i in range(5):
        device = {
            'name': f'Device {i+1}',
            'ip_address': f'192.168.1.{random.randint(2, 254)}',
            'mac_address': ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)]),
            'status': True,
            'blocked': False
        }
        devices.append(device)
    return devices
