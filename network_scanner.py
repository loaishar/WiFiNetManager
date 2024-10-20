import random
from datetime import datetime, timedelta

def generate_mac_address():
    """Generate a random MAC address."""
    return ':'.join(['{:02x}'.format(random.randint(0x00, 0xff)) for _ in range(6)])

def generate_ip_address():
    """Generate a random IP address within a private IP range."""
    return f"192.168.1.{random.randint(2, 254)}"

def generate_device_name():
    """Generate a random device name."""
    device_types = ['Laptop', 'Smartphone', 'Tablet', 'Smart TV', 'Printer', 'Camera']
    return f"{random.choice(device_types)}-{random.randint(1000, 9999)}"

def scan_network():
    """Simulate network scanning by generating a list of devices."""
    devices = []
    for _ in range(random.randint(5, 15)):
        device = {
            'name': generate_device_name(),
            'ip_address': generate_ip_address(),
            'mac_address': generate_mac_address(),
            'status': random.choice([True, False]),
            'blocked': False,
            'last_seen': datetime.utcnow() - timedelta(minutes=random.randint(0, 60))
        }
        devices.append(device)
    return devices
