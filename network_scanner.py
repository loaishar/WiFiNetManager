import psutil
import netifaces
import scapy.all as scapy
import logging
from datetime import datetime, timedelta
import socket
import threading
import time

def get_network_interfaces():
    """Get all active network interfaces."""
    interfaces = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:  # Has IPv4
            interfaces.append(iface)
    return interfaces

def get_ip_network():
    """Get the current network's IP range."""
    for iface in get_network_interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr['addr']
                if not ip.startswith('127.'):  # Skip localhost
                    netmask = addr['netmask']
                    return f"{ip}/{netmask}"
    return "192.168.1.0/24"  # Fallback

def arp_scan(ip_range):
    """Perform ARP scan to discover devices."""
    try:
        # Create ARP request packet
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Send packet and get responses
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        
        devices = []
        for element in answered_list:
            device = {
                'ip_address': element[1].psrc,
                'mac_address': element[1].hwsrc,
                'name': get_device_name(element[1].psrc),
                'status': True,
                'blocked': False,
                'last_seen': datetime.utcnow()
            }
            devices.append(device)
        return devices
    except Exception as e:
        logging.error(f"Error during ARP scan: {str(e)}")
        return []

def get_device_name(ip):
    """Try to get device hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return f"Device-{ip.split('.')[-1]}"

def get_network_usage(interface):
    """Get network usage statistics for an interface."""
    try:
        io_counters = psutil.net_io_counters(pernic=True)
        if interface in io_counters:
            stats = io_counters[interface]
            return {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv
            }
    except Exception as e:
        logging.error(f"Error getting network usage: {str(e)}")
    return None

def monitor_bandwidth(device_ip, duration=5):
    """Monitor bandwidth usage for a specific device."""
    try:
        initial = psutil.net_io_counters()
        time.sleep(duration)
        final = psutil.net_io_counters()
        
        bytes_sent = final.bytes_sent - initial.bytes_sent
        bytes_recv = final.bytes_recv - initial.bytes_recv
        
        return {
            'upload': bytes_sent / duration,  # bytes per second
            'download': bytes_recv / duration  # bytes per second
        }
    except Exception as e:
        logging.error(f"Error monitoring bandwidth: {str(e)}")
        return {'upload': 0, 'download': 0}

def scan_network():
    """Scan network and return list of devices with real data."""
    logging.info("Starting network scan")
    ip_range = get_ip_network()
    devices = arp_scan(ip_range)
    
    # Get bandwidth info for each device
    for device in devices:
        bandwidth = monitor_bandwidth(device['ip_address'])
        device['data_usage'] = bandwidth['upload'] + bandwidth['download']
    
    logging.info(f"Found {len(devices)} devices")
    return devices

# Start background monitoring thread
def start_monitoring():
    def monitor():
        while True:
            try:
                interfaces = get_network_interfaces()
                for interface in interfaces:
                    usage = get_network_usage(interface)
                    if usage:
                        logging.info(f"Interface {interface} usage: {usage}")
            except Exception as e:
                logging.error(f"Monitoring error: {str(e)}")
            time.sleep(60)  # Update every minute

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
