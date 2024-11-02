import psutil
import netifaces
import logging
import ipaddress
from datetime import datetime
import socket
import threading
import time
import os

def is_cloud_environment():
    """Check if running in cloud environment"""
    return os.environ.get('REPL_ID') is not None or os.environ.get('CLOUD_ENVIRONMENT') is not None

def get_network_interfaces():
    """Get all active network interfaces."""
    interfaces = []
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:  # Has IPv4
                stats = psutil.net_io_counters(pernic=True).get(iface)
                if stats and (stats.bytes_sent > 0 or stats.bytes_recv > 0):
                    # Skip loopback and virtual interfaces
                    if not iface.startswith(('lo', 'docker', 'veth', 'br-')):
                        interfaces.append(iface)
                        logging.debug(f"Found active interface: {iface}")
        return interfaces
    except Exception as e:
        logging.error(f"Error getting network interfaces: {str(e)}")
        return []

def get_ip_network():
    """Get the current network's IP range in CIDR notation."""
    try:
        for iface in get_network_interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr['addr']
                    netmask = addr['netmask']
                    if not ip.startswith('127.'):
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            logging.info(f"Determined network CIDR: {str(network)} for interface {iface}")
                            return str(network)
                        except ValueError as e:
                            logging.warning(f"Invalid network for interface {iface}: {str(e)}")
                            continue
        logging.error("No valid network CIDR found")
        return None
    except Exception as e:
        logging.error(f"Error getting IP network: {str(e)}")
        return None

def get_device_name(ip):
    """Try to get device hostname with improved error handling."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and not hostname.startswith('_'):
            logging.debug(f"Resolved hostname for {ip}: {hostname}")
            return hostname
    except (socket.herror, socket.gaierror) as e:
        logging.debug(f"Could not resolve hostname for {ip}: {str(e)}")
    except Exception as e:
        logging.error(f"Error getting device name for {ip}: {str(e)}")
    return f"Device-{ip.split('.')[-1]}"

def scan_network():
    """Scan network for devices using socket-based scanning."""
    if is_cloud_environment():
        logging.warning("Network scanning is disabled in cloud environment")
        return generate_demo_devices()

    devices = []
    try:
        network_cidr = get_ip_network()
        if not network_cidr:
            logging.error("Could not determine network CIDR")
            return devices

        logging.info(f"Starting network scan on {network_cidr}")
        
        # Get the network address and subnet
        network = ipaddress.IPv4Network(network_cidr)
        
        # Get our own IP address
        own_ip = None
        for iface in get_network_interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                own_ip = addrs[netifaces.AF_INET][0]['addr']
                break
        
        if not own_ip:
            logging.error("Could not determine own IP address")
            return devices
            
        # Scan the network
        for ip in network.hosts():
            ip_str = str(ip)
            
            # Skip our own IP
            if ip_str == own_ip:
                continue
                
            try:
                # Try to establish a connection to check if host is up
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)  # 100ms timeout
                result = sock.connect_ex((ip_str, 80))
                sock.close()
                
                if result == 0 or result == 111:  # Connected or Connection refused (host is up)
                    # Try to get the hostname
                    name = get_device_name(ip_str)
                    
                    # Try to get MAC address from ARP cache
                    mac_address = None
                    try:
                        with open('/proc/net/arp', 'r') as f:
                            next(f)  # Skip header
                            for line in f:
                                fields = line.strip().split()
                                if fields[0] == ip_str:
                                    mac_address = fields[3]
                                    break
                    except Exception as e:
                        logging.debug(f"Could not get MAC address for {ip_str}: {str(e)}")
                    
                    if not mac_address:
                        mac_address = f"Unknown-{ip_str.replace('.', '-')}"
                    
                    device = {
                        'ip_address': ip_str,
                        'mac_address': mac_address,
                        'name': name,
                        'status': True,
                        'blocked': False,
                        'last_seen': datetime.utcnow()
                    }
                    devices.append(device)
                    logging.info(f"Found device: {name} ({ip_str})")
            except Exception as e:
                logging.debug(f"Error scanning {ip_str}: {str(e)}")
                continue
                
        logging.info(f"Scan completed. Found {len(devices)} devices")
        return devices
    except Exception as e:
        logging.error(f"Error in scan_network: {str(e)}")
        return devices

def generate_demo_devices():
    """Generate demo devices for cloud environment"""
    logging.info("Generating demo devices for cloud environment")
    demo_devices = [
        {
            'ip_address': '192.168.1.100',
            'mac_address': '00:1A:2B:3C:4D:5E',
            'name': 'Demo-Laptop',
            'status': True,
            'blocked': False,
            'last_seen': datetime.utcnow()
        },
        {
            'ip_address': '192.168.1.101',
            'mac_address': '00:2B:3C:4D:5E:6F',
            'name': 'Demo-Phone',
            'status': True,
            'blocked': False,
            'last_seen': datetime.utcnow()
        },
        {
            'ip_address': '192.168.1.102',
            'mac_address': '00:3C:4D:5E:6F:7G',
            'name': 'Demo-TV',
            'status': False,
            'blocked': True,
            'last_seen': datetime.utcnow()
        }
    ]
    return demo_devices

def get_total_network_usage():
    """Get total network usage for all interfaces."""
    try:
        if is_cloud_environment():
            # Return demo data for cloud environment
            return {
                'timestamp': datetime.utcnow(),
                'bytes_sent': 1024 * 1024 * 100,  # 100 MB sent
                'bytes_recv': 1024 * 1024 * 200   # 200 MB received
            }

        io_counters = psutil.net_io_counters()
        return {
            'timestamp': datetime.utcnow(),
            'bytes_sent': io_counters.bytes_sent,
            'bytes_recv': io_counters.bytes_recv
        }
    except Exception as e:
        logging.error(f"Error getting total network usage: {str(e)}")
        return None

def start_total_usage_monitoring():
    """Start background thread to monitor total network usage."""
    from flask import current_app
    app = current_app._get_current_object()
    
    def monitor():
        logging.info("Starting network usage monitoring")
        previous_usage = get_total_network_usage()
        
        while True:
            try:
                time.sleep(30)  # Update every 30 seconds for more frequent updates
                with app.app_context():
                    from extensions import db
                    from models import TotalNetworkUsage
                    
                    current_usage = get_total_network_usage()
                    if current_usage and previous_usage:
                        bytes_sent = max(0, current_usage['bytes_sent'] - previous_usage['bytes_sent'])
                        bytes_recv = max(0, current_usage['bytes_recv'] - previous_usage['bytes_recv'])
                        
                        # Only record if there's actual network activity
                        if bytes_sent > 0 or bytes_recv > 0:
                            total_usage = TotalNetworkUsage(
                                timestamp=current_usage['timestamp'],
                                bytes_sent=bytes_sent,
                                bytes_recv=bytes_recv
                            )
                            db.session.add(total_usage)
                            db.session.commit()
                            logging.debug(f"Recorded network usage: sent={bytes_sent}, recv={bytes_recv}")
                        
                        previous_usage = current_usage
            except Exception as e:
                logging.error(f"Error in network monitoring: {str(e)}")
                if 'db' in locals():
                    db.session.rollback()
                time.sleep(5)  # Wait before retrying after error
    
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    logging.info("Network usage monitoring thread started")
