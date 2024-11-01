import psutil
import netifaces
import logging
import ipaddress
from datetime import datetime
import socket
import threading
import time

def get_network_interfaces():
    """Get all active network interfaces."""
    interfaces = []
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:  # Has IPv4
                stats = psutil.net_io_counters(pernic=True).get(iface)
                if stats and (stats.bytes_sent > 0 or stats.bytes_recv > 0):
                    interfaces.append(iface)
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
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        return str(network)
        return None
    except Exception as e:
        logging.error(f"Error getting IP network: {str(e)}")
        return None

def get_device_name(ip):
    """Try to get device hostname."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and not hostname.startswith('_'):
            return hostname
    except (socket.herror, socket.gaierror) as e:
        logging.debug(f"Could not resolve hostname for {ip}: {str(e)}")
    except Exception as e:
        logging.error(f"Error getting device name for {ip}: {str(e)}")
    
    return f"Device-{ip.split('.')[-1]}"

def get_total_network_usage():
    """Get total network usage across all interfaces."""
    try:
        io_counters = psutil.net_io_counters()
        return {
            'timestamp': datetime.utcnow(),
            'bytes_sent': io_counters.bytes_sent,
            'bytes_recv': io_counters.bytes_recv
        }
    except Exception as e:
        logging.error(f"Error getting total network usage: {str(e)}")
        return None

def scan_network():
    """Scan network using ARP to discover real devices."""
    logging.info("Starting network scan")
    devices = []
    
    try:
        # Get current network CIDR
        network_cidr = get_ip_network()
        if not network_cidr:
            logging.error("Could not determine network CIDR")
            return devices

        logging.info(f"Scanning network: {network_cidr}")
        
        # Import scapy here to avoid import issues
        from scapy.all import ARP, Ether, srp
        
        # Create ARP request packet
        arp_request = ARP(pdst=network_cidr)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Send ARP request and get responses
        answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        
        # Process responses
        for element in answered_list:
            ip_address = element[1].psrc
            mac_address = element[1].hwsrc
            
            # Skip localhost
            if ip_address.startswith('127.'):
                continue
                
            device = {
                'ip_address': ip_address,
                'mac_address': mac_address,
                'name': get_device_name(ip_address),
                'status': True,
                'blocked': False,
                'last_seen': datetime.utcnow()
            }
            devices.append(device)
            logging.debug(f"Found device: {device['name']} ({device['ip_address']})")
            
    except Exception as e:
        logging.error(f"Error during network scan: {str(e)}")
    
    logging.info(f"Found {len(devices)} devices")
    return devices

def start_total_usage_monitoring():
    """Start background thread to monitor total network usage."""
    from flask import current_app
    app = current_app._get_current_object()
    
    def monitor():
        logging.info("Starting network usage monitoring")
        previous_usage = get_total_network_usage()
        while True:
            try:
                time.sleep(60)  # Update every minute
                with app.app_context():
                    from extensions import db
                    from models import TotalNetworkUsage
                    
                    current_usage = get_total_network_usage()
                    if current_usage and previous_usage:
                        bytes_sent = current_usage['bytes_sent'] - previous_usage['bytes_sent']
                        bytes_recv = current_usage['bytes_recv'] - previous_usage['bytes_recv']
                        
                        # Only record if there's actual network activity
                        if bytes_sent >= 0 and bytes_recv >= 0:
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
    
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    logging.info("Network usage monitoring thread started")
