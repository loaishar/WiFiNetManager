import psutil
import netifaces
import logging
import ipaddress
from datetime import datetime
import socket
import threading
import time
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import os

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
                            return str(network)
                        except ValueError:
                            continue
        return None
    except Exception as e:
        logging.error(f"Error getting IP network: {str(e)}")
        return None

def get_device_name(ip):
    """Try to get device hostname with improved error handling."""
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
    """Get total network usage for all interfaces."""
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
    """Scan the network for devices with improved error handling."""
    devices = []
    try:
        network_cidr = get_ip_network()
        if not network_cidr:
            logging.error("Could not determine network CIDR")
            return devices

        logging.info(f"Starting network scan on {network_cidr}")
        
        # Run scapy with sudo if needed
        if os.geteuid() != 0:
            logging.warning("Scanning may require elevated privileges")
        
        # Create and send ARP request
        arp = ARP(pdst=network_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        try:
            result = scapy.srp(packet, timeout=3, verbose=True)[0]
        except Exception as e:
            logging.error(f"Error during ARP scan: {str(e)}")
            return devices

        # Process discovered devices
        for sent, received in result:
            device = {
                'ip_address': received.psrc,
                'mac_address': received.hwsrc,
                'name': get_device_name(received.psrc),
                'status': True,
                'blocked': False,
                'last_seen': datetime.utcnow()
            }
            devices.append(device)
            logging.info(f"Found device: {device['name']} ({device['ip_address']})")

        return devices
    except Exception as e:
        logging.error(f"Error in scan_network: {str(e)}")
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
