import psutil
import netifaces
import scapy.all as scapy
import logging
import ipaddress
from datetime import datetime, timedelta
import socket
import threading
import time
import os
from flask import current_app

def get_network_interfaces():
    """Get all active network interfaces."""
    interfaces = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:  # Has IPv4
            interfaces.append(iface)
    return interfaces

def get_ip_network():
    """Get the current network's IP range in CIDR notation."""
    for iface in get_network_interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr['addr']
                netmask = addr['netmask']
                if not ip.startswith('127.'):
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
    return "192.168.1.0/24"  # Fallback

def get_device_name(ip):
    """Try to get device hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return f"Device-{ip.split('.')[-1]}"

def get_device_status(ip):
    """Check if device is reachable."""
    try:
        return os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1") == 0
    except:
        return False

def arp_scan(ip_range):
    """Perform ARP scan to discover devices."""
    try:
        # Create ARP request packet
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Send packet and get response
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        
        devices = []
        for element in answered_list:
            # Get real device info
            ip = element[1].psrc
            mac = element[1].hwsrc
            
            # Try to get real device name and status
            name = get_device_name(ip)
            status = get_device_status(ip)
            
            device = {
                'ip_address': ip,
                'mac_address': mac,
                'name': name,
                'status': status,
                'blocked': False,
                'last_seen': datetime.utcnow()
            }
            devices.append(device)
            
        return devices
    except Exception as e:
        logging.error(f"Error during ARP scan: {str(e)}")
        return []

def get_total_network_usage():
    """Get total network usage for all interfaces."""
    try:
        interfaces = get_network_interfaces()
        total_bytes_sent = 0
        total_bytes_recv = 0
        
        for interface in interfaces:
            io_counters = psutil.net_io_counters(pernic=True)
            if interface in io_counters:
                stats = io_counters[interface]
                total_bytes_sent += stats.bytes_sent
                total_bytes_recv += stats.bytes_recv
        
        return {
            'timestamp': datetime.utcnow(),
            'bytes_sent': total_bytes_sent,
            'bytes_recv': total_bytes_recv
        }
    except Exception as e:
        logging.error(f"Error getting total network usage: {str(e)}")
        return None

def scan_network():
    """Scan network and return list of devices."""
    logging.info("Starting network scan")
    ip_range = get_ip_network()
    devices = arp_scan(ip_range)
    logging.info(f"Found {len(devices)} devices")
    return devices

def start_total_usage_monitoring():
    """Start background thread to monitor total network usage."""
    def monitor():
        logging.info("Starting network usage monitoring")
        while True:
            try:
                with current_app.app_context():
                    from extensions import db
                    from models import TotalNetworkUsage
                    
                    usage = get_total_network_usage()
                    if usage:
                        total_usage = TotalNetworkUsage(
                            timestamp=usage['timestamp'],
                            bytes_sent=usage['bytes_sent'],
                            bytes_recv=usage['bytes_recv']
                        )
                        db.session.add(total_usage)
                        db.session.commit()
                        logging.debug(f"Recorded network usage: sent={usage['bytes_sent']}, recv={usage['bytes_recv']}")
            except Exception as e:
                logging.error(f"Error in network monitoring: {str(e)}")
                try:
                    db.session.rollback()
                except:
                    pass
            time.sleep(60)  # Update every minute

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    logging.info("Network usage monitoring thread started")
