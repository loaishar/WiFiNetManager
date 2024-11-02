import psutil
import netifaces
import logging
import ipaddress
from datetime import datetime
import socket
import threading
import time
import os
import subprocess
import re

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

def get_mac_from_ip(ip_address):
    """Get MAC address from IP using ARP table."""
    try:
        with open('/proc/net/arp', 'r') as f:
            next(f)  # Skip header
            for line in f:
                fields = line.strip().split()
                if fields[0] == ip_address:
                    return fields[3]
    except:
        pass
    return None

def get_mac_from_arp(ip_address):
    """Get MAC address using arp command."""
    try:
        if os.name == 'nt':  # Windows
            process = subprocess.Popen(['arp', '-a', ip_address], stdout=subprocess.PIPE)
            output = process.communicate()[0].decode()
            for line in output.splitlines():
                if ip_address in line:
                    mac = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if mac:
                        return mac.group(0)
        else:  # Linux/Unix
            process = subprocess.Popen(['arp', '-n', ip_address], stdout=subprocess.PIPE)
            output = process.communicate()[0].decode()
            for line in output.splitlines():
                if ip_address in line:
                    mac = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if mac:
                        return mac.group(0)
    except:
        pass
    return None

def scan_network():
    """Scan network for devices using socket-based scanning."""
    devices = []
    try:
        # Get all network interfaces
        interfaces = get_network_interfaces()
        if not interfaces:
            logging.error("No network interfaces found")
            return []

        for iface in interfaces:
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET not in addrs:
                    continue

                ip_info = addrs[netifaces.AF_INET][0]
                ip = ip_info['addr']
                netmask = ip_info['netmask']

                # Create network address for scanning
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                logging.info(f"Scanning network {network} on interface {iface}")

                # Scan each host in the network
                for host in network.hosts():
                    host_str = str(host)
                    if host_str == ip:  # Skip our own IP
                        continue

                    try:
                        # Try multiple common ports for better device detection
                        for port in [80, 443, 22, 5000]:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.1)
                            result = sock.connect_ex((host_str, port))
                            sock.close()

                            if result == 0 or result == 111:  # Connection successful or refused (host is up)
                                # Try to get hostname
                                try:
                                    hostname = socket.gethostbyaddr(host_str)[0]
                                except:
                                    hostname = f"Device-{host_str.split('.')[-1]}"

                                # Get MAC address using psutil if available
                                mac = None
                                try:
                                    connections = psutil.net_connections()
                                    for conn in connections:
                                        if conn.raddr and conn.raddr[0] == host_str:
                                            mac = get_mac_from_ip(host_str)
                                            break
                                except:
                                    pass

                                # Fallback to ARP table for MAC address
                                if not mac:
                                    mac = get_mac_from_arp(host_str)

                                if not mac:
                                    mac = f"Unknown-{host_str.replace('.', '-')}"

                                device = {
                                    'ip_address': host_str,
                                    'mac_address': mac,
                                    'name': hostname,
                                    'status': True,
                                    'blocked': False,
                                    'last_seen': datetime.utcnow()
                                }
                                devices.append(device)
                                logging.info(f"Found device: {hostname} ({host_str})")
                                break  # Found device, no need to check other ports

                    except Exception as e:
                        logging.debug(f"Error scanning host {host_str}: {e}")
                        continue

            except Exception as e:
                logging.error(f"Error scanning interface {iface}: {e}")
                continue

        logging.info(f"Scan completed. Found {len(devices)} devices")
        return devices

    except Exception as e:
        logging.error(f"Error in network scan: {e}")
        return devices

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

def start_total_usage_monitoring():
    """Start background thread to monitor total network usage."""
    from flask import current_app
    app = current_app._get_current_object()
    
    def monitor():
        logging.info("Starting network usage monitoring")
        previous_usage = get_total_network_usage()
        
        while True:
            try:
                time.sleep(30)  # Update every 30 seconds
                with app.app_context():
                    from extensions import db
                    from models import TotalNetworkUsage
                    
                    current_usage = get_total_network_usage()
                    if current_usage and previous_usage:
                        bytes_sent = max(0, current_usage['bytes_sent'] - previous_usage['bytes_sent'])
                        bytes_recv = max(0, current_usage['bytes_recv'] - previous_usage['bytes_recv'])
                        
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
