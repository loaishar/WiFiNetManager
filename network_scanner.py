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
import json
import requests

def get_service_name(port):
    """Get service name for common ports."""
    common_services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        8080: 'HTTP-Alt'
    }
    return common_services.get(port, f'Port-{port}')

def get_vendor_from_mac(mac_address):
    """Get vendor information from MAC address using macvendors.com API."""
    try:
        url = f'https://api.macvendors.com/{mac_address}'
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        return 'Unknown Vendor'
    except:
        return 'Unknown Vendor'

def detect_device_type(open_ports, os_type):
    """Detect device type based on open ports and OS."""
    if os_type and 'windows' in os_type.lower():
        return 'Windows PC'
    elif os_type and 'mac' in os_type.lower():
        return 'Mac Device'
    elif os_type and 'linux' in os_type.lower():
        return 'Linux Device'
    elif 80 in [p['port'] for p in open_ports] or 443 in [p['port'] for p in open_ports]:
        return 'IoT Device'
    return 'Unknown Device'

def detect_os(ip_address):
    """Detect operating system using TTL values."""
    try:
        proc = subprocess.Popen(['ping', '-c', '1', ip_address], stdout=subprocess.PIPE)
        output = proc.communicate()[0].decode()
        if 'ttl=64' in output.lower():
            return 'Linux/Unix'
        elif 'ttl=128' in output.lower():
            return 'Windows'
        elif 'ttl=254' in output.lower():
            return 'Solaris/AIX'
        return 'Unknown OS'
    except:
        return 'Unknown OS'

def scan_device_ports(ip_address, common_ports=[80, 443, 22, 21, 23, 25, 53, 3306, 5432, 8080]):
    """Scan for open ports on a device."""
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                service = get_service_name(port)
                open_ports.append({'port': port, 'service': service})
            sock.close()
        except:
            continue
    return open_ports

def send_wol(mac_address):
    """Send Wake-on-LAN magic packet."""
    try:
        mac_bytes = bytes.fromhex(mac_address.replace(':', ''))
        magic_packet = b'\xff' * 6 + mac_bytes * 16
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic_packet, ('<broadcast>', 9))
        return True
    except Exception as e:
        logging.error(f"Error sending WoL packet: {e}")
        return False

def get_network_interfaces():
    """Get all active network interfaces."""
    interfaces = []
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:  # Has IPv4
                stats = psutil.net_io_counters(pernic=True).get(iface)
                if stats and (stats.bytes_sent > 0 or stats.bytes_recv > 0):
                    if not iface.startswith(('lo', 'docker', 'veth', 'br-')):
                        interfaces.append(iface)
                        logging.debug(f"Found active interface: {iface}")
        return interfaces
    except Exception as e:
        logging.error(f"Error getting network interfaces: {str(e)}")
        return []

def get_network_speed(ip_address):
    """Measure network speed to a device."""
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip_address, 80))
        end_time = time.time()
        sock.close()
        return 1 / (end_time - start_time)  # Rough estimate in Mbps
    except:
        return 0

def scan_network():
    """Enhanced network scanning with device fingerprinting."""
    devices = []
    try:
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

                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                logging.info(f"Scanning network {network} on interface {iface}")

                for host in network.hosts():
                    host_str = str(host)
                    if host_str == ip:
                        continue

                    try:
                        # Basic connectivity check
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        result = sock.connect_ex((host_str, 80))
                        sock.close()

                        if result in [0, 111]:  # Host is up
                            # Get device information
                            try:
                                hostname = socket.gethostbyaddr(host_str)[0]
                            except:
                                hostname = f"Device-{host_str.split('.')[-1]}"

                            # Get MAC address
                            mac = None
                            try:
                                with open('/proc/net/arp', 'r') as f:
                                    for line in f.readlines()[1:]:
                                        fields = line.strip().split()
                                        if fields[0] == host_str:
                                            mac = fields[3]
                                            break
                            except:
                                mac = f"Unknown-{host_str.replace('.', '-')}"

                            # Enhanced device information
                            open_ports = scan_device_ports(host_str)
                            os_type = detect_os(host_str)
                            vendor = get_vendor_from_mac(mac) if mac else 'Unknown'
                            device_type = detect_device_type(open_ports, os_type)
                            network_speed = get_network_speed(host_str)

                            device = {
                                'ip_address': host_str,
                                'mac_address': mac,
                                'name': hostname,
                                'status': True,
                                'blocked': False,
                                'device_type': device_type,
                                'vendor': vendor,
                                'os_type': os_type,
                                'open_ports': open_ports,
                                'network_speed': network_speed,
                                'last_seen': datetime.utcnow()
                            }
                            devices.append(device)
                            logging.info(f"Found device: {hostname} ({host_str})")

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
                    from models import TotalNetworkUsage, Device, DeviceHistory
                    
                    # Update total network usage
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
                            
                        previous_usage = current_usage

                    # Check device presence and update history
                    devices = Device.query.all()
                    for device in devices:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.1)
                            result = sock.connect_ex((device.ip_address, 80))
                            sock.close()
                            
                            current_status = result in [0, 111]
                            if current_status != device.status:
                                device.status = current_status
                                history = DeviceHistory(
                                    device_id=device.id,
                                    event_type='connected' if current_status else 'disconnected',
                                    connection_speed=get_network_speed(device.ip_address) if current_status else 0
                                )
                                db.session.add(history)
                        except:
                            continue

                    db.session.commit()
                    logging.debug(f"Updated network usage and device status")
                    
            except Exception as e:
                logging.error(f"Error in network monitoring: {str(e)}")
                if 'db' in locals():
                    db.session.rollback()
                time.sleep(5)
    
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    logging.info("Network usage monitoring thread started")
