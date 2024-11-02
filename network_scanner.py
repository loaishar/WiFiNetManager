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
from extensions import socketio

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

def scan_network():
    """Scan network for devices using multiple detection methods."""
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

                # Use multiple methods to scan for devices
                for host in network.hosts():
                    host_str = str(host)
                    if host_str == ip:  # Skip our own IP
                        continue

                    try:
                        # Try connecting to common ports
                        is_up = False
                        for port in [80, 443, 22, 445]:
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(0.5)  # Increased timeout
                                if sock.connect_ex((host_str, port)) == 0:
                                    is_up = True
                                    break
                            finally:
                                sock.close()

                        # Try ping if port scanning didn't work
                        if not is_up:
                            try:
                                response = subprocess.run(
                                    ['ping', '-c', '1', '-W', '1', host_str],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    timeout=1
                                )
                                is_up = response.returncode == 0
                            except:
                                pass

                        if is_up:
                            # Get hostname
                            try:
                                hostname = socket.gethostbyaddr(host_str)[0]
                            except:
                                hostname = f"Device-{host_str.split('.')[-1]}"

                            # Get MAC address using arp -n
                            mac_address = None
                            try:
                                response = subprocess.run(
                                    ['arp', '-n', host_str],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    timeout=1
                                )
                                if response.returncode == 0:
                                    output = response.stdout.decode()
                                    matches = re.findall(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', output)
                                    if matches:
                                        mac_address = matches[0]
                            except:
                                pass

                            if not mac_address:
                                mac_address = f"Unknown-{host_str.replace('.', '-')}"

                            device = {
                                'ip_address': host_str,
                                'mac_address': mac_address,
                                'name': hostname,
                                'status': True,
                                'blocked': False,
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
                            is_up = False
                            # Try common ports first
                            for port in [80, 443, 22, 445]:
                                try:
                                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    sock.settimeout(0.5)
                                    if sock.connect_ex((device.ip_address, port)) == 0:
                                        is_up = True
                                        break
                                finally:
                                    sock.close()

                            # Try ping if port scanning didn't work
                            if not is_up:
                                try:
                                    response = subprocess.run(
                                        ['ping', '-c', '1', '-W', '1', device.ip_address],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        timeout=1
                                    )
                                    is_up = response.returncode == 0
                                except:
                                    pass

                            if is_up != device.status:
                                device.status = is_up
                                history = DeviceHistory(
                                    device_id=device.id,
                                    event_type='connected' if is_up else 'disconnected'
                                )
                                db.session.add(history)

                                # Emit device status update via Socket.IO
                                device_data = {
                                    'id': device.id,
                                    'name': device.name,
                                    'ip_address': device.ip_address,
                                    'mac_address': device.mac_address,
                                    'status': device.status,
                                    'blocked': device.blocked,
                                    'last_seen': datetime.utcnow().isoformat()
                                }
                                socketio.emit('device_updated', device_data)
                        except Exception as e:
                            logging.error(f"Error checking device {device.ip_address}: {e}")
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
