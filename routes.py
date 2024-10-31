from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, make_response, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, get_jwt_identity,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies, get_jwt,
    verify_jwt_in_request
)
from extensions import db, jwt, socketio
from models import User, Device, NetworkUsage
from network_scanner import scan_network
import logging
from datetime import datetime, timedelta
from flask_socketio import emit
from sqlalchemy import func, desc
import random
import eventlet

main = Blueprint('main', __name__)

logging.basicConfig(level=logging.DEBUG)

@main.route('/')
def index():
    logging.info("Accessing index route")
    return render_template('index.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    logging.info("Accessing register route")
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        try:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            logging.info(f"User {username} registered successfully")
            return redirect(url_for('main.login'))
        except Exception as e:
            logging.error(f"Error during registration: {str(e)}")
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')

    return render_template('register.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    logging.info("Accessing login route")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            access_token = create_access_token(
                identity=user.id,
                expires_delta=timedelta(hours=1)
            )
            refresh_token = create_refresh_token(identity=user.id)
            
            response = make_response(redirect(url_for('main.devices')))
            
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)
            
            logging.info(f"Login successful for user {username}")
            logging.info(f"Access token cookie set: {access_token[:10]}...")
            
            return response
        else:
            logging.warning(f"Failed login attempt for user {username}")
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@main.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        
        response = jsonify({'msg': 'Token refreshed successfully'})
        set_access_cookies(response, access_token)
        
        return response
    except Exception as e:
        logging.error(f"Error refreshing token: {str(e)}")
        return jsonify({"msg": "Token refresh failed"}), 401

@main.route('/logout')
@jwt_required(optional=True)
def logout():
    logging.info("User logged out")
    response = make_response(redirect(url_for('main.login')))
    unset_jwt_cookies(response)
    return response

@main.route('/devices')
@jwt_required()
def devices():
    logging.info("Accessing devices route")
    current_user = get_jwt_identity()
    logging.info(f"User {current_user} accessing devices page")
    return render_template('devices.html')

@main.route('/api/devices', methods=['GET'])
@jwt_required()
def get_devices():
    logging.info("Fetching devices")
    current_user = get_jwt_identity()
    logging.info(f"User {current_user} fetching devices")
    try:
        devices = Device.query.all()
        logging.debug(f"Found {len(devices)} devices")
        return jsonify([{
            'id': device.id,
            'name': device.name,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'status': device.status,
            'blocked': device.blocked,
            'last_seen': device.last_seen.isoformat() if device.last_seen else None,
            'data_usage': device.data_usage
        } for device in devices])
    except Exception as e:
        logging.error(f"Error fetching devices: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@main.route('/api/devices/<int:device_id>/toggle', methods=['POST'])
@jwt_required()
def toggle_device(device_id):
    current_user = get_jwt_identity()
    logging.info(f"User {current_user} toggling device {device_id}")
    try:
        device = Device.query.get_or_404(device_id)
        device.blocked = not device.blocked
        db.session.commit()
        
        device_data = {
            'id': device.id,
            'name': device.name,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'status': device.status,
            'blocked': device.blocked,
            'last_seen': device.last_seen.isoformat() if device.last_seen else None,
            'data_usage': device.data_usage
        }
        
        emit('device_updated', device_data, broadcast=True, namespace='/')
        logging.info(f'Device {device_id} toggled. New blocked status: {device.blocked}')
        return jsonify({'success': True, 'blocked': device.blocked})
    except Exception as e:
        logging.error(f'Error toggling device {device_id}: {str(e)}')
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@main.route('/api/scan', methods=['POST'])
@jwt_required()
def scan():
    current_user = get_jwt_identity()
    logging.info(f"User {current_user} scanning for new devices")
    try:
        new_devices = scan_network()
        logging.debug(f"Scan returned {len(new_devices)} devices")
        for device_data in new_devices:
            existing_device = Device.query.filter_by(mac_address=device_data['mac_address']).first()
            if existing_device:
                logging.debug(f"Updating existing device: {existing_device.name}")
                existing_device.name = device_data['name']
                existing_device.ip_address = device_data['ip_address']
                existing_device.status = device_data['status']
                existing_device.last_seen = device_data['last_seen']
                existing_device.update_data_usage(random.randint(1000000, 10000000))
            else:
                logging.debug(f"Adding new device: {device_data['name']}")
                new_device = Device(
                    name=device_data['name'],
                    ip_address=device_data['ip_address'],
                    mac_address=device_data['mac_address'],
                    status=device_data['status'],
                    blocked=device_data['blocked'],
                    last_seen=device_data['last_seen']
                )
                db.session.add(new_device)
        db.session.commit()
        
        devices = Device.query.all()
        devices_data = [{
            'id': device.id,
            'name': device.name,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'status': device.status,
            'blocked': device.blocked,
            'last_seen': device.last_seen.isoformat() if device.last_seen else None,
            'data_usage': device.data_usage
        } for device in devices]
        
        emit('devices_update', devices_data, broadcast=True, namespace='/')
        logging.info(f"Emitted 'devices_update' event with {len(devices)} devices")
        
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error during device scan: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@main.route('/network_usage')
@jwt_required()
def network_usage():
    try:
        current_user = get_jwt_identity()
        logging.info(f"User {current_user} accessing network usage page")
        
        devices = Device.query.all()
        
        for device in devices:
            device.total_usage = db.session.query(func.sum(NetworkUsage.data_used)).filter(NetworkUsage.device_id == device.id).scalar() or 0
        
        total_network_usage = sum(device.total_usage for device in devices)
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=1)
        hourly_usage = db.session.query(
            func.date_trunc('hour', NetworkUsage.timestamp).label('hour'),
            func.sum(NetworkUsage.data_used).label('usage')
        ).filter(NetworkUsage.timestamp.between(start_time, end_time)
        ).group_by('hour').order_by('hour').all()
        
        hourly_data = [{'hour': entry.hour.isoformat(), 'usage': entry.usage} for entry in hourly_usage]
        
        top_devices = sorted(devices, key=lambda x: x.total_usage, reverse=True)[:5]
        
        return render_template('network_usage.html',
                             devices=devices,
                             total_network_usage=total_network_usage,
                             hourly_data=hourly_data,
                             top_devices=top_devices)
    except Exception as e:
        logging.error(f"Error accessing network usage page: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@main.route('/api/network_usage')
@jwt_required()
def get_network_usage():
    try:
        current_user = get_jwt_identity()
        time_range = request.args.get('range', '24h')
        
        end_time = datetime.utcnow()
        if time_range == '7d':
            start_time = end_time - timedelta(days=7)
            interval = 'hour'
        elif time_range == '30d':
            start_time = end_time - timedelta(days=30)
            interval = 'day'
        else:
            start_time = end_time - timedelta(days=1)
            interval = 'hour'

        usage_data = db.session.query(
            func.date_trunc(interval, NetworkUsage.timestamp).label('interval'),
            func.sum(NetworkUsage.data_used).label('usage')
        ).filter(
            NetworkUsage.timestamp.between(start_time, end_time)
        ).group_by('interval').order_by('interval').all()

        total_usage = sum(entry.usage for entry in usage_data) if usage_data else 0
        peak_usage = max((entry.usage for entry in usage_data), default=0)
        peak_time = next(
            (entry.interval for entry in usage_data if entry.usage == peak_usage),
            None
        )

        if len(usage_data) > 1:
            first_half = sum(entry.usage for entry in usage_data[:len(usage_data)//2])
            second_half = sum(entry.usage for entry in usage_data[len(usage_data)//2:])
            trend = (second_half - first_half) / first_half if first_half > 0 else 0
        else:
            trend = 0

        previous_start = start_time - (end_time - start_time)
        previous_usage = db.session.query(
            func.sum(NetworkUsage.data_used)
        ).filter(
            NetworkUsage.timestamp.between(previous_start, start_time)
        ).scalar() or 0

        period_comparison = (
            ((total_usage - previous_usage) / previous_usage * 100)
            if previous_usage > 0 else 0
        )

        devices = Device.query.all()
        device_usage = []
        for device in devices:
            device_data = db.session.query(
                func.sum(NetworkUsage.data_used).label('total_usage')
            ).filter(
                NetworkUsage.device_id == device.id,
                NetworkUsage.timestamp.between(start_time, end_time)
            ).first()

            device_usage.append({
                'name': device.name,
                'usage': float(device_data.total_usage or 0) / (1024 * 1024)
            })

        response_data = {
            'labels': [entry.interval.isoformat() for entry in usage_data],
            'values': [float(entry.usage or 0) / (1024 * 1024) for entry in usage_data],
            'devices': sorted(device_usage, key=lambda x: x['usage'], reverse=True),
            'statistics': {
                'total_usage': float(total_usage) / (1024 * 1024),
                'peak_usage_time': peak_time.strftime('%Y-%m-%d %H:%M') if peak_time else None,
                'trend': trend,
                'period_comparison': period_comparison
            }
        }

        return jsonify(response_data)
    except Exception as e:
        logging.error(f"Error fetching network usage data: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@socketio.on('connect')
def handle_connect():
    try:
        verify_jwt_in_request()
        current_user = get_jwt_identity()
        logging.info(f'User {current_user} connected via WebSocket')
        return True
    except Exception as e:
        logging.error(f'Error during WebSocket connection: {str(e)}')
        return False

@socketio.on('disconnect')
def handle_disconnect():
    logging.info('Client disconnected from WebSocket')

def simulate_network_usage_updates():
    from app import create_app
    app = create_app()
    
    while True:
        try:
            with app.app_context():
                devices = Device.query.all()
                for device in devices:
                    usage = random.randint(1000000, 10000000)
                    device.update_data_usage(usage)
                db.session.commit()

                response = get_network_usage()
                socketio.emit('network_usage_update', response.json, broadcast=True)
        except Exception as e:
            logging.error(f"Error in network usage simulation: {str(e)}")
        eventlet.sleep(60)

@socketio.on('connect')
def start_usage_simulation():
    eventlet.spawn(simulate_network_usage_updates)