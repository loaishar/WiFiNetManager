from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, make_response
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, get_jwt_identity,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies, get_jwt
)
from extensions import db, jwt, socketio
from models import User, Device, NetworkUsage
from network_scanner import scan_network
import logging
from datetime import datetime, timedelta
from flask_socketio import emit
from sqlalchemy import func

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
        new_access_token = create_access_token(identity=current_user)
        
        resp = jsonify({'access_token': new_access_token})
        set_access_cookies(resp, new_access_token)
        
        logging.info(f"Token refreshed for user {current_user}")
        return resp, 200
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
        token = get_jwt()
        logging.info(f"Token present: {bool(token)}")
        
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
        
        return render_template('network_usage.html', 
                               devices=devices, 
                               total_network_usage=total_network_usage,
                               hourly_data=hourly_data)
    except Exception as e:
        logging.error(f"Error accessing network usage page: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@main.route('/api/network_usage')
@jwt_required()
def get_network_usage():
    try:
        current_user = get_jwt_identity()
        logging.info(f"User {current_user} fetching network usage data")
        token = get_jwt()
        logging.info(f"Token present: {bool(token)}")
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=1)
        hourly_usage = db.session.query(
            func.date_trunc('hour', NetworkUsage.timestamp).label('hour'),
            func.sum(NetworkUsage.data_used).label('usage')
        ).filter(NetworkUsage.timestamp.between(start_time, end_time)
        ).group_by('hour').order_by('hour').all()
        
        labels = [entry.hour.strftime('%Y-%m-%d %H:%M') for entry in hourly_usage]
        values = [float(entry.usage) / (1024 * 1024) for entry in hourly_usage]  # Convert to MB
        
        return jsonify({'labels': labels, 'values': values})
    except Exception as e:
        logging.error(f"Error fetching network usage data: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@socketio.on('connect')
def handle_connect():
    logging.info("WebSocket connection attempt")
    try:
        token = request.args.get('token') or request.headers.get('Authorization')
        if not token:
            auth_data = request.args.get('auth')
            if isinstance(auth_data, dict):
                token = auth_data.get('token')
        if not token:
            token = request.cookies.get('access_token_cookie')

        if not token:
            logging.error('No token provided for WebSocket connection')
            return False

        try:
            jwt.decode_token(token)
            logging.info(f'User connected via WebSocket')
        except Exception as e:
            logging.error(f'Invalid token for WebSocket connection: {str(e)}')
            return False
    except Exception as e:
        logging.error(f'Error during WebSocket connection: {str(e)}')
        return False

    return True

@socketio.on('disconnect')
def handle_disconnect():
    logging.info('Client disconnected from WebSocket')

@socketio.on('toggle_device')
@jwt_required()
def handle_toggle_device(data):
    try:
        current_user = get_jwt_identity()
        device_id = data.get('device_id')
        logging.info(f"User {current_user} toggling device {device_id} via WebSocket")
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
        
        emit('device_updated', device_data, broadcast=True)
        logging.info(f'Device {device_id} toggled. New blocked status: {device.blocked}')
    except Exception as e:
        logging.error(f'Error handling toggle_device: {str(e)}')
        emit('error', {'message': 'Unauthorized or invalid request'})
