from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies, verify_jwt_in_request, decode_token
from extensions import db, jwt, socketio
from models import User, Device
from network_scanner import scan_network
import logging
from datetime import datetime
from flask_socketio import emit

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
            access_token = create_access_token(identity=user.id)
            response = redirect(url_for('main.devices'))
            set_access_cookies(response, access_token)
            logging.info(f"User {username} logged in successfully")
            return response
        else:
            logging.warning(f"Failed login attempt for user {username}")
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@main.route('/devices')
@jwt_required()
def devices():
    logging.info("Accessing devices route")
    current_user_id = get_jwt_identity()
    return render_template('devices.html')

@main.route('/api/devices', methods=['GET'])
@jwt_required()
def get_devices():
    logging.info("Fetching devices")
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
            'last_seen': device.last_seen.isoformat() if device.last_seen else None
        } for device in devices])
    except Exception as e:
        logging.error(f"Error fetching devices: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@main.route('/api/devices/<int:device_id>/toggle', methods=['POST'])
@jwt_required()
def toggle_device(device_id):
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
            'last_seen': device.last_seen.isoformat() if device.last_seen else None
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
    logging.info("Scanning for new devices")
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
            'last_seen': device.last_seen.isoformat() if device.last_seen else None
        } for device in devices]
        
        emit('devices_update', devices_data, broadcast=True, namespace='/')
        logging.info(f"Emitted 'devices_update' event with {len(devices)} devices")
        
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error during device scan: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@main.route('/logout')
def logout():
    logging.info("User logged out")
    response = redirect(url_for('main.login'))
    response.delete_cookie('access_token_cookie')
    return response

@socketio.on('connect')
def handle_connect():
    try:
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        if not token:
            token = request.args.get('token')
        if not token:
            auth = request.args.get('auth')
            if auth:
                token = auth.get('token')
        if not token:
            token = request.cookies.get('access_token_cookie')

        if not token:
            logging.error('No token provided for WebSocket connection')
            return False

        try:
            decoded_token = decode_token(token)
            user_id = decoded_token['sub']
            logging.info(f'User {user_id} connected via WebSocket')
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
def handle_toggle_device(data):
    try:
        verify_jwt_in_request()
        device_id = data.get('device_id')
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
            'last_seen': device.last_seen.isoformat() if device.last_seen else None
        }
        
        emit('device_updated', device_data, broadcast=True)
        logging.info(f'Device {device_id} toggled. New blocked status: {device.blocked}')
    except Exception as e:
        logging.error(f'Error handling toggle_device: {str(e)}')
        emit('error', {'message': 'Unauthorized or invalid request'})
