from flask import render_template, request, jsonify, redirect, url_for, flash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies
from app import app, db
from models import User, Device
from network_scanner import scan_network
import logging
from datetime import datetime

logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def index():
    logging.info("Accessing index route")
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
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
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Error during registration: {str(e)}")
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    logging.info("Accessing login route")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            access_token = create_access_token(identity=user.id)
            response = redirect(url_for('devices'))
            set_access_cookies(response, access_token)
            logging.info(f"User {username} logged in successfully")
            return response
        else:
            logging.warning(f"Failed login attempt for user {username}")
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/devices')
@jwt_required()
def devices():
    logging.info("Accessing devices route")
    current_user_id = get_jwt_identity()
    return render_template('devices.html')

@app.route('/api/devices', methods=['GET'])
@jwt_required()
def get_devices():
    logging.info("Fetching devices")
    try:
        devices = Device.query.all()
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

@app.route('/api/devices/<int:device_id>/toggle', methods=['POST'])
@jwt_required()
def toggle_device(device_id):
    logging.info(f"Toggling device with ID: {device_id}")
    try:
        device = Device.query.get_or_404(device_id)
        device.blocked = not device.blocked
        db.session.commit()
        return jsonify({'success': True, 'blocked': device.blocked})
    except Exception as e:
        logging.error(f"Error toggling device {device_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/scan', methods=['POST'])
@jwt_required()
def scan():
    logging.info("Scanning for new devices")
    try:
        new_devices = scan_network()
        for device_data in new_devices:
            existing_device = Device.query.filter_by(mac_address=device_data['mac_address']).first()
            if existing_device:
                existing_device.name = device_data['name']
                existing_device.ip_address = device_data['ip_address']
                existing_device.status = device_data['status']
                existing_device.last_seen = device_data['last_seen']
            else:
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
        logging.info(f"Scan completed, {len(new_devices)} devices processed")
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error during device scan: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/logout')
def logout():
    logging.info("User logged out")
    response = redirect(url_for('login'))
    # Unset JWT cookies
    response.delete_cookie('access_token_cookie')
    return response

@app.errorhandler(404)
def not_found_error(error):
    logging.error(f"404 error: {error}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"500 error: {error}")
    db.session.rollback()
    return render_template('500.html'), 500
