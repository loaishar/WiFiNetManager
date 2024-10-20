from flask import render_template, request, jsonify, redirect, url_for, flash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies
from app import app, db, jwt
from models import User, Device
from network_scanner import scan_network
import logging

logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    logging.debug("Entering login route")
    if request.method == 'POST':
        logging.debug("Processing POST request for login")
        username = request.form['username']
        password = request.form['password']
        logging.debug(f"Attempting login for user: {username}")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            logging.debug("User authenticated successfully")
            access_token = create_access_token(identity=user.id)
            logging.debug(f"Access token created: {access_token[:10]}...")
            response = redirect(url_for('devices'))
            set_access_cookies(response, access_token)
            logging.debug("Access token set in cookies")
            logging.debug(f"Redirecting to: {response.location}")
            return response
        else:
            logging.debug("Authentication failed")
            flash('Invalid username or password', 'error')

    logging.debug("Rendering login template")
    return render_template('login.html')

@app.route('/devices')
@jwt_required()
def devices():
    logging.debug("Accessing /devices route")
    current_user_id = get_jwt_identity()
    logging.debug(f"Current user ID: {current_user_id}")
    return render_template('devices.html')

@app.route('/api/devices', methods=['GET'])
@jwt_required()
def get_devices():
    logging.debug("Accessing /api/devices route")
    current_user_id = get_jwt_identity()
    logging.debug(f"Current user ID: {current_user_id}")
    devices = Device.query.all()
    return jsonify([{
        'id': device.id,
        'name': device.name,
        'ip_address': device.ip_address,
        'mac_address': device.mac_address,
        'status': device.status,
        'blocked': device.blocked
    } for device in devices])

@app.route('/api/devices/<int:device_id>/toggle', methods=['POST'])
@jwt_required()
def toggle_device(device_id):
    device = Device.query.get_or_404(device_id)
    device.blocked = not device.blocked
    db.session.commit()
    return jsonify({'success': True, 'blocked': device.blocked})

@app.route('/api/scan', methods=['POST'])
@jwt_required()
def scan():
    new_devices = scan_network()
    for device in new_devices:
        existing_device = Device.query.filter_by(mac_address=device['mac_address']).first()
        if not existing_device:
            new_device = Device(**device)
            db.session.add(new_device)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/logout')
def logout():
    response = redirect(url_for('login'))
    jwt.unset_jwt_cookies(response)
    return response

@app.errorhandler(Exception)
def handle_error(e):
    logging.error(f"An error occurred: {str(e)}")
    return jsonify(error=str(e)), 500
