from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False, index=True)
    status = db.Column(db.Boolean, default=True)
    blocked = db.Column(db.Boolean, default=False)
    bandwidth_limit = db.Column(db.Integer, default=0)  # Bandwidth limit in Mbps (0 = unlimited)
    notes = db.Column(db.Text, nullable=True)  # Admin notes about the device
    
    # New fields for enhanced device information
    device_type = db.Column(db.String(50))  # smartphone, laptop, IoT device, etc.
    vendor = db.Column(db.String(100))  # Device manufacturer based on MAC address
    os_type = db.Column(db.String(50))  # Operating system if detectable
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, onupdate=datetime.utcnow)
    open_ports = db.Column(db.JSON)  # Store port scanning results
    network_speed = db.Column(db.Float)  # Current network speed in Mbps
    
    # Relationships
    historical_presence = db.relationship('DeviceHistory', backref='device', lazy=True)
    usage_history = db.relationship('NetworkUsage', backref='device', lazy='dynamic')

class DeviceHistory(db.Model):
    __tablename__ = 'device_history'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(20))  # 'connected' or 'disconnected'
    connection_speed = db.Column(db.Float)  # Network speed at the time of the event

class NetworkUsage(db.Model):
    __tablename__ = 'network_usage'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    data_used = db.Column(db.BigInteger)  # Data used in bytes

class TotalNetworkUsage(db.Model):
    __tablename__ = 'total_network_usage'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    bytes_sent = db.Column(db.BigInteger)
    bytes_recv = db.Column(db.BigInteger)

class NetworkSettings(db.Model):
    __tablename__ = 'network_settings'
    id = db.Column(db.Integer, primary_key=True)
    setting_name = db.Column(db.String(64), unique=True, nullable=False)
    setting_value = db.Column(db.String(256))
    description = db.Column(db.Text)
    last_modified = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    modified_by = db.Column(db.Integer, db.ForeignKey('users.id'))
