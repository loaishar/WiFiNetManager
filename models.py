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
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    data_usage = db.Column(db.BigInteger, default=0)  # Total data usage in bytes
    last_usage_update = db.Column(db.DateTime, default=datetime.utcnow)
    bandwidth_limit = db.Column(db.Integer, default=0)  # Bandwidth limit in Mbps (0 = unlimited)
    notes = db.Column(db.Text, nullable=True)  # Admin notes about the device

    def update_data_usage(self, bytes_used):
        """Update device data usage with actual network statistics."""
        try:
            if not isinstance(bytes_used, (int, float)) or bytes_used < 0:
                logging.error(f"Invalid bytes_used value for device {self.name}: {bytes_used}")
                return

            # Calculate the difference since last update
            if self.data_usage is None:
                self.data_usage = 0
            
            # Only update if we have new data
            if bytes_used > self.data_usage:
                new_bytes = bytes_used - self.data_usage
                self.data_usage = bytes_used
                self.last_usage_update = datetime.utcnow()
                
                # Record the usage increment
                new_usage = NetworkUsage(
                    device_id=self.id,
                    data_used=new_bytes,
                    timestamp=datetime.utcnow()
                )
                db.session.add(new_usage)
                logging.debug(f"Updated data usage for device {self.name}: +{new_bytes} bytes")
        except Exception as e:
            logging.error(f"Error updating data usage for device {self.name}: {str(e)}")
            db.session.rollback()

    def get_hourly_usage(self):
        """Get hourly network usage statistics for the device."""
        try:
            hourly_usage = db.session.query(
                db.func.date_trunc('hour', NetworkUsage.timestamp).label('hour'),
                db.func.sum(NetworkUsage.data_used).label('total_usage')
            ).filter(NetworkUsage.device_id == self.id)\
             .group_by('hour')\
             .order_by('hour')\
             .all()
            return [(usage.hour, usage.total_usage) for usage in hourly_usage]
        except Exception as e:
            logging.error(f"Error getting hourly usage for device {self.name}: {str(e)}")
            return []

class NetworkUsage(db.Model):
    __tablename__ = 'network_usage'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    data_used = db.Column(db.BigInteger)  # Data used in bytes

    device = db.relationship('Device', backref=db.backref('usage_history', lazy='dynamic'))

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
