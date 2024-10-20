import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_jwt_extended import JWTManager, verify_jwt_in_request, get_jwt_identity
from flask_migrate import Migrate
from flask_socketio import SocketIO
import logging

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Setup secret key and database
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "a secret key"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Setup JWT
app.config["JWT_SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or "jwt secret key"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False  # Set to True in production with HTTPS
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Set to True and implement CSRF protection in production
jwt = JWTManager(app)

db.init_app(app)

with app.app_context():
    import models
    db.create_all()

from routes import *

@app.context_processor
def inject_logged_in():
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        return {'logged_in': bool(user_id)}
    except Exception as e:
        app.logger.error(f"Error in context processor: {str(e)}")
        return {'logged_in': False}

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f"404 error: {error}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"500 error: {error}")
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
