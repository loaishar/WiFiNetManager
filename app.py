import os
from flask import Flask
import logging
import eventlet
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

eventlet.monkey_patch()

from extensions import db, jwt, socketio, cors
from flask_migrate import Migrate
from routes import main as main_blueprint

def create_app():
    app = Flask(__name__)

    # Setup logging for production
    logging.basicConfig(
        level=logging.INFO if not app.debug else logging.DEBUG,
        format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('wifi_manager.log')
        ]
    )

    # Setup secret key and database
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

    # Setup JWT with secure settings
    app.config["JWT_SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24)
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_ACCESS_COOKIE_PATH"] = "/"
    app.config["JWT_REFRESH_COOKIE_PATH"] = "/refresh"
    app.config["JWT_COOKIE_CSRF_PROTECT"] = True
    app.config["JWT_COOKIE_SECURE"] = not app.debug  # True in production
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    app.config['JWT_COOKIE_SAMESITE'] = 'Lax'

    # Setup rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

    # Add rate limits for specific endpoints
    limiter.limit("5/minute")(main_blueprint)

    # Set environment flag
    app.config['RUNNING_ON_REPLIT'] = os.environ.get('REPL_ID') is not None

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    cors.init_app(app, supports_credentials=True)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='eventlet', logger=True, engineio_logger=True)
    
    # Initialize Flask-Migrate
    migrate = Migrate(app, db)

    # Add Socket.IO logging
    logging.getLogger('socketio').setLevel(logging.INFO)
    logging.getLogger('engineio').setLevel(logging.INFO)

    # Register the Blueprint
    app.register_blueprint(main_blueprint)

    # Initialize database and start monitoring
    with app.app_context():
        db.create_all()
        
        # Start network monitoring
        from network_scanner import start_total_usage_monitoring
        start_total_usage_monitoring()

    @socketio.on_error_default
    def default_error_handler(e):
        app.logger.error(f'An error occurred: {str(e)}')

    return app
