import os
from flask import Flask
import logging
import eventlet

eventlet.monkey_patch()

from extensions import db, jwt, socketio, cors
from routes import main as main_blueprint

def create_app():
    app = Flask(__name__)

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG,
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

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    cors.init_app(app, supports_credentials=True)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='eventlet', logger=True, engineio_logger=True)

    # Add Socket.IO logging
    logging.getLogger('socketio').setLevel(logging.DEBUG)
    logging.getLogger('engineio').setLevel(logging.DEBUG)

    with app.app_context():
        from models import User, Device
        db.create_all()

    # Register the Blueprint
    app.register_blueprint(main_blueprint)

    # Print URL map for debugging
    print("URL Map:")
    print(app.url_map)

    # Add a test route
    @app.route('/test')
    def test_route():
        return 'Test Route Working'

    @socketio.on_error_default
    def default_error_handler(e):
        app.logger.error(f'An error occurred: {str(e)}')

    return app
