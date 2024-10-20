import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_jwt_extended import JWTManager, verify_jwt_in_request, get_jwt_identity
import logging

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.DEBUG)

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
        logging.error(f"Error in context processor: {str(e)}")
        return {'logged_in': False}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
