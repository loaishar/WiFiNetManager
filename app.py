import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_jwt_extended import JWTManager

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)

# Setup secret key and database
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "a secret key"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Setup JWT
app.config["JWT_SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or "jwt secret key"
jwt = JWTManager(app)

db.init_app(app)

with app.app_context():
    import models
    db.create_all()

from routes import *

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
