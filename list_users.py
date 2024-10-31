from app import create_app
from extensions import db
from models import User

app = create_app()

with app.app_context():
    users = User.query.all()
    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}, Is Admin: {user.is_admin}")
