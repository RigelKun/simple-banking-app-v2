import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
import secrets
import pymysql
from flask_wtf.csrf import CSRFProtect
from flask_limiter.errors import RateLimitExceeded

# Import extensions
from extensions import db, login_manager, bcrypt, limiter

# Load environment variables
load_dotenv()  # *Here for secure data loading from .env file*

# Initialize CSRF protection
csrf = CSRFProtect()  # *Here for CSRF protection*

# MySQL connection
pymysql.install_as_MySQLdb()

# Create Flask application
def create_app():
    app = Flask(__name__)
    
    # Use secure secret key for session management
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)  # *Here for secure session handling*

    # Enable CSRF protection
    csrf.init_app(app)  # *Here to protect all form submissions*

    # Database configuration using environment variables
    mysql_user = os.environ.get('MYSQL_USER', '')
    mysql_password = os.environ.get('MYSQL_PASSWORD', '')
    mysql_host = os.environ.get('MYSQL_HOST', '')
    mysql_port = os.environ.get('MYSQL_PORT', '3306')
    mysql_database = os.environ.get('MYSQL_DATABASE', '')

    if not mysql_host or not mysql_user or not mysql_database:
        print("WARNING: Missing DB configuration")  # *Here for configuration validation and debugging*

    db_uri = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}"
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize Flask extensions
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)  # *Here for protection against abuse via rate limiting*

    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit_exceeded(e):
        if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
            return jsonify({"error": "Rate limit exceeded", "message": str(e)}), 429
        return render_template('rate_limit_error.html', message=str(e)), 429  # *Here to handle abuse limits securely*

    return app

app = create_app()

from models import User, Transaction

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # *Here for secure session management*

from routes import *

def init_db():
    """Initialize the database with required tables and default admin user."""
    with app.app_context():
        db.create_all()

        # Load admin credentials securely
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@bankapp.com')  # *Here for secure admin identity*
        admin_username = os.environ.get('ADMIN_USERNAME', 'admin')  # *Here for configurable admin username*
        admin_password = os.environ.get('ADMIN_PASSWORD')  # *Here for secure password input*

        if not admin_password:
            raise ValueError("ADMIN_PASSWORD environment variable must be set for secure admin setup.")  # *Here to prevent unsecured default passwords*

        existing_admin = User.query.filter_by(is_admin=True).first()
        if not existing_admin:
            admin_user = User(
                username=admin_username,
                email=admin_email,
                account_number="0000000001",
                status="active",
                is_admin=True,
                balance=0.0
            )
            admin_user.set_password(admin_password)  # *Here to store password as a hash securely*
            db.session.add(admin_user)
            db.session.commit()
            print(f"Created admin user: {admin_username}")  # *Here for logging secure admin creation*

if __name__ == '__main__':
    # Only print env values in dev mode
    if os.environ.get('FLASK_ENV') == 'development':
        print("Loaded development environment variables:")
        print(f"MYSQL_HOST: {os.environ.get('MYSQL_HOST')}")
        print(f"MYSQL_USER: {os.environ.get('MYSQL_USER')}")
        print(f"MYSQL_DATABASE: {os.environ.get('MYSQL_DATABASE')}")  # *Here for debug mode only, never expose in production*

    with app.app_context():
        init_db()

    app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')  # *Here to prevent debug mode in production*
