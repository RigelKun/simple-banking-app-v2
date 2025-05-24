import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
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

# Load environment variables from .env file
load_dotenv()

# Initialize CSRF protection instance
csrf = CSRFProtect()

# Set up MySQL compatibility with SQLAlchemy
pymysql.install_as_MySQLdb()

# Create Flask application
def create_app():
    app = Flask(__name__)
    
    # Set secret key for session security, using environment variable or a secure fallback
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)

    # Secure session cookie flags
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = os.path.exists('cert.pem') and os.path.exists('key.pem')  # True only if HTTPS certs exist
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Attach CSRF protection to the Flask app
    csrf.init_app(app)

    # Load database configuration from environment variables
    mysql_user = os.environ.get('MYSQL_USER', '')
    mysql_password = os.environ.get('MYSQL_PASSWORD', '')
    mysql_host = os.environ.get('MYSQL_HOST', '')
    mysql_port = os.environ.get('MYSQL_PORT', '3306')
    mysql_database = os.environ.get('MYSQL_DATABASE', '')

    # Validate presence of essential DB configuration values
    if not mysql_host or not mysql_user or not mysql_database:
        print("WARNING: Missing DB configuration")

    # Configure SQLAlchemy with MySQL database URI
    db_uri = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}"
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize Flask extensions
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)

    # Custom error handler for rate limiting violations
    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit_exceeded(e):
        if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
            return jsonify({"error": "Rate limit exceeded", "message": str(e)}), 429
        return render_template('rate_limit_error.html', message=str(e)), 429

    return app

app = create_app()

# Force HTTPS redirect
@app.before_request
def redirect_to_https():
    # Only redirect if app is running with SSL certs
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)

from models import User, Transaction

# Load user from session using user ID for authentication
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from routes import *

def init_db():
    """Initialize the database schema and create the default admin user if none exists."""
    with app.app_context():
        db.create_all()

        # Load admin credentials from environment for secure setup
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@bankapp.com')
        admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_password = os.environ.get('ADMIN_PASSWORD')  # Secure password from environment variable 

        if not admin_password:
            raise ValueError("ADMIN_PASSWORD environment variable must be set for secure admin setup.")

        # Create admin user only if one does not already exist
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
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            print(f"Created admin user: {admin_username}")

if __name__ == '__main__':
    # Print environment configuration in development mode only
    if os.environ.get('FLASK_ENV') == 'development':
        print("Loaded development environment variables:")
        print(f"MYSQL_HOST: {os.environ.get('MYSQL_HOST')}")
        print(f"MYSQL_USER: {os.environ.get('MYSQL_USER')}")
        print(f"MYSQL_DATABASE: {os.environ.get('MYSQL_DATABASE')}")

    with app.app_context():
        init_db()

    ssl_cert = 'cert.pem'  # Path to your SSL certificate
    ssl_key = 'key.pem'    # Path to your SSL key

    if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        print("Starting app with SSL (HTTPS)")
        app.run(
            debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
            ssl_context=(ssl_cert, ssl_key)
        )
    else:
        print("SSL cert/key not found, starting app without HTTPS")
        app.run(
            debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
        )
