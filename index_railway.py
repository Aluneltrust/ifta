# index_railway.py - User management with email password reset functionality
# =============================================================================
# IMPORTS
# =============================================================================
import os
import json
import logging
import hashlib
import time
import base64
import secrets
import uuid
import re
from datetime import datetime, timedelta
from decimal import Decimal

import psycopg2
import psycopg2.extras
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin


# =============================================================================
# APP CONFIGURATION
# =============================================================================
app = Flask(__name__)

# CORS Configuration - Handle preflight requests properly
CORS(app, 
     resources={r"/api/*": {"origins": "*"}},
     allow_headers=["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],
     supports_credentials=True,
     methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"])

# Explicit OPTIONS handler for all /api/* routes
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        headers = response.headers
        headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept, Origin, X-Requested-With'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Max-Age'] = '3600'
        return response

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin', '*')
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept, Origin, X-Requested-With'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================
SECRET_KEY = os.environ.get('JWT_SECRET', secrets.token_hex(32))
DATABASE_URL = os.environ.get('DATABASE_URL')
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000')

# Square Payment Configuration
SQUARE_ACCESS_TOKEN = os.environ.get('SQUARE_ACCESS_TOKEN')
SQUARE_LOCATION_ID = os.environ.get('SQUARE_LOCATION_ID')
SQUARE_ENVIRONMENT = os.environ.get('SQUARE_ENVIRONMENT', 'sandbox')  # 'sandbox' or 'production'

# Square API URLs
SQUARE_API_URL = 'https://connect.squareupsandbox.com' if SQUARE_ENVIRONMENT == 'sandbox' else 'https://connect.squareup.com'


# =============================================================================
# DATABASE FUNCTIONS
# =============================================================================
def get_db_connection():
    """Get database connection"""
    if not DATABASE_URL:
        raise Exception("DATABASE_URL environment variable not set")
    return psycopg2.connect(DATABASE_URL)


def init_database():
    """Initialize database tables"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email VARCHAR(255) PRIMARY KEY,
                password VARCHAR(255) NOT NULL,
                credits DECIMAL(10,2) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS reset_tokens (
                email VARCHAR(255) PRIMARY KEY,
                token_hash VARCHAR(255) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Add payments table for tracking
        cur.execute('''
            CREATE TABLE IF NOT EXISTS payments (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                credits INTEGER NOT NULL,
                bonus_credits INTEGER DEFAULT 0,
                total_credits INTEGER NOT NULL,
                square_payment_id VARCHAR(255),
                square_checkout_id VARCHAR(255),
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
        ''')
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise


# Initialize on startup
init_database()


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def create_response(status="success", message="", data=None, errors=None, status_code=200):
    """Create standardized API response"""
    response_data = {
        "status": status,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }
    if data is not None:
        response_data.update(data)  # Merge data into response for backwards compatibility
    if errors is not None:
        response_data["errors"] = errors
    return jsonify(response_data), status_code


def validate_email(email):
    """Basic email validation"""
    if not email or not isinstance(email, str):
        return False
    return '@' in email and '.' in email.split('@')[-1] and len(email) > 5


def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"


def extract_token_from_request():
    """Extract token from Authorization header"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    return auth_header.replace('Bearer ', '')


# =============================================================================
# PASSWORD FUNCTIONS
# =============================================================================
def hash_password(password):
    """Hash password with random salt"""
    salt = secrets.token_hex(16)
    combined = password + salt
    hashed = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    try:
        salt, hashed = stored_hash.split(':')
        combined = password + salt
        computed_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        return computed_hash == hashed
    except ValueError:
        return False


# =============================================================================
# TOKEN FUNCTIONS
# =============================================================================
def create_token(email):
    """Create a JWT-like token"""
    payload = {
        'email': email,
        'iat': int(time.time()),
        'exp': int(time.time()) + (30 * 24 * 60 * 60),  # 30 days
        'jti': str(uuid.uuid4())
    }
    message = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    signature = hashlib.sha256((message + SECRET_KEY).encode()).hexdigest()
    token_data = f"{base64.b64encode(message.encode()).decode()}.{signature}"
    return base64.b64encode(token_data.encode()).decode()


def verify_token(token):
    """Verify and decode token"""
    try:
        decoded_token = base64.b64decode(token.encode()).decode()
        message_b64, signature = decoded_token.rsplit('.', 1)
        message = base64.b64decode(message_b64.encode()).decode()
        payload = json.loads(message)
        
        expected_signature = hashlib.sha256((message + SECRET_KEY).encode()).hexdigest()
        if signature != expected_signature:
            return None
        if time.time() > payload.get('exp', 0):
            return None
        return payload.get('email')
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


def generate_reset_token():
    """Generate secure reset token"""
    return secrets.token_urlsafe(32)


def hash_reset_token(token):
    """Hash token for storage"""
    return hashlib.sha256(token.encode()).hexdigest()


# =============================================================================
# USER DATABASE OPERATIONS
# =============================================================================
def get_user_by_email(email):
    """Get user by email"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        return dict(user) if user else None
    except Exception as e:
        logger.error(f"Error getting user {email}: {e}")
        return None


def create_user(email, password, credits=0):
    """Create new user"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        hashed_password = hash_password(password)
        
        cur.execute('''
            INSERT INTO users (email, password, credits, created_at, last_updated)
            VALUES (%s, %s, %s, %s, %s)
        ''', (email, hashed_password, credits, datetime.now(), datetime.now()))
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"User created: {email}")
        return True
    except psycopg2.IntegrityError:
        logger.warning(f"User already exists: {email}")
        return False
    except Exception as e:
        logger.error(f"Error creating user {email}: {e}")
        return False


def update_user_login(email):
    """Update last login timestamp"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            UPDATE users SET last_login = %s, last_updated = %s WHERE email = %s
        ''', (datetime.now(), datetime.now(), email))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"Error updating login for {email}: {e}")


def update_user_password(email, new_password):
    """Update user password"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        hashed_password = hash_password(new_password)
        
        cur.execute('''
            UPDATE users SET password = %s, last_updated = %s WHERE email = %s
        ''', (hashed_password, datetime.now(), email))
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Password updated for {email}")
        return True
    except Exception as e:
        logger.error(f"Error updating password for {email}: {e}")
        return False


# =============================================================================
# CREDITS DATABASE OPERATIONS
# =============================================================================
def get_user_credits(email):
    """Get user credits"""
    user = get_user_by_email(email)
    if user:
        credits = user['credits']
        return float(credits) if isinstance(credits, Decimal) else credits
    return 0


def add_user_credits(email, amount):
    """Add credits to user account"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        amount = Decimal(str(amount))
        
        cur.execute("SELECT credits FROM users WHERE email = %s", (email,))
        result = cur.fetchone()
        
        if result:
            current = Decimal(str(result[0])) if result[0] else Decimal('0')
            new_credits = max(Decimal('0'), current + amount)
            cur.execute('''
                UPDATE users SET credits = %s, last_updated = %s WHERE email = %s
            ''', (new_credits, datetime.now(), email))
        else:
            new_credits = max(Decimal('0'), amount)
            cur.execute('''
                INSERT INTO users (email, password, credits, created_at, last_updated)
                VALUES (%s, %s, %s, %s, %s)
            ''', (email, '', new_credits, datetime.now(), datetime.now()))
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Added {amount} credits to {email}, new balance: {new_credits}")
        return float(new_credits)
    except Exception as e:
        logger.error(f"Error adding credits to {email}: {e}")
        raise


def use_user_credits(email, amount=1.0):
    """Use credits from user account (supports fractional amounts)"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        amount = Decimal(str(amount))
        
        cur.execute("SELECT credits FROM users WHERE email = %s", (email,))
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            logger.warning(f"User not found: {email}")
            return False
        
        current = Decimal(str(result[0])) if result[0] else Decimal('0')
        
        if current < amount:
            cur.close()
            conn.close()
            logger.warning(f"Insufficient credits for {email}. Have: {current}, Need: {amount}")
            return False
        
        new_credits = round(current - amount, 2)
        cur.execute('''
            UPDATE users SET credits = %s, last_updated = %s WHERE email = %s
        ''', (new_credits, datetime.now(), email))
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Used {amount} credits for {email}, remaining: {new_credits}")
        return True
    except Exception as e:
        logger.error(f"Error using credits for {email}: {e}")
        return False


def use_user_credit(email):
    """Use exactly 1 credit (backwards compatibility)"""
    return use_user_credits(email, 1.0)


# =============================================================================
# RESET TOKEN DATABASE OPERATIONS
# =============================================================================
def save_reset_token(email, token_hash, expires_at):
    """Save reset token"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            INSERT INTO reset_tokens (email, token_hash, expires_at, used, created_at)
            VALUES (%s, %s, %s, FALSE, %s)
            ON CONFLICT (email) 
            DO UPDATE SET token_hash = %s, expires_at = %s, used = FALSE, created_at = %s
        ''', (email, token_hash, expires_at, datetime.now(), token_hash, expires_at, datetime.now()))
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Reset token saved for {email}")
    except Exception as e:
        logger.error(f"Error saving reset token for {email}: {e}")


def get_reset_token_info(token_hash):
    """Get reset token information"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('''
            SELECT * FROM reset_tokens 
            WHERE token_hash = %s AND used = FALSE AND expires_at > %s
        ''', (token_hash, datetime.now()))
        token_info = cur.fetchone()
        cur.close()
        conn.close()
        return dict(token_info) if token_info else None
    except Exception as e:
        logger.error(f"Error getting reset token info: {e}")
        return None


def mark_reset_token_used(email):
    """Mark reset token as used"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE reset_tokens SET used = TRUE WHERE email = %s", (email,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"Error marking token as used for {email}: {e}")


def cleanup_expired_tokens():
    """Clean up expired reset tokens"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM reset_tokens WHERE expires_at < %s OR used = TRUE", (datetime.now(),))
        deleted_count = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Cleaned up {deleted_count} expired/used tokens")
        return deleted_count
    except Exception as e:
        logger.error(f"Error cleaning up tokens: {e}")
        return 0


# =============================================================================
# PAYMENT DATABASE OPERATIONS
# =============================================================================
def create_payment_record(email, amount, credits, bonus_credits, total_credits, checkout_id=None):
    """Create a payment record"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            INSERT INTO payments (email, amount, credits, bonus_credits, total_credits, square_checkout_id, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s)
            RETURNING id
        ''', (email, amount, credits, bonus_credits, total_credits, checkout_id, datetime.now()))
        
        payment_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Payment record created: {payment_id} for {email}")
        return payment_id
    except Exception as e:
        logger.error(f"Error creating payment record: {e}")
        return None


def complete_payment(checkout_id, square_payment_id=None):
    """Mark payment as completed and add credits"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get payment record
        cur.execute('''
            SELECT * FROM payments WHERE square_checkout_id = %s AND status = 'pending'
        ''', (checkout_id,))
        payment = cur.fetchone()
        
        if not payment:
            cur.close()
            conn.close()
            logger.warning(f"Payment not found or already completed: {checkout_id}")
            return False
        
        # Update payment status
        cur.execute('''
            UPDATE payments SET status = 'completed', square_payment_id = %s, completed_at = %s
            WHERE square_checkout_id = %s
        ''', (square_payment_id, datetime.now(), checkout_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Add credits to user
        add_user_credits(payment['email'], payment['total_credits'])
        logger.info(f"Payment completed: {checkout_id}, added {payment['total_credits']} credits to {payment['email']}")
        return True
    except Exception as e:
        logger.error(f"Error completing payment: {e}")
        return False


# =============================================================================
# EMAIL FUNCTIONS
# =============================================================================
def send_email(to_email, subject, html_content):
    """Send email using Resend API"""
    resend_api_key = os.environ.get('RESEND_API_KEY')
    
    if not resend_api_key:
        logger.warning("No RESEND_API_KEY found")
        return False
        
    try:
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'Authorization': f'Bearer {resend_api_key}',
                'Content-Type': 'application/json'
            },
            json={
                'from': 'IFTA Counter <noreply@carriermiles.com>',
                'to': [to_email],
                'subject': subject,
                'html': html_content
            },
            timeout=30
        )
        
        if response.status_code == 200:
            logger.info(f"Email sent to {to_email}")
            return True
        else:
            logger.error(f"Resend API failed: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return False


def get_password_reset_email_html(reset_url, expires_at):
    """Generate password reset email HTML"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Password Reset - IFTA Counter</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
            .button {{ display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; margin: 20px 0; font-weight: bold; }}
            .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 6px; margin: 20px 0; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>We received a request to reset your password for your IFTA Counter account.</p>
            <p>Click the button below to reset your password:</p>
            <p style="text-align: center;">
                <a href="{reset_url}" class="button">Reset My Password</a>
            </p>
            <p>Or copy and paste this link:</p>
            <p style="word-break: break-all; background: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-family: monospace;">
                {reset_url}
            </p>
            <div class="warning">
                <strong>Important Security Information:</strong>
                <ul>
                    <li>This link will expire in <strong>1 hour</strong></li>
                    <li>If you didn't request this reset, please ignore this email</li>
                    <li>For security, this link can only be used once</li>
                    <li>Never share this link with anyone</li>
                </ul>
            </div>
        </div>
        <div class="footer">
            <p>Token expires at: {expires_at.strftime('%B %d, %Y at %I:%M %p UTC')}</p>
        </div>
    </body>
    </html>
    """


# =============================================================================
# ROUTES: HEALTH CHECK
# =============================================================================
@app.route('/health', methods=['GET'])
@cross_origin()
def health_check():
    return create_response(
        status="success",
        message="Railway User Management API",
        data={
            "version": "2.4.0",
            "service": "user_management",
            "features": ["auth", "credits", "email_password_reset", "square_payments"],
            "database": "postgresql",
            "email_configured": bool(os.environ.get('RESEND_API_KEY')),
            "square_configured": bool(SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID)
        }
    )


# =============================================================================
# ROUTES: AUTHENTICATION
# =============================================================================
@app.route('/api/auth/register', methods=['POST', 'OPTIONS'])
@cross_origin()
def register():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        if not request.is_json:
            return create_response("error", "Content-Type must be application/json", status_code=400)
        
        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not validate_email(email):
            return create_response("error", "Invalid email format", status_code=400)
        
        if not password or len(password) < 8:
            return create_response("error", "Password must be at least 8 characters", status_code=400)
        
        if not create_user(email, password):
            return create_response("error", "User already exists", status_code=409)
        
        token = create_token(email)
        logger.info(f"User registered: {email}")
        
        return create_response(
            "success", "Registration successful",
            data={
                "token": token,
                "user": {"email": email, "credits": 0, "created_at": datetime.now().isoformat()}
            },
            status_code=201
        )
    except Exception as e:
        logger.error(f"Registration error: {e}", exc_info=True)
        return create_response("error", "Registration failed", errors=[str(e)], status_code=500)


@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
@cross_origin()
def login():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        if not request.is_json:
            return create_response("error", "Content-Type must be application/json", status_code=400)
        
        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not validate_email(email) or not password:
            return create_response("error", "Invalid email or password", status_code=401)
        
        user = get_user_by_email(email)
        if not user:
            time.sleep(0.5)  # Prevent user enumeration
            return create_response("error", "Invalid credentials", status_code=401)
        
        if not verify_password(password, user['password']):
            return create_response("error", "Invalid credentials", status_code=401)
        
        update_user_login(email)
        token = create_token(email)
        logger.info(f"User logged in: {email}")
        
        return create_response(
            "success", "Login successful",
            data={
                "token": token,
                "user": {"email": email, "credits": user['credits'], "last_login": datetime.now().isoformat()}
            }
        )
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return create_response("error", "Login failed", errors=[str(e)], status_code=500)


@app.route('/api/auth/verify', methods=['GET', 'OPTIONS'])
@cross_origin()
def verify():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request()
        if not token:
            return create_response("error", "No token provided", status_code=401)
        
        email = verify_token(token)
        if not email:
            return create_response("error", "Invalid or expired token", status_code=401)
        
        user = get_user_by_email(email)
        if not user:
            return create_response("error", "User not found", status_code=404)
        
        return create_response(
            "success", "Token valid",
            data={
                "user": {
                    "email": email,
                    "credits": user['credits'],
                    "created_at": user['created_at'].isoformat() if user['created_at'] else None,
                    "last_login": user['last_login'].isoformat() if user['last_login'] else None
                }
            }
        )
    except Exception as e:
        logger.error(f"Verification error: {e}", exc_info=True)
        return create_response("error", "Verification failed", errors=[str(e)], status_code=500)


# =============================================================================
# ROUTES: PASSWORD RESET
# =============================================================================
@app.route('/api/auth/forgot-password', methods=['POST', 'OPTIONS'])
@cross_origin()
def forgot_password():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return create_response("error", "Email is required", status_code=400)
        
        email = data['email'].strip().lower()
        
        if not validate_email(email):
            return create_response("error", "Invalid email format", status_code=400)
        
        user = get_user_by_email(email)
        if not user:
            return create_response("success", "If that email exists, reset instructions have been sent")
        
        cleanup_expired_tokens()
        
        token = generate_reset_token()
        token_hash = hash_reset_token(token)
        expires_at = datetime.now() + timedelta(hours=1)
        
        save_reset_token(email, token_hash, expires_at)
        
        # Generate reset URL
        if FRONTEND_URL.startswith('http'):
            reset_url = f"{FRONTEND_URL}/#/reset-password?token={token}"
        else:
            reset_url = f"iftacounter://reset-password?token={token}"
        
        html_content = get_password_reset_email_html(reset_url, expires_at)
        
        if send_email(email, "Password Reset - IFTA Counter", html_content):
            return create_response("success", "Reset instructions have been sent to your email")
        else:
            logger.info(f"Reset URL for {email}: {reset_url}")
            return create_response(
                "success", "Reset link generated",
                data={"reset_url": reset_url, "expires_at": expires_at.isoformat()}
            )
    except Exception as e:
        logger.error(f"Forgot password error: {e}", exc_info=True)
        return create_response("error", "Internal server error", errors=[str(e)], status_code=500)


@app.route('/api/auth/reset-password', methods=['POST', 'OPTIONS'])
@cross_origin()
def reset_password():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        data = request.get_json()
        if not data or 'token' not in data or 'password' not in data:
            return create_response("error", "Token and new password are required", status_code=400)
        
        token = data['token']
        new_password = data['password']
        
        is_valid, message = validate_password(new_password)
        if not is_valid:
            return create_response("error", message, status_code=400)
        
        token_hash = hash_reset_token(token)
        token_info = get_reset_token_info(token_hash)
        
        if not token_info:
            return create_response("error", "Invalid or expired reset token", status_code=400)
        
        email = token_info['email']
        
        if not update_user_password(email, new_password):
            return create_response("error", "Failed to update password", status_code=500)
        
        mark_reset_token_used(email)
        logger.info(f"Password reset successful for {email}")
        
        return create_response("success", "Password has been reset successfully")
    except Exception as e:
        logger.error(f"Reset password error: {e}", exc_info=True)
        return create_response("error", "Internal server error", errors=[str(e)], status_code=500)


@app.route('/api/auth/change-password', methods=['POST', 'OPTIONS'])
@cross_origin()
def change_password():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        data = request.get_json()
        if not data:
            return create_response("error", "Request body required", status_code=400)
        
        email = data.get('email', '').strip().lower()
        current_password = data.get('currentPassword', '')
        new_password = data.get('newPassword', '')
        
        if not email or not current_password or not new_password:
            return create_response("error", "Email, current password, and new password are required", status_code=400)
        
        is_valid, message = validate_password(new_password)
        if not is_valid:
            return create_response("error", message, status_code=400)
        
        user = get_user_by_email(email)
        if not user:
            return create_response("error", "User not found", status_code=404)
        
        if not verify_password(current_password, user['password']):
            return create_response("error", "Current password is incorrect", status_code=401)
        
        if not update_user_password(email, new_password):
            return create_response("error", "Failed to update password", status_code=500)
        
        logger.info(f"Password changed for {email}")
        return create_response("success", "Password changed successfully")
    except Exception as e:
        logger.error(f"Change password error: {e}", exc_info=True)
        return create_response("error", "Internal server error", errors=[str(e)], status_code=500)


# =============================================================================
# ROUTES: CREDITS
# =============================================================================
@app.route('/api/credits/balance', methods=['GET', 'POST', 'OPTIONS'])
@cross_origin()
def get_balance():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        # Support both GET (with token) and POST (with email in body)
        if request.method == 'POST':
            data = request.get_json() or {}
            email = data.get('email', '').strip().lower()
            if not email:
                return create_response("error", "Email required", status_code=400)
        else:
            token = extract_token_from_request()
            if not token:
                return create_response("error", "Authentication required", status_code=401)
            
            email = verify_token(token)
            if not email:
                return create_response("error", "Invalid or expired token", status_code=401)
        
        credits = get_user_credits(email)
        return create_response("success", "Balance retrieved", data={"credits": credits, "email": email})
    except Exception as e:
        logger.error(f"Get balance error: {e}", exc_info=True)
        return create_response("error", "Failed to get balance", errors=[str(e)], status_code=500)


@app.route('/api/credits/use', methods=['POST', 'OPTIONS'])
@cross_origin()
def use_credit():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        logger.info("=" * 60)
        logger.info("CREDIT USE ENDPOINT CALLED")
        logger.info("=" * 60)
        
        # Log raw request data
        logger.info(f"Request Content-Type: {request.content_type}")
        logger.info(f"Request data (raw): {request.data}")
        
        token = extract_token_from_request()
        if not token:
            logger.error("No token provided")
            return create_response("error", "Authentication required", status_code=401)
        
        email = verify_token(token)
        if not email:
            logger.error("Invalid or expired token")
            return create_response("error", "Invalid or expired token", status_code=401)
        
        logger.info(f"User email: {email}")
        
        # Get and log the JSON data
        data = request.get_json() or {}
        logger.info(f"Parsed JSON data: {data}")
        logger.info(f"Data type: {type(data)}")
        logger.info(f"Data keys: {data.keys() if isinstance(data, dict) else 'N/A'}")
        
        # Get amount with detailed logging
        amount = data.get('amount', 1)
        logger.info(f"Amount from request: {amount}")
        logger.info(f"Amount type: {type(amount)}")
        logger.info(f"Amount == 1: {amount == 1}")
        logger.info(f"'amount' in data: {'amount' in data}")
        
        try:
            amount = float(amount)
            logger.info(f"Amount after float conversion: {amount}")
            if amount <= 0:
                logger.error(f"Amount is not positive: {amount}")
                return create_response("error", "Amount must be positive", status_code=400)
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid amount conversion error: {e}")
            return create_response("error", "Invalid amount", status_code=400)
        
        # Get current balance before
        current_balance = get_user_credits(email)
        logger.info(f"Current balance BEFORE: {current_balance}")
        logger.info(f"Attempting to deduct: {amount}")
        
        if use_user_credits(email, amount):
            remaining = get_user_credits(email)
            logger.info("=" * 60)
            logger.info("CREDIT DEDUCTION SUCCESSFUL")
            logger.info(f"  Email: {email}")
            logger.info(f"  Amount requested: {amount}")
            logger.info(f"  Balance before: {current_balance}")
            logger.info(f"  Balance after: {remaining}")
            logger.info(f"  Actual deduction: {current_balance - remaining}")
            logger.info("=" * 60)
            return create_response("success", "Credits used", data={"amount_used": amount, "remaining": remaining})
        else:
            logger.error(f"use_user_credits returned False for {email}, amount={amount}")
            return create_response("error", "Insufficient credits", status_code=400)
    except Exception as e:
        logger.error(f"Use credit error: {e}", exc_info=True)
        return create_response("error", "Failed to use credits", errors=[str(e)], status_code=500)


@app.route('/api/credits/add', methods=['POST', 'OPTIONS'])
@cross_origin()
def add_credits():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        if not request.is_json:
            return create_response("error", "Content-Type must be application/json", status_code=400)
        
        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)
        
        email = data.get('email', '').strip().lower()
        amount = data.get('amount', 0)
        
        if not validate_email(email):
            return create_response("error", "Invalid email", status_code=400)
        
        try:
            amount = float(amount)
            if amount <= 0:
                return create_response("error", "Amount must be positive", status_code=400)
        except (ValueError, TypeError):
            return create_response("error", "Invalid amount", status_code=400)
        
        new_balance = add_user_credits(email, amount)
        logger.info(f"Added {amount} credits to {email}")
        
        return create_response("success", "Credits added", data={"credits": new_balance, "added": amount})
    except Exception as e:
        logger.error(f"Add credits error: {e}", exc_info=True)
        return create_response("error", "Failed to add credits", errors=[str(e)], status_code=500)


# =============================================================================
# ROUTES: PAYMENTS (Square Integration)
# =============================================================================
@app.route('/api/payment/checkout-link', methods=['POST', 'OPTIONS'])
@cross_origin()
def create_checkout_link():
    """Create a Square checkout link for credit purchase"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)
        
        email = data.get('email', '').strip().lower()
        amount = data.get('amount', 0)
        credits = data.get('credits', 0)
        bonus_credits = data.get('bonusCredits', 0)
        total_credits = data.get('totalCredits', 0)
        
        logger.info(f"Checkout request: email={email}, amount={amount}, credits={credits}, bonus={bonus_credits}, total={total_credits}")
        
        if not validate_email(email):
            return create_response("error", "Invalid email", status_code=400)
        
        try:
            amount = float(amount)
            if amount <= 0:
                return create_response("error", "Amount must be positive", status_code=400)
        except (ValueError, TypeError):
            return create_response("error", "Invalid amount", status_code=400)
        
        # Check if Square is configured
        if not SQUARE_ACCESS_TOKEN or not SQUARE_LOCATION_ID:
            logger.warning("Square not configured, using test mode")
            # Test mode - directly add credits
            new_balance = add_user_credits(email, total_credits)
            return create_response(
                "success",
                "Test mode - credits added directly",
                data={
                    "success": True,
                    "testMode": True,
                    "credits": new_balance,
                    "added": total_credits
                }
            )
        
        # Create payment record
        checkout_id = str(uuid.uuid4())
        payment_id = create_payment_record(email, amount, credits, bonus_credits, total_credits, checkout_id)
        
        if not payment_id:
            return create_response("error", "Failed to create payment record", status_code=500)
        
        # Create Square checkout
        try:
            amount_cents = int(amount * 100)
            
            checkout_payload = {
                "idempotency_key": checkout_id,
                "order": {
                    "location_id": SQUARE_LOCATION_ID,
                    "line_items": [
                        {
                            "name": f"{total_credits} IFTA Credits",
                            "quantity": "1",
                            "base_price_money": {
                                "amount": amount_cents,
                                "currency": "USD"
                            },
                            "note": f"Credits: {credits}, Bonus: {bonus_credits}"
                        }
                    ]
                },
                "checkout_options": {
                    "redirect_url": f"{FRONTEND_URL}/#/payment-success?checkout_id={checkout_id}",
                    "merchant_support_email": "support@carriermiles.com"
                },
                "pre_populate_buyer_email": email
            }
            
            response = requests.post(
                f"{SQUARE_API_URL}/v2/online-checkout/payment-links",
                headers={
                    "Square-Version": "2024-01-18",
                    "Authorization": f"Bearer {SQUARE_ACCESS_TOKEN}",
                    "Content-Type": "application/json"
                },
                json=checkout_payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                checkout_url = result.get('payment_link', {}).get('url')
                
                if checkout_url:
                    logger.info(f"Square checkout created: {checkout_url}")
                    return create_response(
                        "success",
                        "Checkout link created",
                        data={
                            "success": True,
                            "checkoutUrl": checkout_url,
                            "checkoutId": checkout_id
                        }
                    )
                else:
                    logger.error(f"No checkout URL in response: {result}")
                    return create_response("error", "Failed to get checkout URL", status_code=500)
            else:
                logger.error(f"Square API error: {response.status_code} - {response.text}")
                return create_response("error", f"Square API error: {response.status_code}", status_code=500)
                
        except requests.exceptions.Timeout:
            logger.error("Square API timeout")
            return create_response("error", "Payment service timeout", status_code=504)
        except requests.exceptions.RequestException as e:
            logger.error(f"Square API request error: {e}")
            return create_response("error", "Payment service error", status_code=502)
            
    except Exception as e:
        logger.error(f"Checkout link error: {e}", exc_info=True)
        return create_response("error", "Failed to create checkout", errors=[str(e)], status_code=500)


@app.route('/api/payment/webhook', methods=['POST', 'OPTIONS'])
@cross_origin()
def payment_webhook():
    """Handle Square payment webhooks"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json()
        logger.info(f"Webhook received: {json.dumps(data, indent=2)}")
        
        event_type = data.get('type')
        
        if event_type == 'payment.updated':
            payment_data = data.get('data', {}).get('object', {}).get('payment', {})
            payment_status = payment_data.get('status')
            
            logger.info(f"Payment status: {payment_status}")
            
            if payment_status == 'COMPLETED':
                square_payment_id = payment_data.get('id')
                amount_cents = payment_data.get('amount_money', {}).get('amount', 0)
                amount_dollars = amount_cents / 100
                
                logger.info(f"Payment completed: amount=${amount_dollars}, square_id={square_payment_id}")
                
                # Find most recent pending payment with matching amount
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                cur.execute('''
                    SELECT * FROM payments 
                    WHERE amount = %s AND status = 'pending'
                    ORDER BY created_at DESC LIMIT 1
                ''', (amount_dollars,))
                payment = cur.fetchone()
                
                cur.close()
                conn.close()
                
                if payment:
                    complete_payment(payment['square_checkout_id'], square_payment_id)
                    logger.info(f"Payment webhook processed for {payment['email']}")
                else:
                    logger.warning(f"No pending payment found for amount ${amount_dollars}")
        
        return create_response("success", "Webhook received")
    except Exception as e:
        logger.error(f"Webhook error: {e}", exc_info=True)
        return create_response("error", "Webhook processing failed", status_code=500)
    
    

@app.route('/api/payment/verify', methods=['POST', 'OPTIONS'])
@cross_origin()
def verify_payment():
    """Verify a payment by checkout ID"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json()
        checkout_id = data.get('checkoutId')
        
        if not checkout_id:
            return create_response("error", "Checkout ID required", status_code=400)
        
        # Check payment status in database
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute('''
            SELECT * FROM payments WHERE square_checkout_id = %s
        ''', (checkout_id,))
        payment = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not payment:
            return create_response("error", "Payment not found", status_code=404)
        
        return create_response(
            "success",
            "Payment status retrieved",
            data={
                "status": payment['status'],
                "email": payment['email'],
                "amount": float(payment['amount']),
                "totalCredits": payment['total_credits'],
                "completed": payment['status'] == 'completed'
            }
        )
    except Exception as e:
        logger.error(f"Verify payment error: {e}", exc_info=True)
        return create_response("error", "Failed to verify payment", status_code=500)


# =============================================================================
# ROUTES: DEBUG
# =============================================================================
@app.route('/api/debug/email-config', methods=['GET', 'OPTIONS'])
@cross_origin()
def debug_email_config():
    if request.method == 'OPTIONS':
        return '', 204
    resend_key = os.environ.get('RESEND_API_KEY')
    return create_response(
        "success", "Email configuration status",
        data={
            "resend_api_key_set": bool(resend_key),
            "resend_key_preview": resend_key[:10] + "..." if resend_key else "NOT SET",
            "frontend_url": FRONTEND_URL,
            "email_ready": bool(resend_key)
        }
    )


@app.route('/api/debug/routes', methods=['GET', 'OPTIONS'])
@cross_origin()
def debug_routes():
    if request.method == 'OPTIONS':
        return '', 204
    routes_info = []
    for rule in app.url_map.iter_rules():
        methods = list(rule.methods - {'HEAD', 'OPTIONS'})
        if methods:
            routes_info.append({"endpoint": rule.endpoint, "methods": methods, "rule": str(rule)})
    
    return create_response(
        "success", "Available routes",
        data={"total_routes": len(routes_info), "routes": sorted(routes_info, key=lambda x: x['rule'])}
    )


@app.route('/api/debug/database', methods=['GET', 'OPTIONS'])
@cross_origin()
def debug_database():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT COUNT(*) FROM users")
        user_count = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM reset_tokens WHERE used = FALSE AND expires_at > %s", (datetime.now(),))
        active_tokens = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return create_response(
            "success", "Database status",
            data={"database_connected": True, "total_users": user_count, "active_reset_tokens": active_tokens}
        )
    except Exception as e:
        logger.error(f"Database debug error: {e}")
        return create_response("error", "Database connection failed", errors=[str(e)], status_code=500)


@app.route('/api/debug/square', methods=['GET', 'OPTIONS'])
@cross_origin()
def debug_square():
    """Debug Square configuration"""
    if request.method == 'OPTIONS':
        return '', 204
    return create_response(
        "success", "Square configuration status",
        data={
            "square_configured": bool(SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID),
            "square_environment": SQUARE_ENVIRONMENT,
            "location_id_set": bool(SQUARE_LOCATION_ID),
            "access_token_set": bool(SQUARE_ACCESS_TOKEN),
            "api_url": SQUARE_API_URL
        }
    )


# =============================================================================
# ERROR HANDLERS
# =============================================================================
@app.errorhandler(404)
def not_found(e):
    return create_response(
        "error", "Resource not found",
        data={"requested_path": request.path, "method": request.method},
        status_code=404
    )


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}", exc_info=True)
    return create_response("error", "Internal server error", errors=[str(e)], status_code=500)


# =============================================================================
# MAIN
# =============================================================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info("=" * 50)
    logger.info("STARTING RAILWAY USER MANAGEMENT API")
    logger.info(f"Port: {port}")
    logger.info(f"Frontend URL: {FRONTEND_URL}")
    logger.info(f"Email configured: {bool(os.environ.get('RESEND_API_KEY'))}")
    logger.info(f"Square configured: {bool(SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID)}")
    logger.info(f"Square environment: {SQUARE_ENVIRONMENT}")
    logger.info("=" * 50)
    app.run(host='0.0.0.0', port=port, debug=False)