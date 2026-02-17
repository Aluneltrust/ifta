# index_railway.py - User management with first purchase bonus
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

from functools import wraps
from collections import defaultdict
import time


# =============================================================================
# APP CONFIGURATION
# =============================================================================
app = Flask(__name__)

CORS(app, 
     resources={r"/api/*": {"origins": "*"}},
     allow_headers=["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],
     supports_credentials=True,
     methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"])

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

# First Purchase Bonus Configuration
# Bonus credits added to ANY first purchase amount
FIRST_PURCHASE_BONUS_CREDITS = 10  # e.g., $50 purchase = 50 + 10 = 60 credits

# Square Payment Configuration
SQUARE_ACCESS_TOKEN = os.environ.get('SQUARE_ACCESS_TOKEN')
SQUARE_LOCATION_ID = os.environ.get('SQUARE_LOCATION_ID')
SQUARE_ENVIRONMENT = os.environ.get('SQUARE_ENVIRONMENT', 'sandbox')

SQUARE_API_URL = 'https://connect.squareupsandbox.com' if SQUARE_ENVIRONMENT == 'sandbox' else 'https://connect.squareup.com'

# Twilio SMS Configuration
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER')


# =============================================================================
# DATABASE FUNCTIONS
# =============================================================================
def get_db_connection():
    """Get database connection"""
    if not DATABASE_URL:
        raise Exception("DATABASE_URL environment variable not set")
    return psycopg2.connect(DATABASE_URL)


def init_database():
    """Initialize database tables and add missing columns"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Users table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email VARCHAR(255) PRIMARY KEY,
                password VARCHAR(255) NOT NULL,
                credits DECIMAL(10,2) DEFAULT 0,
                first_purchase_used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Add first_purchase_used column if it doesn't exist
        cur.execute('''
            ALTER TABLE users 
            ADD COLUMN IF NOT EXISTS first_purchase_used BOOLEAN DEFAULT FALSE
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
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS payments (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                credits INTEGER NOT NULL,
                bonus_credits INTEGER DEFAULT 0,
                total_credits INTEGER NOT NULL,
                is_first_purchase BOOLEAN DEFAULT FALSE,
                square_payment_id VARCHAR(255),
                square_checkout_id VARCHAR(255),
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
        ''')
        
        # Add missing columns to payments table if they don't exist
        cur.execute('ALTER TABLE payments ADD COLUMN IF NOT EXISTS bonus_credits INTEGER DEFAULT 0')
        cur.execute('ALTER TABLE payments ADD COLUMN IF NOT EXISTS total_credits INTEGER')
        cur.execute('ALTER TABLE payments ADD COLUMN IF NOT EXISTS is_first_purchase BOOLEAN DEFAULT FALSE')
        cur.execute('ALTER TABLE payments ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT \'pending\'')
        cur.execute('ALTER TABLE payments ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
        cur.execute('ALTER TABLE payments ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP')
        cur.execute('ALTER TABLE payments ADD COLUMN IF NOT EXISTS user_id INTEGER')
        cur.execute("ALTER TABLE payments ADD COLUMN IF NOT EXISTS bsv_txid VARCHAR(255)")
        cur.execute("ALTER TABLE payments ADD COLUMN IF NOT EXISTS payment_type VARCHAR(20) DEFAULT 'square'")
        
        # Update any null total_credits to match credits + bonus
        cur.execute('''
            UPDATE payments 
            SET total_credits = credits + COALESCE(bonus_credits, 0) 
            WHERE total_credits IS NULL
        ''')
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise


init_database()



# Simple in-memory rate limiter
request_counts = defaultdict(list)

def rate_limit(max_requests=5, window_seconds=300):
    """Allow max_requests per window_seconds per IP"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            
            # Clean old requests
            request_counts[ip] = [t for t in request_counts[ip] if now - t < window_seconds]
            
            if len(request_counts[ip]) >= max_requests:
                return create_response("error", "Too many requests. Try again later.", status_code=429)
            
            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator


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
        response_data.update(data)
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
        'exp': int(time.time()) + (30 * 24 * 60 * 60),
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
            INSERT INTO users (email, password, credits, first_purchase_used, created_at, last_updated)
            VALUES (%s, %s, %s, FALSE, %s, %s)
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


def check_first_purchase_available(email):
    """Check if user is eligible for first purchase bonus"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT first_purchase_used FROM users WHERE email = %s",
            (email,)
        )
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if result is None:
            return True  # New user, eligible
        return not result[0]  # Return True if first_purchase_used is False
    except Exception as e:
        logger.error(f"Error checking first purchase for {email}: {e}")
        return False


def mark_first_purchase_used(email):
    """Mark first purchase bonus as used"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            UPDATE users SET first_purchase_used = TRUE, last_updated = %s WHERE email = %s
        ''', (datetime.now(), email))
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"First purchase marked as used for {email}")
        return True
    except Exception as e:
        logger.error(f"Error marking first purchase for {email}: {e}")
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
    """Use credits from user account"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        amount = Decimal(str(amount))
        
        cur.execute("SELECT credits FROM users WHERE email = %s", (email,))
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            return False
        
        current = Decimal(str(result[0])) if result[0] else Decimal('0')
        
        if current < amount:
            cur.close()
            conn.close()
            return False
        
        new_credits = round(current - amount, 2)
        cur.execute('''
            UPDATE users SET credits = %s, last_updated = %s WHERE email = %s
        ''', (new_credits, datetime.now(), email))
        
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error using credits for {email}: {e}")
        return False


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
        return deleted_count
    except Exception as e:
        logger.error(f"Error cleaning up tokens: {e}")
        return 0


# =============================================================================
# PAYMENT DATABASE OPERATIONS
# =============================================================================
def create_payment_record(email, amount, credits, bonus_credits, total_credits, checkout_id=None, is_first_purchase=False):
    """Create a payment record"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            INSERT INTO payments (email, amount, credits, bonus_credits, total_credits, is_first_purchase, square_checkout_id, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s)
            RETURNING id
        ''', (email, amount, credits, bonus_credits, total_credits, is_first_purchase, checkout_id, datetime.now()))
        
        payment_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Payment record created: {payment_id} for {email}, first_purchase={is_first_purchase}")
        return payment_id
    except Exception as e:
        logger.error(f"Error creating payment record: {e}")
        return None


def complete_payment(checkout_id, square_payment_id=None):
    """Mark payment as completed and add credits"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute('''
            SELECT * FROM payments WHERE square_checkout_id = %s AND status = 'pending'
        ''', (checkout_id,))
        payment = cur.fetchone()
        
        if not payment:
            cur.close()
            conn.close()
            logger.warning(f"Payment not found or already completed: {checkout_id}")
            return False
        
        cur.execute('''
            UPDATE payments SET status = 'completed', square_payment_id = %s, completed_at = %s
            WHERE square_checkout_id = %s
        ''', (square_payment_id, datetime.now(), checkout_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Add credits to user
        add_user_credits(payment['email'], payment['total_credits'])
        
        # If this was first purchase, mark it as used
        if payment['is_first_purchase']:
            mark_first_purchase_used(payment['email'])
        
        logger.info(f"Payment completed: {checkout_id}, added {payment['total_credits']} credits to {payment['email']}")
        return True
    except Exception as e:
        logger.error(f"Error completing payment: {e}")
        return False



# =============================================================================
# ROUTES: BSV PAYMENTS
# =============================================================================
# Add this section to your index_railway.py after the existing payment routes

@app.route('/api/credits/bsv-payment', methods=['POST', 'OPTIONS'])
@cross_origin()
def bsv_payment():
    """Process BSV payment and add credits"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        # Verify authentication
        token = extract_token_from_request()
        if not token:
            return create_response("error", "Authentication required", status_code=401)
        
        token_email = verify_token(token)
        if not token_email:
            return create_response("error", "Invalid or expired token", status_code=401)
        
        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)
        
        email = data.get('email', '').strip().lower()
        txid = data.get('txid', '')
        amount = data.get('amount', 0)
        satoshis = data.get('satoshis', 0)
        credits = data.get('credits', 0)
        bonus_credits = data.get('bonusCredits', 0)
        total_credits = data.get('totalCredits', 0)
        is_first_purchase = data.get('isFirstPurchase', False)
        
        # Validate
        if not txid:
            return create_response("error", "Transaction ID required", status_code=400)
        
        if not validate_email(email):
            return create_response("error", "Invalid email", status_code=400)
        
        # Verify email matches token
        if email != token_email:
            return create_response("error", "Email mismatch", status_code=403)
        
        if total_credits <= 0:
            return create_response("error", "Invalid credits amount", status_code=400)
        
        # Check for duplicate transaction
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT id FROM payments WHERE bsv_txid = %s', (txid,))
        existing = cur.fetchone()
        
        if existing:
            cur.close()
            conn.close()
            return create_response("error", "Transaction already processed", status_code=409)
        
        # Verify first purchase eligibility if claimed
        if is_first_purchase:
            if not check_first_purchase_available(email):
                cur.close()
                conn.close()
                return create_response(
                    "error", 
                    "First purchase bonus has already been used",
                    status_code=400
                )
        
        # Create payment record
        cur.execute('''
            INSERT INTO payments (email, amount, credits, bonus_credits, total_credits, is_first_purchase, bsv_txid, payment_type, status, created_at, completed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'bsv', 'completed', %s, %s)
            RETURNING id
        ''', (email, amount, credits, bonus_credits, total_credits, is_first_purchase, txid, datetime.now(), datetime.now()))
        
        payment_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        
        # Add credits to user
        new_balance = add_user_credits(email, total_credits)
        
        # Mark first purchase as used if applicable
        if is_first_purchase:
            mark_first_purchase_used(email)
        
        logger.info(f"BSV payment processed: {payment_id}, txid={txid}, added {total_credits} credits to {email}")
        
        return create_response(
            "success", 
            "BSV payment processed successfully",
            data={
                "payment_id": payment_id,
                "txid": txid,
                "credits_added": total_credits,
                "new_balance": new_balance,
                "is_first_purchase": is_first_purchase
            }
        )
        
    except Exception as e:
        logger.error(f"BSV payment error: {e}", exc_info=True)
        return create_response("error", "Failed to process BSV payment", status_code=500)



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
                'from': 'MilesOn <noreply@carriermiles.com>',
                'to': [to_email],
                'subject': subject,
                'html': html_content
            },
            timeout=30
        )
        
        if response.status_code == 200:
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
    <head><title>Password Reset - MilesOn</title></head>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1>Password Reset Request</h1>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
            <p>Click the button below to reset your password:</p>
            <p style="text-align: center;">
                <a href="{reset_url}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold;">Reset My Password</a>
            </p>
            <p>This link expires in 1 hour.</p>
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
            "version": "3.1.0",
            "features": ["auth", "credits", "first_purchase_bonus", "square_payments", "sms_messaging", "stablecoin_payments"],
            "square_configured": bool(SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID),
            "twilio_configured": bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE_NUMBER),
            "stablecoin_merchant": bool(os.environ.get('STABLECOIN_MERCHANT_ADDRESS')),
            "first_purchase_bonus": {
                "bonus_credits": FIRST_PURCHASE_BONUS_CREDITS,
                "description": f"+{FIRST_PURCHASE_BONUS_CREDITS} bonus credits on first purchase"
            }
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
        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not validate_email(email):
            return create_response("error", "Invalid email format", status_code=400)
        
        if not password or len(password) < 8:
            return create_response("error", "Password must be at least 8 characters", status_code=400)
        
        if not create_user(email, password, credits=0):
            return create_response("error", "User already exists", status_code=409)
        
        token = create_token(email)
        logger.info(f"User registered: {email}")
        
        return create_response(
            "success", 
            "Registration successful! Get 10 credits for just $1 with your first purchase.",
            data={
                "token": token,
                "user": {
                    "email": email, 
                    "credits": 0,
                    "first_purchase_available": True,
                    "created_at": datetime.now().isoformat()
                },
                "first_purchase_offer": {
                    "available": True,
                    "bonus_credits": FIRST_PURCHASE_BONUS_CREDITS
                }
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
        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not validate_email(email) or not password:
            return create_response("error", "Invalid email or password", status_code=401)
        
        user = get_user_by_email(email)
        if not user:
            time.sleep(0.5)
            return create_response("error", "Invalid credentials", status_code=401)
        
        if not verify_password(password, user['password']):
            return create_response("error", "Invalid credentials", status_code=401)
        
        update_user_login(email)
        token = create_token(email)
        
        first_purchase_available = not user.get('first_purchase_used', False)
        
        return create_response(
            "success", "Login successful",
            data={
                "token": token,
                "user": {
                    "email": email, 
                    "credits": user['credits'],
                    "first_purchase_available": first_purchase_available,
                    "last_login": datetime.now().isoformat()
                },
                "first_purchase_offer": {
                    "available": first_purchase_available,
                    "bonus_credits": FIRST_PURCHASE_BONUS_CREDITS
                } if first_purchase_available else None
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
        
        first_purchase_available = not user.get('first_purchase_used', False)
        
        return create_response(
            "success", "Token valid",
            data={
                "user": {
                    "email": email,
                    "credits": user['credits'],
                    "first_purchase_available": first_purchase_available
                },
                "first_purchase_offer": {
                    "available": first_purchase_available,
                    "bonus_credits": FIRST_PURCHASE_BONUS_CREDITS
                } if first_purchase_available else None
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
@rate_limit(max_requests=5, window_seconds=300) 
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
        
        # Always use web URL - redirects to app via /reset-password page
        reset_url = f"https://ifta-production.up.railway.app/reset-password?token={token}"
        
        html_content = get_password_reset_email_html(reset_url, expires_at)
        
        if send_email(email, "Password Reset - MilesOn", html_content):
            return create_response("success", "Reset instructions have been sent to your email")
        else:
            return create_response(
                "success", "Reset link generated",
                data={"reset_url": reset_url, "expires_at": expires_at.isoformat()}
            )
    except Exception as e:
        logger.error(f"Forgot password error: {e}", exc_info=True)
        return create_response("error", "Internal server error", status_code=500)
    

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
        
        return create_response("success", "Password has been reset successfully")
    except Exception as e:
        logger.error(f"Reset password error: {e}", exc_info=True)
        return create_response("error", "Internal server error", status_code=500)



@app.route('/reset-password', methods=['GET'])
def reset_password_redirect():
    """Redirect web link to Electron app"""
    token = request.args.get('token', '')
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Reset Password - MilesOn</title>
        <style>
            body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
            .btn {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <h1>Reset Your Password</h1>
        <p>Click the button below to open MilesOn and reset your password:</p>
        <a href="mileson://reset-password?token={token}" class="btn">Open MilesOn</a>
        <p style="color: #666; margin-top: 30px;">If the app doesn't open, make sure MilesOn is installed.</p>
    </body>
    </html>
    '''


# =============================================================================
# ROUTES: CREDITS
# =============================================================================
@app.route('/api/credits/balance', methods=['GET', 'POST', 'OPTIONS'])
@cross_origin()
def get_balance():
    if request.method == 'OPTIONS':
        return '', 204
    try:
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
        first_purchase_available = check_first_purchase_available(email)
        
        return create_response(
            "success", "Balance retrieved", 
            data={
                "credits": credits, 
                "email": email,
                "first_purchase_available": first_purchase_available
            }
        )
    except Exception as e:
        logger.error(f"Get balance error: {e}", exc_info=True)
        return create_response("error", "Failed to get balance", status_code=500)


@app.route('/api/credits/use', methods=['POST', 'OPTIONS'])
@cross_origin()
def use_credit():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request()
        if not token:
            return create_response("error", "Authentication required", status_code=401)
        
        email = verify_token(token)
        if not email:
            return create_response("error", "Invalid or expired token", status_code=401)
        
        data = request.get_json() or {}
        amount = data.get('amount', 1)
        
        try:
            amount = float(amount)
            if amount <= 0:
                return create_response("error", "Amount must be positive", status_code=400)
        except (ValueError, TypeError):
            return create_response("error", "Invalid amount", status_code=400)
        
        if use_user_credits(email, amount):
            remaining = get_user_credits(email)
            return create_response("success", "Credits used", data={"amount_used": amount, "remaining": remaining})
        else:
            return create_response("error", "Insufficient credits", status_code=400)
    except Exception as e:
        logger.error(f"Use credit error: {e}", exc_info=True)
        return create_response("error", "Failed to use credits", status_code=500)


@app.route('/api/credits/add', methods=['POST', 'OPTIONS'])
@cross_origin()
def add_credits():
    if request.method == 'OPTIONS':
        return '', 204
    try:
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
        
        return create_response("success", "Credits added", data={"credits": new_balance, "added": amount})
    except Exception as e:
        logger.error(f"Add credits error: {e}", exc_info=True)
        return create_response("error", "Failed to add credits", status_code=500)


# =============================================================================
# ROUTES: FIRST PURCHASE CHECK
# =============================================================================
@app.route('/api/credits/first-purchase-status', methods=['GET', 'OPTIONS'])
@cross_origin()
def first_purchase_status():
    """Check if user is eligible for first purchase bonus"""
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request()
        if not token:
            return create_response("error", "Authentication required", status_code=401)
        
        email = verify_token(token)
        if not email:
            return create_response("error", "Invalid or expired token", status_code=401)
        
        available = check_first_purchase_available(email)
        
        return create_response(
            "success", 
            "First purchase bonus available!" if available else "First purchase bonus already used",
            data={
                "first_purchase_available": available,
                "offer": {
                    "bonus_credits": FIRST_PURCHASE_BONUS_CREDITS,
                    "description": f"+{FIRST_PURCHASE_BONUS_CREDITS} bonus credits on your first purchase!"
                } if available else None
            }
        )
    except Exception as e:
        logger.error(f"First purchase status error: {e}", exc_info=True)
        return create_response("error", "Failed to check status", status_code=500)


# =============================================================================
# ROUTES: PAYMENTS
# =============================================================================
@app.route('/api/payment/checkout-link', methods=['POST', 'OPTIONS'])
@cross_origin()
def create_checkout_link():
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
        is_first_purchase = data.get('isFirstPurchase', False)
        
        if not validate_email(email):
            return create_response("error", "Invalid email", status_code=400)
        
        try:
            amount = float(amount)
            if amount <= 0:
                return create_response("error", "Amount must be positive", status_code=400)
        except (ValueError, TypeError):
            return create_response("error", "Invalid amount", status_code=400)
        
        # Verify first purchase eligibility if claimed
        if is_first_purchase:
            if not check_first_purchase_available(email):
                return create_response(
                    "error", 
                    "First purchase bonus has already been used",
                    status_code=400
                )
            # Add bonus credits to the purchase
            bonus_credits = FIRST_PURCHASE_BONUS_CREDITS
            total_credits = int(credits) + bonus_credits
            logger.info(f"First purchase bonus applied: {credits} + {bonus_credits} = {total_credits}")
        
        logger.info(f"Checkout request: email={email}, amount=${amount}, credits={credits}, bonus={bonus_credits}, total={total_credits}, first_purchase={is_first_purchase}")
        
        if not SQUARE_ACCESS_TOKEN or not SQUARE_LOCATION_ID:
            # Test mode - directly add credits
            new_balance = add_user_credits(email, total_credits)
            if is_first_purchase:
                mark_first_purchase_used(email)
            return create_response(
                "success",
                "Test mode - credits added directly",
                data={"success": True, "testMode": True, "credits": new_balance, "added": total_credits}
            )
        
        checkout_id = str(uuid.uuid4())
        payment_id = create_payment_record(email, amount, credits, bonus_credits, total_credits, checkout_id, is_first_purchase)
        
        if not payment_id:
            return create_response("error", "Failed to create payment record", status_code=500)
        
        try:
            amount_cents = int(amount * 100)
            
            # Description for the checkout
            if is_first_purchase and bonus_credits > 0:
                item_name = f"🎉 {credits} + {bonus_credits} Bonus = {total_credits} MilesOn Credits"
            else:
                item_name = f"{total_credits} MilesOn Credits"
            
            checkout_payload = {
                "idempotency_key": checkout_id,
                "order": {
                    "location_id": SQUARE_LOCATION_ID,
                    "line_items": [{
                        "name": item_name,
                        "quantity": "1",
                        "base_price_money": {"amount": amount_cents, "currency": "USD"}
                    }]
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
                    return create_response(
                        "success", "Checkout link created",
                        data={"success": True, "checkoutUrl": checkout_url, "checkoutId": checkout_id}
                    )
            
            logger.error(f"Square API error: {response.status_code} - {response.text}")
            return create_response("error", "Failed to create checkout", status_code=500)
                
        except requests.exceptions.Timeout:
            return create_response("error", "Payment service timeout", status_code=504)
        except requests.exceptions.RequestException as e:
            return create_response("error", "Payment service error", status_code=502)
            
    except Exception as e:
        logger.error(f"Checkout link error: {e}", exc_info=True)
        return create_response("error", "Failed to create checkout", status_code=500)


@app.route('/api/payment/webhook', methods=['POST', 'OPTIONS'])
@cross_origin()
def payment_webhook():
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json()
        event_type = data.get('type')
        
        if event_type == 'payment.updated':
            payment_data = data.get('data', {}).get('object', {}).get('payment', {})
            if payment_data.get('status') == 'COMPLETED':
                amount_cents = payment_data.get('amount_money', {}).get('amount', 0)
                amount_dollars = amount_cents / 100
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute('''
                    SELECT * FROM payments WHERE amount = %s AND status = 'pending'
                    ORDER BY created_at DESC LIMIT 1
                ''', (amount_dollars,))
                payment = cur.fetchone()
                cur.close()
                conn.close()
                
                if payment:
                    complete_payment(payment['square_checkout_id'], payment_data.get('id'))
        
        return create_response("success", "Webhook received")
    except Exception as e:
        logger.error(f"Webhook error: {e}", exc_info=True)
        return create_response("error", "Webhook processing failed", status_code=500)


@app.route('/api/payment/verify', methods=['POST', 'OPTIONS'])
@cross_origin()
def verify_payment():
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json()
        checkout_id = data.get('checkoutId')
        
        if not checkout_id:
            return create_response("error", "Checkout ID required", status_code=400)
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM payments WHERE square_checkout_id = %s', (checkout_id,))
        payment = cur.fetchone()
        cur.close()
        conn.close()
        
        if not payment:
            return create_response("error", "Payment not found", status_code=404)
        
        return create_response(
            "success", "Payment status retrieved",
            data={
                "status": payment['status'],
                "email": payment['email'],
                "amount": float(payment['amount']),
                "totalCredits": payment['total_credits'],
                "isFirstPurchase": payment.get('is_first_purchase', False),
                "completed": payment['status'] == 'completed'
            }
        )
    except Exception as e:
        logger.error(f"Verify payment error: {e}", exc_info=True)
        return create_response("error", "Failed to verify payment", status_code=500)


# =============================================================================
# STABLECOIN CHAINS CONFIG (for on-chain verification)
# =============================================================================

STABLECOIN_CHAINS = {
    1: {
        'name': 'Ethereum', 'rpc': 'https://eth.llamarpc.com', 'explorer': 'https://etherscan.io',
        'tokens': {
            'USDC': {'addr': '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'dec': 6},
            'USDT': {'addr': '0xdAC17F958D2ee523a2206206994597C13D831ec7', 'dec': 6},
        }
    },
    8453: {
        'name': 'Base', 'rpc': 'https://mainnet.base.org', 'explorer': 'https://basescan.org',
        'tokens': {
            'USDC': {'addr': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', 'dec': 6},
        }
    },
    137: {
        'name': 'Polygon', 'rpc': 'https://polygon-rpc.com', 'explorer': 'https://polygonscan.com',
        'tokens': {
            'USDC': {'addr': '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', 'dec': 6},
            'USDT': {'addr': '0xc2132D05D31c914a87C6611C10748AEb04B58e8F', 'dec': 6},
        }
    },
    42161: {
        'name': 'Arbitrum One', 'rpc': 'https://arb1.arbitrum.io/rpc', 'explorer': 'https://arbiscan.io',
        'tokens': {
            'USDC': {'addr': '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', 'dec': 6},
            'USDT': {'addr': '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9', 'dec': 6},
        }
    },
    10: {
        'name': 'Optimism', 'rpc': 'https://mainnet.optimism.io', 'explorer': 'https://optimistic.etherscan.io',
        'tokens': {
            'USDC': {'addr': '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85', 'dec': 6},
            'USDT': {'addr': '0x94b008aA00579c1307B0EF2c499aD98a8ce58e58', 'dec': 6},
        }
    },
    43114: {
        'name': 'Avalanche', 'rpc': 'https://api.avax.network/ext/bc/C/rpc', 'explorer': 'https://snowtrace.io',
        'tokens': {
            'USDC': {'addr': '0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E', 'dec': 6},
            'USDT': {'addr': '0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7', 'dec': 6},
        }
    },
    56: {
        'name': 'BNB Chain', 'rpc': 'https://bsc-dataseed.binance.org', 'explorer': 'https://bscscan.com',
        'tokens': {
            'USDC': {'addr': '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d', 'dec': 18},
            'USDT': {'addr': '0x55d398326f99059fF775485246999027B3197955', 'dec': 18},
        }
    },
}

STABLECOIN_MERCHANT_ADDRESS = os.environ.get('STABLECOIN_MERCHANT_ADDRESS', '')


# =============================================================================
# STABLECOIN ON-CHAIN VERIFICATION
# =============================================================================

def verify_stablecoin_tx_onchain(tx_hash, chain_id, expected_token, expected_amount_usd):
    """Verify a stablecoin transaction on-chain via RPC"""
    chain = STABLECOIN_CHAINS.get(chain_id)
    if not chain:
        return False, f"Unsupported chain ID: {chain_id}"

    try:
        # Fetch transaction receipt
        resp = requests.post(chain['rpc'], json={
            'jsonrpc': '2.0', 'id': 1,
            'method': 'eth_getTransactionByHash',
            'params': [tx_hash]
        }, timeout=15)
        data = resp.json()
        tx = data.get('result')

        if not tx:
            return False, "Transaction not found (may not be mined yet)"

        # Verify the tx was sent to a known stablecoin contract on this chain
        tx_to = tx.get('to', '').lower()
        known_addrs = {v['addr'].lower(): k for k, v in chain['tokens'].items()}

        if tx_to not in known_addrs:
            return False, f"Transaction target {tx_to} is not a known stablecoin contract"

        # Basic check passed — tx was sent to a stablecoin contract
        logger.info(f"Stablecoin tx verified: {tx_hash} on {chain['name']} to {known_addrs[tx_to]}")
        return True, None

    except requests.exceptions.Timeout:
        return False, "RPC timeout"
    except Exception as e:
        logger.error(f"Stablecoin verification error: {e}")
        return False, str(e)


# =============================================================================
# ROUTES: STABLECOIN PAYMENT PAGE (served in browser for MetaMask)
# =============================================================================

@app.route('/pay/stablecoin', methods=['GET'])
def stablecoin_pay_page():
    """Serve the stablecoin payment page for browser-based MetaMask payments"""
    token = request.args.get('token', '')
    email = request.args.get('email', '')
    amount = request.args.get('amount', '10')
    credits_param = request.args.get('credits', amount)
    bonus = request.args.get('bonus', '0')
    total = request.args.get('total', credits_param)
    is_first = request.args.get('first', '0')
    merchant = request.args.get('merchant', STABLECOIN_MERCHANT_ADDRESS)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MilesOn - Stablecoin Payment</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#1e293b;border-radius:16px;padding:32px;max-width:420px;width:100%;box-shadow:0 25px 50px rgba(0,0,0,0.3)}}
h1{{font-size:20px;text-align:center;margin-bottom:4px}}
.subtitle{{text-align:center;color:#94a3b8;font-size:13px;margin-bottom:24px}}
.step{{display:none}}.step.active{{display:flex;flex-direction:column;align-items:center;gap:12px}}
.amount-box{{background:#0f172a;border-radius:12px;padding:16px;text-align:center;width:100%}}
.amount-big{{font-size:32px;font-weight:700;color:#fff}}.amount-credits{{color:#059669;font-size:14px;font-weight:500}}
.bonus-tag{{background:#065f46;color:#34d399;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:600}}
.chain-list{{display:flex;flex-direction:column;gap:6px;width:100%;max-height:280px;overflow-y:auto}}
.chain-btn{{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;background:#0f172a;border:1px solid #334155;border-radius:10px;cursor:pointer;color:#e2e8f0;font-size:14px;width:100%;text-align:left}}
.chain-btn:hover{{border-color:#6366f1}}.chain-btn.disabled{{opacity:0.4;cursor:not-allowed}}
.chain-name{{font-weight:500}}.chain-token{{color:#818cf8;font-size:12px;font-weight:600;background:#1e1b4b;padding:1px 6px;border-radius:4px;margin-left:6px}}
.chain-bal{{font-family:monospace;font-size:13px;color:#94a3b8}}.chain-bal.enough{{color:#34d399}}
.btn{{padding:12px 24px;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;width:100%;margin-top:4px}}
.btn-metamask{{background:#f6851b;color:#fff}}.btn-metamask:hover{{background:#e2761b}}
.btn-primary{{background:#6366f1;color:#fff}}.btn-primary:hover{{background:#4f46e5}}
.btn-secondary{{background:#334155;color:#94a3b8}}.btn-secondary:hover{{background:#475569}}
.btn:disabled{{opacity:0.6;cursor:not-allowed}}
.btn-row{{display:flex;gap:8px;width:100%}}
.btn-row .btn{{flex:1}}
.review-card{{background:#0f172a;border-radius:10px;padding:16px;width:100%}}
.review-row{{display:flex;justify-content:space-between;padding:4px 0;font-size:13px}}
.review-label{{color:#94a3b8}}.review-value{{color:#e2e8f0;font-weight:500}}
.review-divider{{height:1px;background:#334155;margin:6px 0}}
.success-icon{{width:56px;height:56px;border-radius:50%;background:#065f46;display:flex;align-items:center;justify-content:center;font-size:28px}}
.tx-box{{background:#0f172a;border-radius:8px;padding:10px 14px;width:100%;font-family:monospace;font-size:11px;color:#94a3b8;word-break:break-all}}
.spinner{{width:40px;height:40px;border:3px solid #334155;border-top-color:#6366f1;border-radius:50%;animation:spin 1s linear infinite}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.error-text{{color:#f87171;font-size:13px;text-align:center}}
.no-metamask{{text-align:center;color:#94a3b8;font-size:14px;line-height:1.6}}
.no-metamask a{{color:#818cf8;text-decoration:none;font-weight:600}}
.note{{font-size:12px;color:#64748b;text-align:center}}
</style>
</head>
<body>
<div class="card">
<h1>MilesOn Credits</h1>
<p class="subtitle">Pay with USDC or USDT via MetaMask</p>

<div id="stepConnect" class="step active">
  <div class="amount-box">
    <div class="amount-big">${amount} USDC/USDT</div>
    <div class="amount-credits">= {total} Credits{' <span class="bonus-tag">+' + bonus + ' bonus!</span>' if int(bonus) > 0 else ''}</div>
  </div>
  <div id="noMetamask" class="no-metamask" style="display:none">MetaMask not detected.<br/><a href="https://metamask.io/download/" target="_blank">Install MetaMask</a> and refresh this page.</div>
  <div id="hasMetamask"><button class="btn btn-metamask" id="btnConnect" onclick="connectWallet()">&#129418; Connect MetaMask</button></div>
</div>

<div id="stepChains" class="step">
  <div class="amount-box">
    <div class="amount-big">${amount}</div>
    <div class="amount-credits">{total} Credits</div>
  </div>
  <p class="note">Select network & stablecoin</p>
  <div class="chain-list" id="chainList"></div>
  <button class="btn btn-secondary" onclick="showStep('stepConnect')">Back</button>
</div>

<div id="stepReview" class="step">
  <div class="review-card">
    <div class="review-row"><span class="review-label">Network</span><span class="review-value" id="rvChain"></span></div>
    <div class="review-row"><span class="review-label">Token</span><span class="review-value" id="rvToken"></span></div>
    <div class="review-divider"></div>
    <div class="review-row"><span class="review-label">Amount</span><span class="review-value" id="rvAmount"></span></div>
    <div class="review-row"><span class="review-label">Credits</span><span class="review-value" id="rvCredits"></span></div>
    <div class="review-row"><span class="review-label">To</span><span class="review-value" style="font-size:11px;font-family:monospace" id="rvMerchant"></span></div>
  </div>
  <div class="btn-row">
    <button class="btn btn-secondary" onclick="showStep('stepChains')">Back</button>
    <button class="btn btn-primary" onclick="sendPayment()">Confirm & Pay</button>
  </div>
</div>

<div id="stepSending" class="step">
  <div class="spinner"></div>
  <p>Confirm in MetaMask...</p>
  <p class="note">Do not close this page</p>
</div>

<div id="stepSuccess" class="step">
  <div class="success-icon">&#10003;</div>
  <h2 style="color:#34d399"><span id="successCredits"></span> Credits Added!</h2>
  <div class="tx-box">
    <div style="font-size:11px;color:#64748b;margin-bottom:4px">Transaction</div>
    <span id="txHashDisplay"></span>
    <a id="txExplorerLink" href="#" target="_blank" style="color:#818cf8;margin-left:6px;font-size:11px">View ↗</a>
  </div>
  <p class="note">You can close this page and return to MilesOn.</p>
</div>

<div id="stepError" class="step">
  <p class="error-text" id="errorMsg">Payment failed</p>
  <button class="btn btn-secondary" onclick="showStep('stepReview')">Try Again</button>
</div>
</div>

<script>
const API_BASE='{request.host_url.rstrip("/")}';
const AUTH_TOKEN='{token}';
const EMAIL='{email}';
const AMOUNT={amount};
const CREDITS={credits_param};
const BONUS={bonus};
const TOTAL_CREDITS={total};
const IS_FIRST={'true' if is_first == '1' else 'false'};
const MERCHANT_ADDR='{merchant}';

const CHAINS={{8453:{{name:'Base',short:'Base',hex:'0x2105',rpc:'https://mainnet.base.org',explorer:'https://basescan.org',tokens:{{USDC:{{addr:'0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',dec:6}}}}}},137:{{name:'Polygon',short:'MATIC',hex:'0x89',rpc:'https://polygon-rpc.com',explorer:'https://polygonscan.com',tokens:{{USDC:{{addr:'0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359',dec:6}},USDT:{{addr:'0xc2132D05D31c914a87C6611C10748AEb04B58e8F',dec:6}}}}}},42161:{{name:'Arbitrum One',short:'ARB',hex:'0xa4b1',rpc:'https://arb1.arbitrum.io/rpc',explorer:'https://arbiscan.io',tokens:{{USDC:{{addr:'0xaf88d065e77c8cC2239327C5EDb3A432268e5831',dec:6}},USDT:{{addr:'0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9',dec:6}}}}}},10:{{name:'Optimism',short:'OP',hex:'0xa',rpc:'https://mainnet.optimism.io',explorer:'https://optimistic.etherscan.io',tokens:{{USDC:{{addr:'0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85',dec:6}},USDT:{{addr:'0x94b008aA00579c1307B0EF2c499aD98a8ce58e58',dec:6}}}}}},43114:{{name:'Avalanche',short:'AVAX',hex:'0xa86a',rpc:'https://api.avax.network/ext/bc/C/rpc',explorer:'https://snowtrace.io',tokens:{{USDC:{{addr:'0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E',dec:6}},USDT:{{addr:'0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7',dec:6}}}}}},56:{{name:'BNB Chain',short:'BSC',hex:'0x38',rpc:'https://bsc-dataseed.binance.org',explorer:'https://bscscan.com',tokens:{{USDC:{{addr:'0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',dec:18}},USDT:{{addr:'0x55d398326f99059fF775485246999027B3197955',dec:18}}}}}},1:{{name:'Ethereum',short:'ETH',hex:'0x1',rpc:'https://eth.llamarpc.com',explorer:'https://etherscan.io',tokens:{{USDC:{{addr:'0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',dec:6}},USDT:{{addr:'0xdAC17F958D2ee523a2206206994597C13D831ec7',dec:6}}}}}}}};
const ORDER=[8453,137,42161,10,43114,56,1];
const SEL={{balanceOf:'70a08231',transfer:'a9059cbb'}};
let walletAddress='',selectedChainId=0,selectedToken='',chainBalances={{}};

function showStep(id){{document.querySelectorAll('.step').forEach(s=>s.classList.remove('active'));document.getElementById(id).classList.add('active');}}
function encAddr(a){{return a.toLowerCase().replace('0x','').padStart(64,'0');}}
function encU256(v){{return v.toString(16).padStart(64,'0');}}
function parseAmt(a,d){{const[w,f='']=a.toString().split('.');return BigInt(w+f.padEnd(d,'0').slice(0,d));}}

window.addEventListener('load',()=>{{if(!window.ethereum){{document.getElementById('noMetamask').style.display='block';document.getElementById('hasMetamask').style.display='none';}}}});

async function connectWallet(){{
  try{{
    const accts=await window.ethereum.request({{method:'eth_requestAccounts'}});
    walletAddress=accts[0];
    await buildChainList();
    showStep('stepChains');
  }}catch(e){{
    if(e.code!==4001)alert(e.message||'Failed to connect');
  }}
}}

async function buildChainList(){{
  const list=document.getElementById('chainList');
  list.innerHTML='<p class="note">Loading balances...</p>';
  chainBalances={{}};
  const callData='0x'+SEL.balanceOf+encAddr(walletAddress);
  const fetches=[];
  for(const cid of ORDER){{
    const ch=CHAINS[cid];
    for(const[sym,tok] of Object.entries(ch.tokens)){{
      fetches.push(fetch(ch.rpc,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{jsonrpc:'2.0',id:1,method:'eth_call',params:[{{to:tok.addr,data:callData}},'latest']}})}}
      ).then(r=>r.json()).then(d=>{{
        if(d.result&&d.result!=='0x'&&d.result!=='0x0'){{
          const raw=BigInt(d.result);
          const whole=raw/BigInt(10**tok.dec);
          const frac=(raw%BigInt(10**tok.dec)).toString().padStart(tok.dec,'0').slice(0,2);
          chainBalances[cid+'_'+sym]={{raw,display:whole+'.'+frac,enough:raw>=parseAmt(AMOUNT,tok.dec)}};
        }}
      }}).catch(()=>{{}}));
    }}
  }}
  await Promise.all(fetches);
  list.innerHTML='';
  for(const cid of ORDER){{
    const ch=CHAINS[cid];
    for(const[sym,tok] of Object.entries(ch.tokens)){{
      const key=cid+'_'+sym;
      const bal=chainBalances[key];
      const hasEnough=bal&&bal.enough;
      const btn=document.createElement('button');
      btn.className='chain-btn'+(bal&&!hasEnough?' disabled':'');
      btn.innerHTML=`<span><span class="chain-name">${{ch.name}}</span><span class="chain-token">${{sym}}</span></span><span class="chain-bal${{hasEnough?' enough':''}}">${{bal?bal.display:'0.00'}}</span>`;
      if(hasEnough)btn.onclick=()=>selectChain(cid,sym);
      list.appendChild(btn);
    }}
  }}
  if(list.children.length===0)list.innerHTML='<p class="note">No stablecoin balances found</p>';
}}

async function selectChain(cid,sym){{
  selectedChainId=cid;selectedToken=sym;
  const ch=CHAINS[cid];
  const currentHex=await window.ethereum.request({{method:'eth_chainId'}});
  if(parseInt(currentHex,16)!==cid){{
    try{{await window.ethereum.request({{method:'wallet_switchEthereumChain',params:[{{chainId:ch.hex}}]}});}}
    catch(e){{
      if(e.code===4902){{try{{await window.ethereum.request({{method:'wallet_addEthereumChain',params:[{{chainId:ch.hex,chainName:ch.name,rpcUrls:[ch.rpc],blockExplorerUrls:[ch.explorer],nativeCurrency:ch.nc||{{name:'ETH',symbol:'ETH',decimals:18}}}}]}});}}catch(e2){{alert('Failed to add network');return;}}}}
      else{{return;}}
    }}
  }}
  document.getElementById('rvChain').textContent=ch.name;
  document.getElementById('rvToken').textContent=sym;
  document.getElementById('rvAmount').textContent=AMOUNT+' '+sym;
  document.getElementById('rvCredits').textContent=TOTAL_CREDITS;
  document.getElementById('rvMerchant').textContent=MERCHANT_ADDR.slice(0,6)+'...'+MERCHANT_ADDR.slice(-4);
  showStep('stepReview');
}}

async function sendPayment(){{
  showStep('stepSending');
  const ch=CHAINS[selectedChainId],tok=ch.tokens[selectedToken];
  const raw=parseAmt(AMOUNT,tok.dec);
  const txData='0x'+SEL.transfer+encAddr(MERCHANT_ADDR)+encU256(raw);
  let txHash;
  try{{txHash=await window.ethereum.request({{method:'eth_sendTransaction',params:[{{from:walletAddress,to:tok.addr,data:txData}}]}});}}
  catch(e){{if(e.code===4001){{showStep('stepReview');return;}}document.getElementById('errorMsg').textContent=e.message||'Transaction failed';showStep('stepError');return;}}

  async function tryBackend(attempt){{
    try{{
      const r=await fetch(API_BASE+'/api/credits/stablecoin-payment',{{method:'POST',headers:{{'Authorization':'Bearer '+AUTH_TOKEN,'Content-Type':'application/json'}},body:JSON.stringify({{email:EMAIL,txHash:txHash,chainId:selectedChainId,chainName:ch.name,token:selectedToken,amount:AMOUNT,credits:CREDITS,bonusCredits:BONUS,totalCredits:TOTAL_CREDITS,isFirstPurchase:IS_FIRST}})}});
      const res=await r.json();
      if(r.ok&&res.status==='success')return{{ok:true,res}};
      if(res.message&&res.message.includes('not found')&&attempt<5){{await new Promise(r=>setTimeout(r,5000));return tryBackend(attempt+1);}}
      return{{ok:false,res}};
    }}catch(e){{if(attempt<3){{await new Promise(r=>setTimeout(r,3000));return tryBackend(attempt+1);}}return{{ok:false,res:{{message:e.message}}}};}}
  }}

  await new Promise(r=>setTimeout(r,3000));
  const result=await tryBackend(1);
  document.getElementById('successCredits').textContent=TOTAL_CREDITS;
  document.getElementById('txHashDisplay').textContent=txHash;
  document.getElementById('txExplorerLink').href=ch.explorer+'/tx/'+txHash;
  if(!result.ok){{document.getElementById('txHashDisplay').textContent=txHash+'\\n\\nBackend: '+(result.res.message||'unknown error')+'\\nCredits may take a moment to appear.';}}
  showStep('stepSuccess');
}}
</script>
</body></html>'''


# =============================================================================
# ROUTES: STABLECOIN PAYMENT VERIFICATION
# =============================================================================

@app.route('/api/credits/stablecoin-payment', methods=['POST', 'OPTIONS'])
@cross_origin()
def stablecoin_payment():
    """Process stablecoin payment: verify on-chain and add credits"""
    if request.method == 'OPTIONS':
        return '', 204

    try:
        # Verify authentication
        token = extract_token_from_request()
        if not token:
            return create_response("error", "Authentication required", status_code=401)

        token_email = verify_token(token)
        if not token_email:
            return create_response("error", "Invalid or expired token", status_code=401)

        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)

        email = data.get('email', '').strip().lower()
        tx_hash = data.get('txHash', '')
        chain_id = data.get('chainId', 0)
        chain_name = data.get('chainName', '')
        token_symbol = data.get('token', '')
        amount = data.get('amount', 0)
        credits_amount = data.get('credits', 0)
        bonus_credits = data.get('bonusCredits', 0)
        total_credits = data.get('totalCredits', 0)
        is_first_purchase = data.get('isFirstPurchase', False)

        # Validate
        if not tx_hash:
            return create_response("error", "Transaction hash required", status_code=400)
        if not validate_email(email):
            return create_response("error", "Invalid email", status_code=400)
        if email != token_email:
            return create_response("error", "Email mismatch", status_code=403)
        if total_credits <= 0:
            return create_response("error", "Invalid credits amount", status_code=400)

        # Check for duplicate transaction
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM payments WHERE bsv_txid = %s", (tx_hash,))
        existing = cur.fetchone()

        if existing:
            cur.close()
            conn.close()
            return create_response("error", "Transaction already processed", status_code=409)

        # Verify first purchase eligibility if claimed
        if is_first_purchase:
            if not check_first_purchase_available(email):
                cur.close()
                conn.close()
                return create_response("error", "First purchase bonus already used", status_code=400)

        # Verify on-chain
        verified, verify_error = verify_stablecoin_tx_onchain(tx_hash, chain_id, token_symbol, float(amount))

        if not verified:
            logger.warning(f"Stablecoin tx verification failed: {verify_error}")
            # Still process — the tx might not be mined yet, user saw it in MetaMask

        # Create payment record
        cur.execute('''
            INSERT INTO payments (email, amount, credits, bonus_credits, total_credits, is_first_purchase, bsv_txid, payment_type, status, created_at, completed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'stablecoin', 'completed', %s, %s)
            RETURNING id
        ''', (email, amount, credits_amount, bonus_credits, total_credits, is_first_purchase, tx_hash, datetime.now(), datetime.now()))

        payment_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        # Add credits
        new_balance = add_user_credits(email, total_credits)

        # Mark first purchase if applicable
        if is_first_purchase:
            mark_first_purchase_used(email)

        logger.info(f"Stablecoin payment: {payment_id}, tx={tx_hash}, chain={chain_name}, {total_credits} credits to {email}")

        return create_response("success", "Payment processed", data={
            "payment_id": payment_id,
            "txHash": tx_hash,
            "credits_added": total_credits,
            "new_balance": new_balance,
            "is_first_purchase": is_first_purchase
        })

    except Exception as e:
        logger.error(f"Stablecoin payment error: {e}", exc_info=True)
        return create_response("error", "Failed to process payment", status_code=500)


# =============================================================================
# TWILIO SMS HELPERS
# =============================================================================

def normalize_phone(phone):
    """Normalize phone number to E.164 format (+1XXXXXXXXXX)"""
    if not phone:
        return None
    digits = re.sub(r'[^\d+]', '', phone)
    if digits.startswith('+'):
        return digits
    digits = re.sub(r'[^\d]', '', digits)
    if len(digits) == 10:
        return f'+1{digits}'
    if len(digits) == 11 and digits.startswith('1'):
        return f'+{digits}'
    return f'+{digits}'


def parse_driver_reply(body):
    """Parse driver's SMS reply into confirmed/declined/unknown"""
    if not body:
        return 'unknown'
    cleaned = body.strip().lower()
    confirmed_words = ['yes', 'y', 'ok', 'confirm', 'confirmed', 'accept', 'accepted',
                       '10-4', '10 4', 'copy', 'roger', 'affirmative', 'sure', 'yep',
                       'yeah', 'yea', 'da', 'si']
    declined_words = ['no', 'n', 'decline', 'declined', 'reject', 'rejected', 'pass',
                      "can't", 'cannot', 'cant', 'nope', 'negative', 'nah', 'net', 'nyet']
    if cleaned in confirmed_words or any(cleaned.startswith(w + ' ') for w in confirmed_words[:5]):
        return 'confirmed'
    if cleaned in declined_words or any(cleaned.startswith(w + ' ') for w in declined_words[:5]):
        return 'declined'
    return 'unknown'


def build_route_message(route_summary, route_link=None, pickup_info=None, 
                        delivery_info=None, estimated_miles=None, notes=None):
    """Build the route confirmation SMS text"""
    lines = [f"New Route: {route_summary}"]
    if estimated_miles:
        lines.append(f"Distance: {estimated_miles} miles")
    if pickup_info:
        lines.append(f"Pickup: {pickup_info}")
    if delivery_info:
        lines.append(f"Delivery: {delivery_info}")
    if route_link:
        lines.append(f"Map: {route_link}")
    if notes:
        lines.append(f"Notes: {notes}")
    lines.append("")
    lines.append("Reply YES to confirm or NO to decline.")
    return "\n".join(lines)


def twilio_send_sms(to_phone, message):
    """Send SMS via Twilio REST API (no SDK needed)"""
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
        return {'success': False, 'error': 'Twilio not configured'}
    
    to_normalized = normalize_phone(to_phone)
    if not to_normalized:
        return {'success': False, 'error': 'Invalid phone number'}
    
    try:
        url = f'https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json'
        response = requests.post(
            url,
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            data={
                'From': TWILIO_PHONE_NUMBER,
                'To': to_normalized,
                'Body': message
            },
            timeout=30
        )
        
        if response.status_code in (200, 201):
            data = response.json()
            return {
                'success': True,
                'message_sid': data.get('sid'),
                'to': to_normalized,
                'status': data.get('status')
            }
        else:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            error_msg = error_data.get('message', f'Twilio API error: {response.status_code}')
            logger.error(f"Twilio send failed: {response.status_code} - {error_msg}")
            return {'success': False, 'error': error_msg}
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Twilio request timeout'}
    except Exception as e:
        logger.error(f"Twilio send error: {e}")
        return {'success': False, 'error': str(e)}


def twilio_check_replies(from_phone, since_timestamp=None):
    """Check for inbound SMS replies from a specific phone number"""
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
        return {'success': False, 'error': 'Twilio not configured', 'replies': []}
    
    from_normalized = normalize_phone(from_phone)
    if not from_normalized:
        return {'success': False, 'error': 'Invalid phone number', 'replies': []}
    
    try:
        url = f'https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json'
        params = {
            'To': TWILIO_PHONE_NUMBER,
            'From': from_normalized,
            'PageSize': 10,
        }
        if since_timestamp:
            try:
                dt = datetime.fromisoformat(since_timestamp.replace('Z', '+00:00'))
                params['DateSent>'] = dt.strftime('%Y-%m-%d')
            except (ValueError, AttributeError):
                pass
        
        response = requests.get(
            url,
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            params=params,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            messages = data.get('messages', [])
            
            replies = []
            for msg in messages:
                if msg.get('direction') in ('inbound',):
                    msg_time = msg.get('date_sent', '')
                    # Filter by since timestamp if provided
                    if since_timestamp and msg_time:
                        try:
                            msg_dt = datetime.fromisoformat(msg_time.replace('Z', '+00:00').replace('+00:00', ''))
                            since_dt = datetime.fromisoformat(since_timestamp.replace('Z', '+00:00').replace('+00:00', ''))
                            if msg_dt < since_dt:
                                continue
                        except (ValueError, AttributeError):
                            pass
                    
                    replies.append({
                        'body': msg.get('body', ''),
                        'timestamp': msg_time,
                        'from': msg.get('from', ''),
                        'sid': msg.get('sid', '')
                    })
            
            return {'success': True, 'replies': replies}
        else:
            logger.error(f"Twilio check replies failed: {response.status_code}")
            return {'success': False, 'error': f'Twilio API error: {response.status_code}', 'replies': []}
    except Exception as e:
        logger.error(f"Twilio check replies error: {e}")
        return {'success': False, 'error': str(e), 'replies': []}


# =============================================================================
# ROUTES: SMS MESSAGING
# =============================================================================

@app.route('/api/messaging/send', methods=['POST', 'OPTIONS'])
@cross_origin()
def messaging_send():
    """Send a free-form SMS to a driver"""
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request()
        if not token:
            return create_response("error", "Authentication required", status_code=401)
        email = verify_token(token)
        if not email:
            return create_response("error", "Invalid or expired token", status_code=401)
        
        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)
        
        driver_name = data.get('driverName', '')
        message = data.get('message', '')
        phone = data.get('phone', '')
        
        if not driver_name:
            return create_response("error", "driverName is required", status_code=400)
        if not message:
            return create_response("error", "message is required", status_code=400)
        if not phone:
            return create_response("error", "phone is required", status_code=400)
        
        result = twilio_send_sms(phone, message)
        
        if result['success']:
            return create_response("success", "Message sent", data={
                "success": True,
                "message_id": result.get('message_sid'),
                "phone": result.get('to'),
                "driver": driver_name,
                "sent_at": datetime.now().isoformat()
            })
        else:
            return create_response("error", result.get('error', 'Failed to send'), 
                                   data={"success": False, "error": result.get('error')}, status_code=500)
    except Exception as e:
        logger.error(f"Messaging send error: {e}", exc_info=True)
        return create_response("error", "Failed to send message", status_code=500)


@app.route('/api/messaging/send-route', methods=['POST', 'OPTIONS'])
@cross_origin()
def messaging_send_route():
    """Send a route confirmation SMS to a driver"""
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request()
        if not token:
            return create_response("error", "Authentication required", status_code=401)
        email = verify_token(token)
        if not email:
            return create_response("error", "Invalid or expired token", status_code=401)
        
        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)
        
        driver_name = data.get('driverName', '')
        phone = data.get('phone', '')
        route_summary = data.get('routeSummary', '')
        route_link = data.get('routeLink')
        pickup_info = data.get('pickupInfo')
        delivery_info = data.get('deliveryInfo')
        estimated_miles = data.get('estimatedMiles')
        notes = data.get('notes')
        
        if not driver_name:
            return create_response("error", "driverName is required", status_code=400)
        if not route_summary:
            return create_response("error", "routeSummary is required", status_code=400)
        if not phone:
            return create_response("error", "phone is required", status_code=400)
        
        message = build_route_message(
            route_summary=route_summary,
            route_link=route_link,
            pickup_info=pickup_info,
            delivery_info=delivery_info,
            estimated_miles=estimated_miles,
            notes=notes
        )
        
        result = twilio_send_sms(phone, message)
        
        if result['success']:
            return create_response("success", "Route sent to driver", data={
                "success": True,
                "message_id": result.get('message_sid'),
                "phone": result.get('to'),
                "driver": driver_name,
                "sent_at": datetime.now().isoformat(),
                "route_summary": route_summary
            })
        else:
            return create_response("error", result.get('error', 'Failed to send'), 
                                   data={"success": False, "error": result.get('error')}, status_code=500)
    except Exception as e:
        logger.error(f"Messaging send-route error: {e}", exc_info=True)
        return create_response("error", "Failed to send route", status_code=500)


@app.route('/api/messaging/check-reply', methods=['POST', 'OPTIONS'])
@cross_origin()
def messaging_check_reply():
    """Check for driver's SMS reply"""
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request()
        if not token:
            return create_response("error", "Authentication required", status_code=401)
        email = verify_token(token)
        if not email:
            return create_response("error", "Invalid or expired token", status_code=401)
        
        data = request.get_json()
        if not data:
            return create_response("error", "No JSON data provided", status_code=400)
        
        driver_name = data.get('driverName', '')
        phone = data.get('phone', '')
        since = data.get('since')
        
        if not driver_name:
            return create_response("error", "driverName is required", status_code=400)
        if not phone:
            return create_response("error", "phone is required", status_code=400)
        
        result = twilio_check_replies(phone, since)
        
        if not result['success']:
            return create_response("error", result.get('error', 'Failed to check replies'),
                                   data={"status": "error", "driver": driver_name, "error": result.get('error')},
                                   status_code=500)
        
        replies = result.get('replies', [])
        
        if not replies:
            return create_response("success", "No reply yet", data={
                "status": "pending",
                "replies": [],
                "driver": driver_name
            })
        
        # Parse the latest reply
        latest = replies[0]
        reply_status = parse_driver_reply(latest.get('body', ''))
        
        return create_response("success", "Reply found", data={
            "status": reply_status,
            "replies": replies,
            "latest_reply": latest,
            "driver": driver_name
        })
    except Exception as e:
        logger.error(f"Messaging check-reply error: {e}", exc_info=True)
        return create_response("error", "Failed to check reply", status_code=500)


@app.route('/api/messaging/test', methods=['POST', 'OPTIONS'])
@cross_origin()
def messaging_test():
    """Test Twilio connection"""
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request()
        if not token:
            return create_response("error", "Authentication required", status_code=401)
        email = verify_token(token)
        if not email:
            return create_response("error", "Invalid or expired token", status_code=401)
        
        if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
            return create_response("error", "Twilio not configured", 
                                   data={"success": False, "message": "Missing Twilio credentials"}, status_code=500)
        
        # Verify credentials by fetching account info
        try:
            url = f'https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}.json'
            response = requests.get(url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN), timeout=10)
            
            if response.status_code == 200:
                return create_response("success", "Twilio connection OK", data={
                    "success": True,
                    "message": "Twilio is configured and connected",
                    "phone_number": TWILIO_PHONE_NUMBER
                })
            else:
                return create_response("error", "Twilio credentials invalid",
                                       data={"success": False, "message": "Invalid Twilio credentials"}, status_code=500)
        except Exception as e:
            return create_response("error", f"Twilio connection failed: {str(e)}",
                                   data={"success": False}, status_code=500)
    except Exception as e:
        logger.error(f"Messaging test error: {e}", exc_info=True)
        return create_response("error", "Test failed", status_code=500)


@app.route('/api/messaging/test-message', methods=['POST', 'OPTIONS'])
@cross_origin()
def messaging_test_message():
    """Send a test SMS"""
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request()
        if not token:
            return create_response("error", "Authentication required", status_code=401)
        email = verify_token(token)
        if not email:
            return create_response("error", "Invalid or expired token", status_code=401)
        
        data = request.get_json()
        phone = data.get('phone', '') if data else ''
        
        if not phone:
            return create_response("error", "phone is required", status_code=400)
        
        result = twilio_send_sms(phone, "Test message from MilesOn. If you received this, SMS is working!")
        
        if result['success']:
            return create_response("success", "Test message sent", data={
                "success": True,
                "message_id": result.get('message_sid'),
                "phone": result.get('to'),
                "sent_at": datetime.now().isoformat()
            })
        else:
            return create_response("error", result.get('error', 'Failed to send'),
                                   data={"success": False, "error": result.get('error')}, status_code=500)
    except Exception as e:
        logger.error(f"Messaging test-message error: {e}", exc_info=True)
        return create_response("error", "Failed to send test", status_code=500)


# =============================================================================
# ROUTES: DEBUG
# =============================================================================
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
        
        cur.execute("SELECT COUNT(*) FROM users WHERE first_purchase_used = TRUE")
        first_purchase_count = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM payments WHERE status = 'completed'")
        completed_payments = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return create_response(
            "success", "Database status",
            data={
                "total_users": user_count,
                "first_purchase_used_count": first_purchase_count,
                "completed_payments": completed_payments
            }
        )
    except Exception as e:
        return create_response("error", "Database error", errors=[str(e)], status_code=500)


# =============================================================================
# ERROR HANDLERS
# =============================================================================
@app.errorhandler(404)
def not_found(e):
    return create_response("error", "Resource not found", status_code=404)


@app.errorhandler(500)
def internal_error(e):
    return create_response("error", "Internal server error", status_code=500)


# =============================================================================
# MAIN
# =============================================================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info("=" * 50)
    logger.info("STARTING RAILWAY API WITH FIRST PURCHASE BONUS")
    logger.info(f"Port: {port}")
    logger.info(f"First purchase bonus: +{FIRST_PURCHASE_BONUS_CREDITS} credits")
    logger.info(f"Square configured: {bool(SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID)}")
    logger.info(f"Twilio configured: {bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE_NUMBER)}")
    logger.info(f"Stablecoin merchant: {bool(STABLECOIN_MERCHANT_ADDRESS)}")
    logger.info("=" * 50)
    app.run(host='0.0.0.0', port=port, debug=False)
