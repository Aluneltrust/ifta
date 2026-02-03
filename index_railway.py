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
# ROUTES: STABLECOIN PAYMENTS (Browser-based)
# =============================================================================
# Add this section to index_railway.py after the BSV payment route.
# Also add STABLECOIN_MERCHANT_ADDRESS and STABLECOIN_* constants near
# the other CONSTANTS at the top of the file.
# =============================================================================

# ---- Add these constants near the top with the other constants ----

# STABLECOIN_MERCHANT_ADDRESS = os.environ.get('STABLECOIN_MERCHANT_ADDRESS', '').lower()
#
# STABLECOIN_CHAIN_RPCS = {
#     1:     'https://eth.llamarpc.com',
#     8453:  'https://mainnet.base.org',
#     137:   'https://polygon-rpc.com',
#     42161: 'https://arb1.arbitrum.io/rpc',
#     10:    'https://mainnet.optimism.io',
#     43114: 'https://api.avax.network/ext/bc/C/rpc',
#     56:    'https://bsc-dataseed.binance.org',
# }
#
# STABLECOIN_CONTRACTS = {
#     1:     {'0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', '0xdac17f958d2ee523a2206206994597c13d831ec7'},
#     8453:  {'0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'},
#     137:   {'0x3c499c542cef5e3811e1192ce70d8cc03d5c3359', '0xc2132d05d31c914a87c6611c10748aeb04b58e8f'},
#     42161: {'0xaf88d065e77c8cc2239327c5edb3a432268e5831', '0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9'},
#     10:    {'0x0b2c639c533813f4aa9d7837caf62653d097ff85', '0x94b008aa00579c1307b0ef2c499ad98a8ce58e58'},
#     43114: {'0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e', '0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7'},
#     56:    {'0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d', '0x55d398326f99059ff775485246999027b3197955'},
# }

# ---- Routes below ----


STABLECOIN_PAY_PAGE = r'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MilesOn — Stablecoin Payment</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      padding: 20px; color: #e2e8f0;
    }
    .card {
      background: #1e293b; border: 1px solid #334155; border-radius: 16px;
      width: 100%; max-width: 460px; overflow: hidden;
      box-shadow: 0 20px 60px rgba(0,0,0,0.4);
    }
    .header {
      background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
      padding: 24px; text-align: center;
    }
    .header h1 { font-size: 20px; font-weight: 700; color: #fff; margin-bottom: 4px; }
    .header p { font-size: 13px; color: rgba(255,255,255,0.8); }
    .body { padding: 24px; }
    .amount-box {
      background: #0f172a; border: 1px solid #334155; border-radius: 12px;
      padding: 20px; text-align: center; margin-bottom: 20px;
    }
    .amount-label { font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
    .amount-value { font-size: 36px; font-weight: 700; color: #fff; margin: 4px 0; }
    .amount-credits { font-size: 14px; color: #22c55e; font-weight: 500; }
    .amount-bonus { color: #f59e0b; }
    .step { display: none; } .step.active { display: block; }
    .step-title { font-size: 16px; font-weight: 600; color: #f1f5f9; margin-bottom: 12px; }
    .no-metamask {
      background: #7f1d1d22; border: 1px solid #991b1b; border-radius: 10px;
      padding: 16px; text-align: center; color: #fca5a5; font-size: 14px;
    }
    .no-metamask a { color: #818cf8; text-decoration: none; font-weight: 600; }
    .btn {
      display: flex; align-items: center; justify-content: center; gap: 8px;
      width: 100%; padding: 14px; border: none; border-radius: 10px;
      font-size: 15px; font-weight: 600; cursor: pointer; transition: opacity 0.15s;
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn:hover:not(:disabled) { opacity: 0.9; }
    .btn-metamask { background: #f6851b; color: #fff; }
    .btn-primary { background: #6366f1; color: #fff; }
    .btn-secondary { background: #334155; color: #e2e8f0; }
    .btn-success { background: #059669; color: #fff; }
    .wallet-badge {
      display: flex; align-items: center; gap: 8px;
      background: #0f172a; border: 1px solid #334155; border-radius: 8px;
      padding: 10px 14px; margin-bottom: 16px;
      font-family: monospace; font-size: 13px; color: #94a3b8;
    }
    .wallet-dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; }
    .chain-list { display: flex; flex-direction: column; gap: 6px; max-height: 280px; overflow-y: auto; margin-bottom: 12px; }
    .chain-option {
      display: flex; align-items: center; justify-content: space-between;
      padding: 12px 14px; background: #0f172a; border: 1px solid #334155;
      border-radius: 10px; cursor: pointer; transition: border-color 0.15s; color: #e2e8f0;
    }
    .chain-option:hover { border-color: #6366f1; }
    .chain-option.disabled { opacity: 0.4; cursor: not-allowed; }
    .chain-name { font-size: 14px; font-weight: 500; }
    .token-badge { font-size: 11px; color: #818cf8; background: #312e81; padding: 2px 6px; border-radius: 4px; font-weight: 600; margin-left: 8px; }
    .chain-balance { font-size: 13px; font-family: monospace; color: #94a3b8; }
    .chain-balance.enough { color: #22c55e; }
    .chain-hint { font-size: 12px; color: #64748b; text-align: center; }
    .review-card { background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
    .review-row { display: flex; justify-content: space-between; padding: 6px 0; font-size: 14px; }
    .review-label { color: #94a3b8; } .review-value { color: #f1f5f9; font-weight: 500; }
    .review-divider { height: 1px; background: #334155; margin: 6px 0; }
    .review-buttons { display: flex; gap: 10px; } .review-buttons .btn { flex: 1; }
    .review-note { font-size: 12px; color: #64748b; text-align: center; margin-bottom: 12px; }
    .sending-box { text-align: center; padding: 30px 0; }
    .spinner { width: 48px; height: 48px; border: 3px solid #334155; border-top-color: #6366f1; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 16px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .success-box { text-align: center; padding: 20px 0; }
    .success-icon { width: 56px; height: 56px; border-radius: 50%; background: #064e3b; display: flex; align-items: center; justify-content: center; margin: 0 auto 12px; font-size: 28px; color: #22c55e; }
    .tx-hash-box { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 10px 14px; margin: 12px 0; font-family: monospace; font-size: 12px; color: #94a3b8; word-break: break-all; }
    .tx-hash-box a { color: #818cf8; text-decoration: none; }
    .close-msg { font-size: 13px; color: #64748b; margin-top: 12px; }
    .error-box { text-align: center; padding: 20px 0; }
    .error-icon { font-size: 48px; margin-bottom: 12px; color: #f87171; }
    .error-msg { background: #7f1d1d22; border: 1px solid #991b1b; border-radius: 8px; padding: 10px 14px; color: #fca5a5; font-size: 13px; margin: 12px 0; word-break: break-word; }
  </style>
</head>
<body>
<div class="card">
  <div class="header"><h1>MilesOn Payment</h1><p>Pay with USDC or USDT via MetaMask</p></div>
  <div class="body">
    <div class="amount-box">
      <div class="amount-label">Amount to Pay</div>
      <div class="amount-value" id="displayAmount">$0.00</div>
      <div class="amount-credits"><span id="displayCredits">0</span> credits<span id="displayBonus" class="amount-bonus" style="display:none"> + <span id="bonusNum">0</span> bonus</span></div>
    </div>
    <div class="step active" id="stepConnect">
      <div id="noMetamask" class="no-metamask" style="display:none">MetaMask not detected.<br/><a href="https://metamask.io/download/" target="_blank">Install MetaMask</a> and refresh this page.</div>
      <div id="hasMetamask"><button class="btn btn-metamask" id="btnConnect" onclick="connectWallet()">&#129418; Connect MetaMask</button></div>
    </div>
    <div class="step" id="stepChain">
      <div class="wallet-badge"><div class="wallet-dot"></div><span id="walletAddr">0x...</span></div>
      <p class="step-title">Select network & stablecoin</p>
      <div class="chain-list" id="chainList"></div>
      <p class="chain-hint">&#128161; Base & Polygon have the lowest fees</p>
    </div>
    <div class="step" id="stepReview">
      <p class="step-title">Confirm Payment</p>
      <div class="review-card">
        <div class="review-row"><span class="review-label">Network</span><span class="review-value" id="reviewChain">-</span></div>
        <div class="review-row"><span class="review-label">Token</span><span class="review-value" id="reviewToken">-</span></div>
        <div class="review-row"><span class="review-label">Amount</span><span class="review-value" id="reviewAmount">-</span></div>
        <div class="review-divider"></div>
        <div class="review-row"><span class="review-label">Credits</span><span class="review-value" id="reviewCredits">-</span></div>
      </div>
      <p class="review-note">MetaMask will ask you to confirm. Gas fees apply.</p>
      <div class="review-buttons">
        <button class="btn btn-secondary" onclick="showStep('stepChain')">Back</button>
        <button class="btn btn-primary" id="btnPay" onclick="sendPayment()">Pay <span id="btnPayAmount">0.00</span> <span id="btnPayToken">USDC</span></button>
      </div>
    </div>
    <div class="step" id="stepSending"><div class="sending-box"><div class="spinner"></div><p class="step-title">Confirm in MetaMask</p><p style="color:#94a3b8;font-size:14px;">Approve the transaction in your MetaMask extension</p></div></div>
    <div class="step" id="stepSuccess"><div class="success-box"><div class="success-icon">&#10003;</div><p class="step-title" style="color:#22c55e;">Payment Complete!</p><p style="color:#94a3b8;font-size:14px;"><strong id="successCredits">0</strong> credits have been added to your account.</p><div class="tx-hash-box"><span id="txHashDisplay">-</span><br/><a id="txExplorerLink" href="#" target="_blank">View on block explorer &rarr;</a></div><p class="close-msg">You can close this tab and return to MilesOn.</p><button class="btn btn-success" style="margin-top:12px;" onclick="window.close()">Done - Close Tab</button></div></div>
    <div class="step" id="stepError"><div class="error-box"><div class="error-icon">&#10007;</div><p class="step-title" style="color:#f87171;">Payment Failed</p><div class="error-msg" id="errorMsg">Something went wrong.</div><div class="review-buttons" style="margin-top:16px;"><button class="btn btn-secondary" onclick="window.close()">Close</button><button class="btn btn-primary" onclick="showStep('stepChain')">Try Again</button></div></div></div>
  </div>
</div>
<script>
const CHAINS={8453:{name:'Base',short:'Base',hex:'0x2105',rpc:'https://mainnet.base.org',explorer:'https://basescan.org',nc:{name:'Ether',symbol:'ETH',decimals:18},tokens:{USDC:{addr:'0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',dec:6}}},137:{name:'Polygon',short:'MATIC',hex:'0x89',rpc:'https://polygon-rpc.com',explorer:'https://polygonscan.com',nc:{name:'POL',symbol:'POL',decimals:18},tokens:{USDC:{addr:'0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359',dec:6},USDT:{addr:'0xc2132D05D31c914a87C6611C10748AEb04B58e8F',dec:6}}},42161:{name:'Arbitrum One',short:'ARB',hex:'0xa4b1',rpc:'https://arb1.arbitrum.io/rpc',explorer:'https://arbiscan.io',nc:{name:'Ether',symbol:'ETH',decimals:18},tokens:{USDC:{addr:'0xaf88d065e77c8cC2239327C5EDb3A432268e5831',dec:6},USDT:{addr:'0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9',dec:6}}},10:{name:'Optimism',short:'OP',hex:'0xa',rpc:'https://mainnet.optimism.io',explorer:'https://optimistic.etherscan.io',nc:{name:'Ether',symbol:'ETH',decimals:18},tokens:{USDC:{addr:'0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85',dec:6},USDT:{addr:'0x94b008aA00579c1307B0EF2c499aD98a8ce58e58',dec:6}}},43114:{name:'Avalanche',short:'AVAX',hex:'0xa86a',rpc:'https://api.avax.network/ext/bc/C/rpc',explorer:'https://snowtrace.io',nc:{name:'Avalanche',symbol:'AVAX',decimals:18},tokens:{USDC:{addr:'0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E',dec:6},USDT:{addr:'0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7',dec:6}}},56:{name:'BNB Chain',short:'BSC',hex:'0x38',rpc:'https://bsc-dataseed.binance.org',explorer:'https://bscscan.com',nc:{name:'BNB',symbol:'BNB',decimals:18},tokens:{USDC:{addr:'0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',dec:18},USDT:{addr:'0x55d398326f99059fF775485246999027B3197955',dec:18}}},1:{name:'Ethereum',short:'ETH',hex:'0x1',rpc:'https://eth.llamarpc.com',explorer:'https://etherscan.io',nc:{name:'Ether',symbol:'ETH',decimals:18},tokens:{USDC:{addr:'0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',dec:6},USDT:{addr:'0xdAC17F958D2ee523a2206206994597C13D831ec7',dec:6}}}};
const CHAIN_ORDER=[8453,137,42161,10,43114,56,1];
const SEL={balanceOf:'70a08231',transfer:'a9059cbb'};
const params=new URLSearchParams(window.location.search);
const AUTH_TOKEN=params.get('token')||'',EMAIL=params.get('email')||'',AMOUNT=parseFloat(params.get('amount')||'0'),CREDITS=parseInt(params.get('credits')||'0',10),BONUS=parseInt(params.get('bonus')||'0',10),TOTAL_CREDITS=parseInt(params.get('total')||'0',10)||(CREDITS+BONUS),IS_FIRST=params.get('first')==='1',MERCHANT_ADDR=params.get('merchant')||'',API_BASE=window.location.origin;
document.getElementById('displayAmount').textContent='$'+AMOUNT.toFixed(2);
document.getElementById('displayCredits').textContent=TOTAL_CREDITS;
if(BONUS>0){document.getElementById('displayBonus').style.display='inline';document.getElementById('bonusNum').textContent=BONUS;}
let walletAddress=null,selectedChainId=null,selectedToken=null,balances={};
function encAddr(a){return a.toLowerCase().replace('0x','').padStart(64,'0');}
function encU256(v){return BigInt(v).toString(16).padStart(64,'0');}
function parseAmt(a,d){const[w,f='']=a.toString().split('.');return BigInt(w+f.padEnd(d,'0').slice(0,d));}
function fmtAmt(r,d){if(r===0n)return'0.00';const dv=BigInt(10**d);return(r/dv)+'.'+(r%dv).toString().padStart(d,'0').slice(0,2);}
function showStep(id){document.querySelectorAll('.step').forEach(s=>s.classList.remove('active'));document.getElementById(id).classList.add('active');}
async function connectWallet(){const b=document.getElementById('btnConnect');b.disabled=true;b.textContent='Connecting...';try{const acc=await window.ethereum.request({method:'eth_requestAccounts'});if(!acc||!acc.length)throw new Error('No accounts');walletAddress=acc[0];document.getElementById('walletAddr').textContent=walletAddress.slice(0,6)+'...'+walletAddress.slice(-4);await loadBal();renderChains();showStep('stepChain');}catch(e){alert('Failed: '+(e.message||e));b.disabled=false;b.textContent='\u{1F98A} Connect MetaMask';}}
async function loadBal(){balances={};const cd='0x'+SEL.balanceOf+encAddr(walletAddress);const ps=[];for(const cid of CHAIN_ORDER){const ch=CHAINS[cid];for(const[sym,tok]of Object.entries(ch.tokens)){ps.push(fetch(ch.rpc,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_call',params:[{to:tok.addr,data:cd},'latest']})}).then(r=>r.json()).then(d=>{if(d.result&&d.result!=='0x'&&d.result!=='0x0'){const raw=BigInt(d.result);if(raw>0n)balances[cid+'-'+sym]=fmtAmt(raw,tok.dec);}}).catch(()=>{}));}}await Promise.all(ps);}
function renderChains(){const l=document.getElementById('chainList');l.innerHTML='';for(const cid of CHAIN_ORDER){const ch=CHAINS[cid];for(const[sym]of Object.entries(ch.tokens)){const k=cid+'-'+sym,bal=balances[k]||'0.00',bn=parseFloat(bal),ok=bn>=AMOUNT;const d=document.createElement('div');d.className='chain-option'+((!ok&&bn>0)?' disabled':'');d.innerHTML='<div><span class="chain-name">'+ch.name+'</span><span class="token-badge">'+sym+'</span></div><span class="chain-balance'+(ok?' enough':'')+'">'+((bn>0)?bal+' '+sym:'\u2014')+'</span>';if(ok||bn===0)d.onclick=()=>selChain(cid,sym);l.appendChild(d);}}}
async function selChain(cid,tok){selectedChainId=cid;selectedToken=tok;const ch=CHAINS[cid];try{const cur=await window.ethereum.request({method:'eth_chainId'});if(parseInt(cur,16)!==cid){try{await window.ethereum.request({method:'wallet_switchEthereumChain',params:[{chainId:ch.hex}]});}catch(e){if(e.code===4902)await window.ethereum.request({method:'wallet_addEthereumChain',params:[{chainId:ch.hex,chainName:ch.name,nativeCurrency:ch.nc,rpcUrls:[ch.rpc],blockExplorerUrls:[ch.explorer]}]});else throw e;}}}catch(e){alert('Switch failed: '+(e.message||e));return;}document.getElementById('reviewChain').textContent=ch.name;document.getElementById('reviewToken').textContent=tok;document.getElementById('reviewAmount').textContent=AMOUNT.toFixed(2)+' '+tok;document.getElementById('reviewCredits').textContent=CREDITS+(IS_FIRST&&BONUS>0?' + '+BONUS+' bonus':'')+' = '+TOTAL_CREDITS;document.getElementById('btnPayAmount').textContent=AMOUNT.toFixed(2);document.getElementById('btnPayToken').textContent=tok;showStep('stepReview');}
async function sendPayment(){showStep('stepSending');const ch=CHAINS[selectedChainId],tok=ch.tokens[selectedToken],raw=parseAmt(AMOUNT,tok.dec),txData='0x'+SEL.transfer+encAddr(MERCHANT_ADDR)+encU256(raw);let txHash;try{txHash=await window.ethereum.request({method:'eth_sendTransaction',params:[{from:walletAddress,to:tok.addr,data:txData}]});}catch(e){if(e.code===4001){showStep('stepReview');return;}document.getElementById('errorMsg').textContent=e.message||'Transaction failed';showStep('stepError');return;}try{const r=await fetch(API_BASE+'/api/credits/stablecoin-payment',{method:'POST',headers:{'Authorization':'Bearer '+AUTH_TOKEN,'Content-Type':'application/json'},body:JSON.stringify({email:EMAIL,txHash,chainId:selectedChainId,chainName:ch.name,token:selectedToken,amount:AMOUNT,credits:CREDITS,bonusCredits:BONUS,totalCredits:TOTAL_CREDITS,isFirstPurchase:IS_FIRST})});const res=await r.json();console.log('Backend:',res);}catch(e){console.warn('Backend call failed:',e);}document.getElementById('successCredits').textContent=TOTAL_CREDITS;document.getElementById('txHashDisplay').textContent=txHash;document.getElementById('txExplorerLink').href=ch.explorer+'/tx/'+txHash;showStep('stepSuccess');}
if(typeof window.ethereum==='undefined'){document.getElementById('noMetamask').style.display='block';document.getElementById('hasMetamask').style.display='none';}
</script>
</body></html>'''


@app.route('/pay/stablecoin', methods=['GET'])
def stablecoin_pay_page():
    """Serve the stablecoin payment page for browser-based MetaMask payments"""
    return STABLECOIN_PAY_PAGE, 200, {'Content-Type': 'text/html'}


# --- On-chain verification helper ---

STABLECOIN_MERCHANT_ADDRESS = os.environ.get('STABLECOIN_MERCHANT_ADDRESS', '').lower()

STABLECOIN_CHAIN_RPCS = {
    1:     'https://eth.llamarpc.com',
    8453:  'https://mainnet.base.org',
    137:   'https://polygon-rpc.com',
    42161: 'https://arb1.arbitrum.io/rpc',
    10:    'https://mainnet.optimism.io',
    43114: 'https://api.avax.network/ext/bc/C/rpc',
    56:    'https://bsc-dataseed.binance.org',
}

STABLECOIN_CONTRACTS = {
    1:     {'0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', '0xdac17f958d2ee523a2206206994597c13d831ec7'},
    8453:  {'0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'},
    137:   {'0x3c499c542cef5e3811e1192ce70d8cc03d5c3359', '0xc2132d05d31c914a87c6611c10748aeb04b58e8f'},
    42161: {'0xaf88d065e77c8cc2239327c5edb3a432268e5831', '0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9'},
    10:    {'0x0b2c639c533813f4aa9d7837caf62653d097ff85', '0x94b008aa00579c1307b0ef2c499ad98a8ce58e58'},
    43114: {'0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e', '0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7'},
    56:    {'0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d', '0x55d398326f99059ff775485246999027b3197955'},
}


def verify_stablecoin_tx_onchain(tx_hash, chain_id, expected_token, expected_amount_usd):
    """Verify a stablecoin transaction on-chain"""
    rpc_url = STABLECOIN_CHAIN_RPCS.get(chain_id)
    if not rpc_url:
        return False, f"Unsupported chain: {chain_id}"

    if not STABLECOIN_MERCHANT_ADDRESS:
        logger.warning("STABLECOIN_MERCHANT_ADDRESS not configured - skipping verification")
        return True, None

    try:
        response = requests.post(rpc_url, json={
            'jsonrpc': '2.0', 'id': 1,
            'method': 'eth_getTransactionReceipt',
            'params': [tx_hash],
        }, timeout=15)

        data = response.json()
        receipt = data.get('result')

        if not receipt:
            return False, "Transaction not found or not yet mined"

        if receipt.get('status', '0x0') != '0x1':
            return False, "Transaction failed on-chain"

        tx_to = (receipt.get('to') or '').lower()
        known_contracts = STABLECOIN_CONTRACTS.get(chain_id, set())
        if tx_to not in known_contracts:
            return False, f"Target {tx_to} is not a known stablecoin contract"

        transfer_topic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
        for log in receipt.get('logs', []):
            topics = log.get('topics', [])
            if len(topics) >= 3 and topics[0] == transfer_topic:
                log_to = '0x' + topics[2][-40:]
                if log_to.lower() == STABLECOIN_MERCHANT_ADDRESS:
                    return True, None

        return False, "No Transfer event to merchant address found"

    except requests.exceptions.Timeout:
        return False, "RPC timeout"
    except Exception as e:
        logger.error(f"On-chain verification error: {e}")
        return False, f"Verification error: {str(e)}"


@app.route('/api/credits/stablecoin-payment', methods=['POST', 'OPTIONS'])
@cross_origin()
def stablecoin_payment():
    """Process stablecoin payment: verify on-chain and add credits"""
    if request.method == 'OPTIONS':
        return '', 204

    try:
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
        tx_hash = data.get('txHash', '').strip()
        chain_id = data.get('chainId', 0)
        token_symbol = data.get('token', '')
        chain_name = data.get('chainName', '')
        amount = data.get('amount', 0)
        credits = data.get('credits', 0)
        bonus_credits = data.get('bonusCredits', 0)
        total_credits = data.get('totalCredits', 0)
        is_first_purchase = data.get('isFirstPurchase', False)

        if not tx_hash or not tx_hash.startswith('0x'):
            return create_response("error", "Valid transaction hash required", status_code=400)
        if not validate_email(email):
            return create_response("error", "Invalid email", status_code=400)
        if email != token_email:
            return create_response("error", "Email mismatch", status_code=403)
        if total_credits <= 0:
            return create_response("error", "Invalid credits amount", status_code=400)

        # Duplicate check
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT id FROM payments WHERE bsv_txid = %s', (tx_hash,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return create_response("error", "Transaction already processed", status_code=409)

        # First purchase check
        if is_first_purchase and not check_first_purchase_available(email):
            cur.close()
            conn.close()
            return create_response("error", "First purchase bonus already used", status_code=400)

        # On-chain verification
        verified, verify_error = verify_stablecoin_tx_onchain(tx_hash, chain_id, token_symbol, float(amount))
        if not verified:
            cur.close()
            conn.close()
            logger.warning(f"Stablecoin tx verification failed: {tx_hash} - {verify_error}")
            return create_response("error", f"Verification failed: {verify_error}", status_code=400)

        # Record payment
        cur.execute('''
            INSERT INTO payments (email, amount, credits, bonus_credits, total_credits,
                 is_first_purchase, bsv_txid, payment_type, status, created_at, completed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'stablecoin', 'completed', %s, %s)
            RETURNING id
        ''', (email, amount, credits, bonus_credits, total_credits,
              is_first_purchase, tx_hash, datetime.now(), datetime.now()))

        payment_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        new_balance = add_user_credits(email, total_credits)
        if is_first_purchase:
            mark_first_purchase_used(email)

        logger.info(f"Stablecoin payment: id={payment_id}, tx={tx_hash}, chain={chain_name}, "
                     f"token={token_symbol}, amount=${amount}, credits={total_credits}, user={email}")

        return create_response("success", "Payment processed", data={
            "payment_id": payment_id, "txHash": tx_hash, "credits_added": total_credits,
            "new_balance": new_balance, "is_first_purchase": is_first_purchase,
        })

    except Exception as e:
        logger.error(f"Stablecoin payment error: {e}", exc_info=True)
        return create_response("error", "Failed to process payment", status_code=500)
    
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
            "version": "3.0.0",
            "features": ["auth", "credits", "first_purchase_bonus", "square_payments"],
            "square_configured": bool(SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID),
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
    logger.info("=" * 50)
    app.run(host='0.0.0.0', port=port, debug=False)
