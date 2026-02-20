# railway.py - MilesOn User Management API
# =============================================================================
# IMPORTS
# =============================================================================
import os
import logging
import time
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from functools import wraps
from collections import defaultdict

import psycopg2
import psycopg2.extras
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin

# Import from modules
from config import (
    SECRET_KEY, DATABASE_URL, FRONTEND_URL,
    FIRST_PURCHASE_BONUS_CREDITS,
    SQUARE_ACCESS_TOKEN, SQUARE_LOCATION_ID, SQUARE_ENVIRONMENT, SQUARE_API_URL,
    TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER,
    ANTHROPIC_API_KEY,
)
from auth import (
    hash_password, verify_password, validate_password,
    create_token, verify_token,
    generate_reset_token, hash_reset_token,
    validate_email, extract_token_from_request,
)
from database import (
    init_database,
    get_user_by_email, create_user, update_user_login, update_user_password,
    check_first_purchase_available, mark_first_purchase_used,
    get_user_credits, add_user_credits, use_user_credits,
    save_reset_token, get_reset_token_info, mark_reset_token_used, cleanup_expired_tokens,
    create_payment_record, complete_payment,
)
from email_service import send_email, get_password_reset_email_html
from sms import (
    normalize_phone, parse_driver_reply, build_route_message,
    twilio_send_sms, twilio_check_replies,
)
from route_optimizer import optimize_stops


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


# Initialize database on startup
init_database()


# =============================================================================
# RATE LIMITER
# =============================================================================
request_counts = defaultdict(list)

def rate_limit(max_requests=5, window_seconds=300):
    """Allow max_requests per window_seconds per IP"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
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


def _extract_token():
    """Extract and verify token from request, returns email or None"""
    token = extract_token_from_request(request)
    if not token:
        return None
    return verify_token(token)


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
            "version": "3.2.0",
            "features": ["auth", "credits", "first_purchase_bonus", "square_payments", "bsv_payments", "sms_messaging", "route_optimizer"],
            "square_configured": bool(SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID),
            "twilio_configured": bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE_NUMBER),
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
        token = extract_token_from_request(request)
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
            token = extract_token_from_request(request)
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
        token = extract_token_from_request(request)
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
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request(request)
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
# ROUTES: SQUARE PAYMENTS
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
                return create_response("error", "First purchase bonus has already been used", status_code=400)
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
                "success", "Test mode - credits added directly",
                data={"success": True, "testMode": True, "credits": new_balance, "added": total_credits}
            )

        checkout_id = str(uuid.uuid4())
        payment_id = create_payment_record(email, amount, credits, bonus_credits, total_credits, checkout_id, is_first_purchase)

        if not payment_id:
            return create_response("error", "Failed to create payment record", status_code=500)

        try:
            amount_cents = int(amount * 100)

            if is_first_purchase and bonus_credits > 0:
                item_name = f"\U0001f389 {credits} + {bonus_credits} Bonus = {total_credits} MilesOn Credits"
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
        except requests.exceptions.RequestException:
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

                from database import get_db_connection
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

        from database import get_db_connection
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
# ROUTES: BSV PAYMENTS
# =============================================================================
@app.route('/api/credits/bsv-payment', methods=['POST', 'OPTIONS'])
@cross_origin()
def bsv_payment():
    if request.method == 'OPTIONS':
        return '', 204

    try:
        token = extract_token_from_request(request)
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

        if not txid:
            return create_response("error", "Transaction ID required", status_code=400)
        if not validate_email(email):
            return create_response("error", "Invalid email", status_code=400)
        if email != token_email:
            return create_response("error", "Email mismatch", status_code=403)
        if total_credits <= 0:
            return create_response("error", "Invalid credits amount", status_code=400)

        # Check for duplicate transaction
        from database import get_db_connection
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
                return create_response("error", "First purchase bonus has already been used", status_code=400)

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

        new_balance = add_user_credits(email, total_credits)

        if is_first_purchase:
            mark_first_purchase_used(email)

        logger.info(f"BSV payment processed: {payment_id}, txid={txid}, added {total_credits} credits to {email}")

        return create_response(
            "success", "BSV payment processed successfully",
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
# ROUTES: SMS MESSAGING
# =============================================================================
@app.route('/api/messaging/send', methods=['POST', 'OPTIONS'])
@cross_origin()
def messaging_send():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request(request)
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
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request(request)
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
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request(request)
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
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request(request)
        if not token:
            return create_response("error", "Authentication required", status_code=401)
        email = verify_token(token)
        if not email:
            return create_response("error", "Invalid or expired token", status_code=401)

        if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
            return create_response("error", "Twilio not configured",
                                   data={"success": False, "message": "Missing Twilio credentials"}, status_code=500)

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
    if request.method == 'OPTIONS':
        return '', 204
    try:
        token = extract_token_from_request(request)
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
# ROUTES: AI ROUTE OPTIMIZER
# =============================================================================
@app.route('/api/route/optimize', methods=['POST', 'OPTIONS'])
@cross_origin()
def optimize_route():
    """
    POST /api/route/optimize
    Body: { "addresses": ["City, ST", ...] }
    Only city/state names are sent to AI. No personal or business data.
    """
    if request.method == 'OPTIONS':
        return '', 204

    try:
        data = request.get_json()
        if not data:
            return create_response("error", "No data provided", status_code=400)

        addresses = data.get('addresses', [])

        if len(addresses) < 4:
            return create_response("success", "Too few stops to optimize", data={
                "addresses": addresses, "optimized": False, "engine": "none"
            })

        logger.info(f"[RouteOptimizer] {len(addresses)} stops: {' -> '.join(addresses)}")

        optimized, engine = optimize_stops(addresses)

        was_changed = optimized != addresses
        if was_changed:
            logger.info(f"[RouteOptimizer] Optimized ({engine}): {' -> '.join(optimized)}")

        return create_response("success", "Route optimized" if was_changed else "Route unchanged", data={
            "addresses": optimized,
            "optimized": was_changed,
            "engine": engine
        })

    except Exception as e:
        logger.error(f"[RouteOptimizer] Error: {e}", exc_info=True)
        return create_response("error", str(e), status_code=500)


# =============================================================================
# ROUTES: RECEIPT SCANNING (Claude Vision)
# =============================================================================

@app.route('/api/receipt/scan', methods=['POST', 'OPTIONS'])
@cross_origin()
def scan_receipt():
    """
    POST /api/receipt/scan
    Body: { "images": ["base64_data", ...] }
    
    Accepts receipt images (jpg/png) and fuel card transaction reports (pdf).
    Sends to Claude Vision API to extract fuel stop data.
    Returns: { entries: [{ date, city, state, gallons, paid }] }
    """
    if request.method == 'OPTIONS':
        return '', 204

    if not ANTHROPIC_API_KEY:
        return create_response("error", "AI service not configured", status_code=500)

    try:
        data = request.get_json()
        if not data:
            return create_response("error", "No data provided", status_code=400)

        images = data.get('images', [])
        if not images:
            return create_response("error", "No images provided", status_code=400)

        if len(images) > 10:
            return create_response("error", "Maximum 10 images per request", status_code=400)

        # Build Claude message with all images/documents
        content = []
        for img_data in images:
            media_type = 'image/jpeg'
            pure_base64 = img_data
            if img_data.startswith('data:'):
                header, pure_base64 = img_data.split(',', 1)
                if 'pdf' in header:
                    media_type = 'application/pdf'
                elif 'png' in header:
                    media_type = 'image/png'
                elif 'webp' in header:
                    media_type = 'image/webp'
                elif 'gif' in header:
                    media_type = 'image/gif'

            # PDFs use document type, images use image type
            if media_type == 'application/pdf':
                content.append({
                    "type": "document",
                    "source": {
                        "type": "base64",
                        "media_type": media_type,
                        "data": pure_base64,
                    }
                })
            else:
                content.append({
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": media_type,
                        "data": pure_base64,
                    }
                })

        content.append({
            "type": "text",
            "text": """Analyze these fuel receipt images or fuel card transaction reports.

For EACH fuel transaction/receipt, extract ONLY:
- city: city name where fuel was purchased
- state: 2-letter state code (e.g. WA, OR, ND)

For transaction reports (tables with multiple rows), extract one entry per row/transaction.
Look for columns like "City", "State/Prov", "Location Name" to find the data.

If a field is not visible or unclear, use empty string "".
Do NOT include summary/total rows.

Return ONLY a JSON array, no other text:
[{"city": "Beach", "state": "ND"}, {"city": "Rockville", "state": "MN"}]"""
        })

        import json
        import urllib.request
        import urllib.error

        payload = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": content}]
        }).encode('utf-8')

        req = urllib.request.Request(
            'https://api.anthropic.com/v1/messages',
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'x-api-key': ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01',
            },
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode('utf-8'))

        text = ''.join(
            b.get('text', '') for b in result.get('content', [])
            if b.get('type') == 'text'
        )

        logger.info(f"[ReceiptScan] Claude response: {text[:500]}")

        import re
        text = text.strip()
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text).strip()

        match = re.search(r'\[.*\]', text, re.DOTALL)
        if match:
            text = match.group(0)

        entries = json.loads(text)

        if not isinstance(entries, list):
            entries = [entries]

        # Validate and clean — only include entries with city AND state
        cleaned = []
        for entry in entries:
            city = str(entry.get('city', '')).strip()
            state = str(entry.get('state', '')).strip().upper()[:2]
            if city and state:
                cleaned.append({
                    'date': str(entry.get('date', '')).strip(),
                    'city': city,
                    'state': state,
                    'gallons': str(entry.get('gallons', '')).strip(),
                    'paid': str(entry.get('paid', '')).strip(),
                })

        logger.info(f"[ReceiptScan] Extracted {len(cleaned)} fuel entries")

        return create_response("success", f"Extracted {len(cleaned)} entries", data={
            "entries": cleaned
        })

    except json.JSONDecodeError as e:
        logger.error(f"[ReceiptScan] JSON parse error: {e}")
        return create_response("error", "Failed to parse receipt data", status_code=500)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else 'no body'
        logger.error(f"[ReceiptScan] Claude HTTP {e.code}: {error_body}")
        return create_response("error", f"AI service error: {e.code}", status_code=500)
    except Exception as e:
        logger.error(f"[ReceiptScan] Error: {e}", exc_info=True)
        return create_response("error", str(e), status_code=500)
    
# =============================================================================
# ROUTES: DEBUG
# =============================================================================
@app.route('/api/debug/database', methods=['GET', 'OPTIONS'])
@cross_origin()
def debug_database():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        from database import get_db_connection
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
    logger.info(f"Route optimizer: Claude API ({bool(ANTHROPIC_API_KEY)})")
    logger.info("=" * 50)
    app.run(host='0.0.0.0', port=port, debug=False)
