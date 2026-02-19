import hashlib
import secrets
import base64
import json
import time
import uuid
import re

from config import SECRET_KEY


# =============================================================================
# PASSWORD
# =============================================================================
def hash_password(password):
    salt = secrets.token_hex(16)
    combined = password + salt
    hashed = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password, stored_hash):
    try:
        salt, hashed = stored_hash.split(':')
        combined = password + salt
        computed_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        return computed_hash == hashed
    except ValueError:
        return False


def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"


# =============================================================================
# JWT-LIKE TOKENS
# =============================================================================
def create_token(email):
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


# =============================================================================
# RESET TOKENS
# =============================================================================
def generate_reset_token():
    return secrets.token_urlsafe(32)


def hash_reset_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


# =============================================================================
# HELPERS
# =============================================================================
def validate_email(email):
    if not email or not isinstance(email, str):
        return False
    return '@' in email and '.' in email.split('@')[-1] and len(email) > 5


def extract_token_from_request(request):
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    return auth_header.replace('Bearer ', '')
