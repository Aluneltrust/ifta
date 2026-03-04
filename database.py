import logging
import psycopg2
import psycopg2.extras
from datetime import datetime
from decimal import Decimal

from config import DATABASE_URL

logger = logging.getLogger(__name__)


# =============================================================================
# CONNECTION
# =============================================================================
def get_db_connection():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL environment variable not set")
    return psycopg2.connect(DATABASE_URL)


def init_database():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

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
        cur.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS first_purchase_used BOOLEAN DEFAULT FALSE')

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

        for stmt in [
            'ALTER TABLE payments ADD COLUMN IF NOT EXISTS bonus_credits INTEGER DEFAULT 0',
            'ALTER TABLE payments ADD COLUMN IF NOT EXISTS total_credits INTEGER',
            'ALTER TABLE payments ADD COLUMN IF NOT EXISTS is_first_purchase BOOLEAN DEFAULT FALSE',
            "ALTER TABLE payments ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending'",
            'ALTER TABLE payments ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
            'ALTER TABLE payments ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP',
            'ALTER TABLE payments ADD COLUMN IF NOT EXISTS user_id INTEGER',
            'ALTER TABLE payments ADD COLUMN IF NOT EXISTS bsv_txid VARCHAR(255)',
            "ALTER TABLE payments ADD COLUMN IF NOT EXISTS payment_type VARCHAR(20) DEFAULT 'square'",
        ]:
            cur.execute(stmt)

        cur.execute('''
            UPDATE payments
            SET total_credits = credits + COALESCE(bonus_credits, 0)
            WHERE total_credits IS NULL
        ''')

        conn.commit()
        cur.close()
        conn.close()

        logger.info("Database tables initialized successfully")

        try:
            from loads_db import init_loads_table
            init_loads_table()
            logger.info("Loads table initialized successfully")
        except Exception as loads_err:
            logger.error(f"Error initializing loads table: {loads_err}", exc_info=True)

    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise
# =============================================================================
# USERS
# =============================================================================
def get_user_by_email(email):
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
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        from auth import hash_password
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
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE users SET last_login = %s, last_updated = %s WHERE email = %s',
                    (datetime.now(), datetime.now(), email))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"Error updating login for {email}: {e}")


def update_user_password(email, new_password):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        from auth import hash_password
        hashed_password = hash_password(new_password)
        cur.execute('UPDATE users SET password = %s, last_updated = %s WHERE email = %s',
                    (hashed_password, datetime.now(), email))
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Password updated for {email}")
        return True
    except Exception as e:
        logger.error(f"Error updating password for {email}: {e}")
        return False


def check_first_purchase_available(email):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT first_purchase_used FROM users WHERE email = %s", (email,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result is None:
            return True
        return not result[0]
    except Exception as e:
        logger.error(f"Error checking first purchase for {email}: {e}")
        return False


def mark_first_purchase_used(email):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE users SET first_purchase_used = TRUE, last_updated = %s WHERE email = %s',
                    (datetime.now(), email))
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"First purchase marked as used for {email}")
        return True
    except Exception as e:
        logger.error(f"Error marking first purchase for {email}: {e}")
        return False


# =============================================================================
# CREDITS
# =============================================================================
def get_user_credits(email):
    user = get_user_by_email(email)
    if user:
        credits = user['credits']
        return float(credits) if isinstance(credits, Decimal) else credits
    return 0


def add_user_credits(email, amount):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        amount = Decimal(str(amount))
        cur.execute("SELECT credits FROM users WHERE email = %s", (email,))
        result = cur.fetchone()
        if result:
            current = Decimal(str(result[0])) if result[0] else Decimal('0')
            new_credits = max(Decimal('0'), current + amount)
            cur.execute('UPDATE users SET credits = %s, last_updated = %s WHERE email = %s',
                        (new_credits, datetime.now(), email))
        else:
            new_credits = max(Decimal('0'), amount)
            cur.execute('INSERT INTO users (email, password, credits, created_at, last_updated) VALUES (%s, %s, %s, %s, %s)',
                        (email, '', new_credits, datetime.now(), datetime.now()))
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Added {amount} credits to {email}, new balance: {new_credits}")
        return float(new_credits)
    except Exception as e:
        logger.error(f"Error adding credits to {email}: {e}")
        raise


def use_user_credits(email, amount=1.0):
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
        cur.execute('UPDATE users SET credits = %s, last_updated = %s WHERE email = %s',
                    (new_credits, datetime.now(), email))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error using credits for {email}: {e}")
        return False


# =============================================================================
# RESET TOKENS
# =============================================================================
def save_reset_token(email, token_hash, expires_at):
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
# PAYMENTS
# =============================================================================
def create_payment_record(email, amount, credits, bonus_credits, total_credits, checkout_id=None, is_first_purchase=False):
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
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM payments WHERE square_checkout_id = %s AND status = 'pending'", (checkout_id,))
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
        add_user_credits(payment['email'], payment['total_credits'])
        if payment['is_first_purchase']:
            mark_first_purchase_used(payment['email'])
        logger.info(f"Payment completed: {checkout_id}, added {payment['total_credits']} credits to {payment['email']}")
        return True
    except Exception as e:
        logger.error(f"Error completing payment: {e}")
        return False
