import logging
import psycopg2
import psycopg2.extras
from datetime import datetime

from config import DATABASE_URL

logger = logging.getLogger(__name__)


# =============================================================================
# LOADS TABLE INIT
# =============================================================================
def init_loads_table():
    """Create loads table if it doesn't exist. Called from init_database()."""
    try:
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute('''
            CREATE TABLE IF NOT EXISTS loads (
                id SERIAL PRIMARY KEY,
                poster_email VARCHAR(255) NOT NULL,
                origin_city VARCHAR(100) NOT NULL,
                origin_state VARCHAR(2) NOT NULL,
                dest_city VARCHAR(100) NOT NULL,
                dest_state VARCHAR(2) NOT NULL,
                pickup_date DATE NOT NULL,
                delivery_date DATE,
                equipment_type VARCHAR(100) NOT NULL,
                weight DECIMAL(10,2),
                length DECIMAL(6,2),
                commodity VARCHAR(255),
                rate DECIMAL(10,2),
                rate_type VARCHAR(20) DEFAULT 'flat',
                contact_name VARCHAR(100),
                contact_phone VARCHAR(30),
                contact_email VARCHAR(255),
                notes TEXT,
                company_name VARCHAR(255),
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Add any missing columns for upgrades
        upgrade_stmts = [
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS delivery_date DATE",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS weight DECIMAL(10,2)",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS length DECIMAL(6,2)",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS commodity VARCHAR(255)",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS rate DECIMAL(10,2)",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS rate_type VARCHAR(20) DEFAULT 'flat'",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS contact_name VARCHAR(100)",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS contact_phone VARCHAR(30)",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS contact_email VARCHAR(255)",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS notes TEXT",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            "ALTER TABLE loads ADD COLUMN IF NOT EXISTS company_name VARCHAR(255)",
        ]
        for stmt in upgrade_stmts:
            try:
                cur.execute(stmt)
            except Exception:
                pass  # Column already exists

        conn.commit()
        cur.close()
        conn.close()
        logger.info("Loads table initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing loads table: {e}")
        raise


# =============================================================================
# LOADS CRUD
# =============================================================================
def create_load(poster_email, origin_city, origin_state, dest_city, dest_state,
                pickup_date, equipment_type, delivery_date=None, weight=None,
                length=None, commodity=None, rate=None, rate_type='flat',
                contact_name=None, contact_phone=None, contact_email=None, notes=None,
                company_name=None):
    try:
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('''
            INSERT INTO loads (
                poster_email, origin_city, origin_state, dest_city, dest_state,
                pickup_date, delivery_date, equipment_type, weight, length,
                commodity, rate, rate_type, contact_name, contact_phone,
                contact_email, notes, company_name, status, created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, 'active', %s, %s
            ) RETURNING *
        ''', (
            poster_email, origin_city, origin_state.upper(), dest_city, dest_state.upper(),
            pickup_date, delivery_date, equipment_type, weight, length,
            commodity, rate, rate_type, contact_name, contact_phone,
            contact_email, notes, company_name, datetime.now(), datetime.now()
        ))
        load = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Load created by {poster_email}: {origin_city},{origin_state} -> {dest_city},{dest_state}")
        return dict(load) if load else None
    except Exception as e:
        logger.error(f"Error creating load: {e}")
        return None


def get_all_active_loads(origin_state=None, dest_state=None, equipment_type=None, from_date=None):
    try:
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        query = """
            SELECT l.*, u.email as company_email
            FROM loads l
            JOIN users u ON l.poster_email = u.email
            WHERE l.status = 'active'
        """
        params = []

        if origin_state:
            params.append(origin_state.upper())
            query += f" AND l.origin_state = %s"
        if dest_state:
            params.append(dest_state.upper())
            query += f" AND l.dest_state = %s"
        if equipment_type:
            params.append(equipment_type)
            query += f" AND l.equipment_type ILIKE %s"
        if from_date:
            params.append(from_date)
            query += f" AND l.pickup_date >= %s"

        query += " ORDER BY l.created_at DESC"

        cur.execute(query, params)
        loads = cur.fetchall()
        cur.close()
        conn.close()
        return [dict(l) for l in loads]
    except Exception as e:
        logger.error(f"Error fetching active loads: {e}")
        return []


def get_loads_by_email(email):
    try:
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT * FROM loads WHERE poster_email = %s ORDER BY created_at DESC",
            (email,)
        )
        loads = cur.fetchall()
        cur.close()
        conn.close()
        return [dict(l) for l in loads]
    except Exception as e:
        logger.error(f"Error fetching loads for {email}: {e}")
        return []


def get_load_by_id(load_id):
    try:
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM loads WHERE id = %s", (load_id,))
        load = cur.fetchone()
        cur.close()
        conn.close()
        return dict(load) if load else None
    except Exception as e:
        logger.error(f"Error fetching load {load_id}: {e}")
        return None


def delete_load(load_id, poster_email):
    """Delete a load - only the owner can delete their own load."""
    try:
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM loads WHERE id = %s AND poster_email = %s RETURNING id",
            (load_id, poster_email)
        )
        deleted = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        if deleted:
            logger.info(f"Load {load_id} deleted by {poster_email}")
            return True
        logger.warning(f"Load {load_id} not found or not owned by {poster_email}")
        return False
    except Exception as e:
        logger.error(f"Error deleting load {load_id}: {e}")
        return False


def update_load_status(load_id, poster_email, status):
    """Update load status (active/inactive). Only owner can update."""
    try:
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            """UPDATE loads SET status = %s, updated_at = %s
               WHERE id = %s AND poster_email = %s RETURNING *""",
            (status, datetime.now(), load_id, poster_email)
        )
        load = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return dict(load) if load else None
    except Exception as e:
        logger.error(f"Error updating load {load_id} status: {e}")
        return None


def update_load(load_id, poster_email, origin_city, origin_state, dest_city, dest_state,
                pickup_date, equipment_type, delivery_date=None, weight=None,
                length=None, commodity=None, rate=None, rate_type='flat',
                contact_name=None, contact_phone=None, contact_email=None, notes=None,
                company_name=None):
    """Update a load - only the owner can update their own load."""
    try:
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('''
            UPDATE loads SET
                origin_city = %s, origin_state = %s,
                dest_city = %s, dest_state = %s,
                pickup_date = %s, delivery_date = %s,
                equipment_type = %s, weight = %s, length = %s,
                commodity = %s, rate = %s, rate_type = %s,
                contact_name = %s, contact_phone = %s, contact_email = %s,
                notes = %s, company_name = %s, updated_at = %s
            WHERE id = %s AND poster_email = %s
            RETURNING *
        ''', (
            origin_city, origin_state.upper(), dest_city, dest_state.upper(),
            pickup_date, delivery_date, equipment_type,
            weight or None, length or None, commodity or None,
            rate or None, rate_type,
            contact_name or None, contact_phone or None, contact_email or None,
            notes or None, company_name or None, datetime.now(),
            load_id, poster_email
        ))
        load = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        if load:
            logger.info(f"Load {load_id} updated by {poster_email}")
            return dict(load)
        logger.warning(f"Load {load_id} not found or not owned by {poster_email}")
        return None
    except Exception as e:
        logger.error(f"Error updating load {load_id}: {e}")
        return None


def serialize_load(load: dict) -> dict:
    """Convert load dict to JSON-serializable format (dates -> strings)."""
    result = {}
    for k, v in load.items():
        if hasattr(v, 'isoformat'):
            result[k] = v.isoformat()
        elif hasattr(v, '__float__'):
            result[k] = float(v)
        else:
            result[k] = v
    return result
