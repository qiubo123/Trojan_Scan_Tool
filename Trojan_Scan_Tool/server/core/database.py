import sqlite3
import hashlib
import uuid
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

DB_PATH = None
SESSION_EXPIRE_HOURS = 24


def init_db(db_path):
    global DB_PATH
    DB_PATH = db_path
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER DEFAULT 0,
            threat_type TEXT DEFAULT '',
            description TEXT DEFAULT '',
            source TEXT DEFAULT 'server',
            status TEXT DEFAULT 'active',
            location TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            related_virus TEXT DEFAULT '',
            create_time TEXT,
            update_time TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            hostname TEXT DEFAULT '',
            version TEXT DEFAULT '',
            os TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            last_seen TEXT,
            registered_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT,
            expires_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT DEFAULT '',
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            created_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            purpose TEXT NOT NULL,
            api_key TEXT NOT NULL,
            created_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER DEFAULT 0,
            threat_type TEXT DEFAULT '',
            description TEXT DEFAULT '',
            source TEXT DEFAULT 'client',
            location TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            related_virus TEXT DEFAULT '',
            client_id TEXT DEFAULT '',
            batch_id TEXT DEFAULT '',
            review_status TEXT DEFAULT 'pending',
            create_time TEXT,
            update_time TEXT
        )
    """)
    conn.commit()

    try:
        cursor.execute("ALTER TABLE pending_ips ADD COLUMN batch_id TEXT DEFAULT ''")
    except Exception:
        pass

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        import uuid
        default_pw = uuid.uuid4().hex[:12]
        pw_hash = hash_password(default_pw)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin", pw_hash, "admin", now)
        )
        conn.commit()
        logger.info(f"已创建默认管理员账户: admin / {default_pw}")
        logger.info("请立即登录后修改默认密码！")

    conn.close()


def get_conn():
    return sqlite3.connect(DB_PATH)


def hash_password(password):
    import hashlib
    salt = hashlib.sha256(password.encode()).hexdigest()[:16]
    return hashlib.sha256((salt + password).encode()).hexdigest() + ":" + salt


def verify_password(password, stored_hash):
    import hashlib
    if ":" not in stored_hash:
        return hashlib.sha256(password.encode()).hexdigest() == stored_hash
    parts = stored_hash.rsplit(":", 1)
    if len(parts) != 2:
        return False
    hash_part, salt = parts
    return hashlib.sha256((salt + password).encode()).hexdigest() == hash_part


def generate_token():
    return uuid.uuid4().hex + uuid.uuid4().hex


def verify_session(token):
    if not token:
        return None
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, expires_at FROM sessions WHERE token = ?",
        (token,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    username, expires_at = row
    expires = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
    if expires < datetime.now():
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        return None
    return username


def add_audit_log(username, action, detail="", ip_address=""):
    try:
        conn = get_conn()
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO audit_log (username, action, detail, ip_address, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, action, detail, ip_address, now)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"写入审计日志失败: {e}")


def dict_fetch_all(cursor):
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def verify_api_key(api_key):
    if not api_key:
        return None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT purpose FROM api_keys WHERE api_key = ?", (api_key,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return row[0]
        return None
    except Exception:
        return None
