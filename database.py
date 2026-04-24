import sqlite3
import os
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet
from config import Config

def get_fernet():
    if not Config.ENCRYPTION_KEY:
        raise ValueError("ENCRYPTION_KEY is not set.")
    return Fernet(Config.ENCRYPTION_KEY.encode('utf-8') if isinstance(Config.ENCRYPTION_KEY, str) else Config.ENCRYPTION_KEY)

def encrypt_value(value):
    if not value:
        return value
    f = get_fernet()
    return f.encrypt(value.encode('utf-8')).decode('utf-8')

def decrypt_value(value):
    if not value:
        return value
    try:
        f = get_fernet()
        return f.decrypt(value.encode('utf-8')).decode('utf-8')
    except Exception:
        # Fallback to plain-text if it's not encrypted (e.g. before migration)
        return value

def _decrypt_device_row(row):
    if not row:
        return row
    device = dict(row)
    device['password'] = decrypt_value(device.get('password'))
    device['enable_secret'] = decrypt_value(device.get('enable_secret'))
    return device


def get_db():
    """Get a database connection with row factory."""
    db = sqlite3.connect(Config.DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    """Initialize database tables and default admin user."""
    os.makedirs(Config.BACKUP_DIR, exist_ok=True)
    db = get_db()

    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            device_type TEXT NOT NULL,
            port INTEGER DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            enable_secret TEXT DEFAULT '',
            description TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_id INTEGER,
            action TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'success',
            details TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
        );
    ''')

    # Create default admin user if none exists
    existing = db.execute('SELECT id FROM users LIMIT 1').fetchone()
    if not existing:
        db.execute(
            'INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)',
            ('admin', generate_password_hash('admin123'), 'Administrator', 'admin')
        )
        print("[*] Default admin user created — username: admin / password: admin123")

    db.commit()
    db.close()


# --- User helpers ---

def get_user_by_id(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()
    return user


def get_user_by_username(username):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    db.close()
    return user


# --- Device helpers ---

def get_all_devices():
    db = get_db()
    rows = db.execute('SELECT * FROM devices ORDER BY hostname').fetchall()
    db.close()
    return [_decrypt_device_row(r) for r in rows]


def get_device_by_id(device_id):
    db = get_db()
    row = db.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    db.close()
    return _decrypt_device_row(row)


def add_device(hostname, ip_address, device_type, port, username, password, enable_secret, description):
    db = get_db()
    db.execute(
        '''INSERT INTO devices (hostname, ip_address, device_type, port, username, password, enable_secret, description)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (hostname, ip_address, device_type, port, username, encrypt_value(password), encrypt_value(enable_secret), description)
    )
    db.commit()
    db.close()


def update_device(device_id, hostname, ip_address, device_type, port, username, password, enable_secret, description):
    db = get_db()
    db.execute(
        '''UPDATE devices SET hostname=?, ip_address=?, device_type=?, port=?, username=?, password=?, enable_secret=?, description=?
           WHERE id=?''',
        (hostname, ip_address, device_type, port, username, encrypt_value(password), encrypt_value(enable_secret), description, device_id)
    )
    db.commit()
    db.close()


def delete_device(device_id):
    db = get_db()
    db.execute('DELETE FROM devices WHERE id = ?', (device_id,))
    db.commit()
    db.close()


# --- User management helpers ---

def get_all_users():
    db = get_db()
    users = db.execute('SELECT id, username, display_name, role, created_at FROM users ORDER BY id').fetchall()
    db.close()
    return users


def add_user(username, password, display_name, role):
    db = get_db()
    db.execute(
        'INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)',
        (username, generate_password_hash(password), display_name, role)
    )
    db.commit()
    db.close()


def update_user(user_id, username, display_name, role, password=None):
    db = get_db()
    if password:
        db.execute(
            'UPDATE users SET username=?, password_hash=?, display_name=?, role=? WHERE id=?',
            (username, generate_password_hash(password), display_name, role, user_id)
        )
    else:
        db.execute(
            'UPDATE users SET username=?, display_name=?, role=? WHERE id=?',
            (username, display_name, role, user_id)
        )
    db.commit()
    db.close()


def delete_user(user_id):
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    db.close()


# --- Backup helpers ---

def get_all_backups():
    db = get_db()
    backups = db.execute('''
        SELECT b.*, d.hostname, d.ip_address
        FROM backups b
        JOIN devices d ON b.device_id = d.id
        ORDER BY b.created_at DESC
    ''').fetchall()
    db.close()
    return backups


def get_backup_by_id(backup_id):
    db = get_db()
    backup = db.execute('''
        SELECT b.*, d.hostname, d.ip_address
        FROM backups b
        JOIN devices d ON b.device_id = d.id
        WHERE b.id = ?
    ''', (backup_id,)).fetchone()
    db.close()
    return backup


def save_backup(device_id, filename, content):
    file_size = len(content.encode('utf-8'))
    db = get_db()
    db.execute(
        'INSERT INTO backups (device_id, filename, content, file_size) VALUES (?, ?, ?, ?)',
        (device_id, filename, content, file_size)
    )
    db.commit()
    db.close()

    # Also save to disk
    filepath = os.path.join(Config.BACKUP_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)


# --- Activity Log helpers ---

def log_activity(user_id, device_id, action, status='success', details=''):
    db = get_db()
    db.execute(
        'INSERT INTO activity_logs (user_id, device_id, action, status, details) VALUES (?, ?, ?, ?, ?)',
        (user_id, device_id, action, status, details)
    )
    db.commit()
    db.close()


def get_recent_activities(limit=20):
    db = get_db()
    activities = db.execute('''
        SELECT a.*, u.username, d.hostname, d.ip_address
        FROM activity_logs a
        LEFT JOIN users u ON a.user_id = u.id
        LEFT JOIN devices d ON a.device_id = d.id
        ORDER BY a.created_at DESC
        LIMIT ?
    ''', (limit,)).fetchall()
    db.close()
    return activities


def get_stats():
    db = get_db()
    stats = {
        'total_devices': db.execute('SELECT COUNT(*) FROM devices').fetchone()[0],
        'total_backups': db.execute('SELECT COUNT(*) FROM backups').fetchone()[0],
        'total_configs': db.execute("SELECT COUNT(*) FROM activity_logs WHERE action = 'configure'").fetchone()[0],
        'total_errors': db.execute("SELECT COUNT(*) FROM activity_logs WHERE status = 'error'").fetchone()[0],
    }
    db.close()
    return stats
