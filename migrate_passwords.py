import sqlite3
import os
import sys

# Add current dir to path to import config and database
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from database import encrypt_value, get_db

def migrate():
    print("Starting password migration...")
    db = get_db()
    
    # Backup DB first
    import shutil
    db_path = Config.DATABASE
    if os.path.exists(db_path):
        backup_path = db_path + '.bak'
        shutil.copy2(db_path, backup_path)
        print(f"Backed up database to {backup_path}")

    rows = db.execute("SELECT id, password, enable_secret FROM devices").fetchall()
    migrated_count = 0
    for row in rows:
        device_id = row['id']
        password = row['password']
        enable_secret = row['enable_secret']

        # Simple heuristic to avoid double-encrypting: Fernet tokens are long and start with 'gAAAAA'
        needs_update = False
        new_password = password
        if password and not password.startswith('gAAAAA'):
            new_password = encrypt_value(password)
            needs_update = True
        
        new_secret = enable_secret
        if enable_secret and not enable_secret.startswith('gAAAAA'):
            new_secret = encrypt_value(enable_secret)
            needs_update = True

        if needs_update:
            db.execute("UPDATE devices SET password=?, enable_secret=? WHERE id=?", 
                       (new_password, new_secret, device_id))
            migrated_count += 1

    db.commit()
    db.close()
    print(f"Migration complete. Updated {migrated_count} devices.")

if __name__ == '__main__':
    migrate()
