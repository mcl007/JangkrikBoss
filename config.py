import os
import secrets
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    DATABASE = os.path.join(BASE_DIR, 'netauto.db')
    BACKUP_DIR = os.path.join(BASE_DIR, 'backups')
    DEBUG = True

    # Security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

    # Supported device types mapping (display_name -> netmiko device_type)
    DEVICE_TYPES = {
        'Cisco IOS': 'cisco_ios',
        'Cisco IOS-XE': 'cisco_xe',
        'Cisco NX-OS': 'cisco_nxos',
        'Fortinet FortiOS': 'fortinet',
        'MikroTik RouterOS': 'mikrotik_routeros',
        'Linux': 'linux',
    }
