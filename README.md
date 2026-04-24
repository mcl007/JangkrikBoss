# ENI NetAutomation — Network Automation Platform

A web-based network automation platform built for **ENI Oil & Gas** infrastructure teams. Manage, configure, troubleshoot, and back up network devices (Cisco, Fortinet, MikroTik, Linux) from a single dark-themed dashboard with role-based access control.

---

## 🚀 Features

### Core Modules
| Module | Description |
|--------|-------------|
| **Dashboard** | Overview with device count, backups, config pushes, errors, and recent activity logs |
| **Device Inventory** | Add, edit, delete network devices with real-time online/offline status check (TCP probe) |
| **Configuration Push** | Send CLI commands to devices via SSH (Netmiko). Supports multi-line configs |
| **Troubleshooting** | Run diagnostic commands — Ping, Traceroute, Show commands on any registered device |
| **Backup Management** | Automated `show running-config` backup to SQLite + local file system with preview & download |
| **Scheduled Backups** | Background scheduled task (via APScheduler) to automatically pull backups daily at 2:00 AM |
| **Config Diff** | Compare any two backups side-by-side to easily identify configuration changes |
| **Web SSH Terminal** | Interactive SSH sessions directly in the browser using xterm.js + WebSocket |
| **User Management** | Create users with **Admin** (full access) or **Viewer** (read-only) roles |

### Security
- 🔐 **Authentication** — Flask-Login with PBKDF2 password hashing
- 🔑 **Credential Encryption** — Device SSH passwords and enable secrets are strongly encrypted at rest using `cryptography` (Fernet)
- 🛡️ **CSRF Protection** — Flask-WTF on all POST forms
- 🚫 **Command Sanitization** — Blocks dangerous commands (`reload`, `erase`, `format`, `rm -rf`, etc.)
- 🔒 **Role-Based Access Control** — Admin vs Viewer roles; viewers cannot modify devices or push configs
- 🍪 **Secure Cookies** — HttpOnly, SameSite=Lax

### Supported Device Types
| Vendor | Type | Netmiko Driver |
|--------|------|---------------|
| Cisco | IOS | `cisco_ios` |
| Cisco | IOS-XE | `cisco_xe` |
| Cisco | NX-OS | `cisco_nxos` |
| Fortinet | FortiOS | `fortinet` |
| MikroTik | RouterOS | `mikrotik_routeros` |
| Linux | SSH | `linux` |

---

## 📁 Project Structure

```
NetAutomation/
├── app.py                  # Flask application (routes, WebSocket, SSH)
├── config.py               # Configuration (secret key, DB path, device types)
├── database.py             # SQLite schema, CRUD helpers
├── requirements.txt        # Python dependencies
├── netauto.db              # SQLite database (auto-created)
├── backups/                # Local backup storage (auto-created)
├── static/
│   ├── css/
│   │   └── style.css       # Custom dark theme CSS
│   └── js/
│       └── app.js          # Frontend interactivity
└── templates/
    ├── base.html            # Layout: sidebar, topbar, content blocks
    ├── login.html           # Login page with ENI branding
    ├── dashboard.html       # Stats, quick actions, activity feed
    ├── devices.html         # Device CRUD + status + edit/delete modals
    ├── configure.html       # Command push interface
    ├── troubleshoot.html    # Ping, traceroute, show commands
    ├── backup.html          # Backup list, preview modal, download
    ├── terminal.html        # Web SSH terminal (xterm.js)
    └── users.html           # User management (admin only)
```

---

## ⚙️ Installation

### Prerequisites
- **Python 3.9+**
- **pip** (Python package manager)
- Network access to target devices (SSH port 22)

### Steps

```bash
# 1. Clone or copy the project
cd d:\Michael\NetAutomation

# 2. Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate .env file for encryption key
python -c "import os; from cryptography.fernet import Fernet; open('.env', 'w').write(f'ENCRYPTION_KEY={Fernet.generate_key().decode()}\n')"

# 5. Run the application
python app.py
```

### First Launch
```
============================================================
  NetAutomation — Network Automation Platform
  http://127.0.0.1:5000
  Default login: admin / admin123
============================================================
```

> ⚠️ **Change the default admin password immediately** after first login via User Management.

---

## 🖥️ Usage

### Default Credentials
| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Admin |

### User Roles
| Permission | Admin | Viewer |
|-----------|-------|--------|
| View Dashboard | ✅ | ✅ |
| View Devices | ✅ | ✅ |
| Add/Edit/Delete Devices | ✅ | ❌ |
| Check Device Status | ✅ | ✅ |
| Push Configuration | ✅ | ❌ |
| Run Troubleshoot Commands | ✅ | ✅ |
| Create/Download Backups | ✅ | ❌ |
| View Backups | ✅ | ✅ |
| Web SSH Terminal | ✅ | ✅ |
| Manage Users | ✅ | ❌ |

### Adding a Device
1. Navigate to **Devices** in the sidebar
2. Fill in: Hostname, IP Address, Device Type, SSH Port, Username, Password
3. Click **Add Device**
4. Click **Check Status** to verify connectivity

### Pushing Configuration
1. Navigate to **Configure**
2. Select a device from the dropdown
3. Enter CLI commands (one per line)
4. Click **Send Configuration**

### Creating a Backup
1. Navigate to **Backups**
2. Select a device
3. Click **Create Backup**
4. View or download backups from the history table

---

## 🗄️ Database

SQLite database (`netauto.db`) with the following schema:

| Table | Purpose |
|-------|---------|
| `users` | User accounts with hashed passwords and roles |
| `devices` | Network device inventory (hostname, IP, credentials, type) |
| `backups` | Configuration backup content and metadata |
| `activity_logs` | Audit trail of all user actions |

---

## 🔧 Configuration

Edit `config.py` to customize:

```python
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    DATABASE = os.path.join(BASE_DIR, 'netauto.db')
    BACKUP_DIR = os.path.join(BASE_DIR, 'backups')
    DEBUG = True  # Set to False for production!
```

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session encryption key | Auto-generated |
| `ENCRYPTION_KEY` | Key to encrypt/decrypt device credentials | Requires generation in `.env` |

---

## 📜 License

Internal use — ENI Oil & Gas. Not for public distribution.
