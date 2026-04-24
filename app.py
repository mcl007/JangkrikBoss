import os
import re
import socket
import subprocess
import threading
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    Response, jsonify, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO, emit
from werkzeug.security import check_password_hash

from config import Config
from database import (
    init_db, get_user_by_id, get_user_by_username,
    get_all_devices, get_device_by_id, add_device, update_device, delete_device,
    get_all_backups, get_backup_by_id, save_backup,
    log_activity, get_recent_activities, get_stats,
    get_all_users, add_user, update_user, delete_user
)

# ── App Setup ──────────────────────────────────────────────────────

app = Flask(__name__)
app.config.from_object(Config)

csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'


# ── User Model (Flask-Login) ──────────────────────────────────────

class User(UserMixin):
    def __init__(self, user_row):
        self.id = user_row['id']
        self.username = user_row['username']
        self.display_name = user_row['display_name']
        self.role = user_row['role']

    @property
    def is_admin(self):
        return self.role == 'admin'


@login_manager.user_loader
def load_user(user_id):
    row = get_user_by_id(int(user_id))
    return User(row) if row else None


def admin_required(f):
    """Decorator that restricts access to admin users only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ── Input Validation ─────────────────────────────────────────────

def validate_ip(ip):
    """Basic IP address validation."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split('.'))


def validate_hostname(hostname):
    """Basic hostname validation."""
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$'
    return bool(re.match(pattern, hostname))


def sanitize_command(cmd):
    """Block dangerous commands."""
    dangerous = ['reload', 'erase', 'format', 'delete', 'write erase', 'rm -rf', 'mkfs']
    cmd_lower = cmd.strip().lower()
    for d in dangerous:
        if cmd_lower.startswith(d):
            return False, f"Blocked dangerous command: {d}"
    return True, ""


# ── Netmiko Helper ───────────────────────────────────────────────

def connect_to_device(device):
    """Create a Netmiko connection dict from a device DB row."""
    from netmiko import ConnectHandler
    device_params = {
        'device_type': device['device_type'],
        'host': device['ip_address'],
        'username': device['username'],
        'password': device['password'],
        'port': device['port'],
        'timeout': 30,
        'conn_timeout': 30,
    }
    if device['enable_secret']:
        device_params['secret'] = device['enable_secret']
    return ConnectHandler(**device_params)


# ── Auth Routes ──────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user_row = get_user_by_username(username)
        if user_row and check_password_hash(user_row['password_hash'], password):
            login_user(User(user_row))
            flash('Welcome back!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ── Dashboard ────────────────────────────────────────────────────

@app.route('/')
@login_required
def dashboard():
    stats = get_stats()
    activities = get_recent_activities(10)
    return render_template('dashboard.html', stats=stats, activities=activities)


# ── Devices ──────────────────────────────────────────────────────

@app.route('/devices', methods=['GET', 'POST'])
@login_required
def devices():
    if request.method == 'POST' and current_user.is_admin:
        hostname = request.form.get('hostname', '').strip()
        ip_address = request.form.get('ip_address', '').strip()
        device_type = request.form.get('device_type', '').strip()
        port = request.form.get('port', '22').strip()
        username = request.form.get('dev_username', '').strip()
        password = request.form.get('dev_password', '')
        enable_secret = request.form.get('enable_secret', '')
        description = request.form.get('description', '').strip()

        # Validate
        errors = []
        if not validate_hostname(hostname):
            errors.append('Invalid hostname.')
        if not validate_ip(ip_address):
            errors.append('Invalid IP address.')
        if device_type not in Config.DEVICE_TYPES.values():
            errors.append('Invalid device type.')
        if not username:
            errors.append('Username is required.')
        if not password:
            errors.append('Password is required.')
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            errors.append('Port must be 1–65535.')

        if errors:
            for e in errors:
                flash(e, 'danger')
        else:
            add_device(hostname, ip_address, device_type, port, username, password, enable_secret, description)
            log_activity(current_user.id, None, 'add_device', 'success', f'Added device {hostname} ({ip_address})')
            flash(f'Device {hostname} added successfully!', 'success')

        return redirect(url_for('devices'))

    all_devices = get_all_devices()
    return render_template('devices.html', devices=all_devices, device_types=Config.DEVICE_TYPES)


@app.route('/devices/<int:device_id>/edit', methods=['POST'])
@login_required
@admin_required
def device_edit(device_id):
    device = get_device_by_id(device_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('devices'))

    hostname = request.form.get('hostname', '').strip()
    ip_address = request.form.get('ip_address', '').strip()
    device_type = request.form.get('device_type', '').strip()
    port = request.form.get('port', '22').strip()
    username = request.form.get('dev_username', '').strip()
    password = request.form.get('dev_password', '')
    enable_secret = request.form.get('enable_secret', '')
    description = request.form.get('description', '').strip()

    errors = []
    if not validate_hostname(hostname):
        errors.append('Invalid hostname.')
    if not validate_ip(ip_address):
        errors.append('Invalid IP address.')
    if device_type not in Config.DEVICE_TYPES.values():
        errors.append('Invalid device type.')
    if not username:
        errors.append('Username is required.')
    # Password is optional on edit — keep existing if not provided
    if not password:
        password = device['password']
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        errors.append('Port must be 1–65535.')

    if errors:
        for e in errors:
            flash(e, 'danger')
    else:
        if not enable_secret:
            enable_secret = device['enable_secret']
        update_device(device_id, hostname, ip_address, device_type, port, username, password, enable_secret, description)
        log_activity(current_user.id, device_id, 'edit_device', 'success', f'Edited {hostname} ({ip_address})')
        flash(f'Device {hostname} updated successfully!', 'success')

    return redirect(url_for('devices'))


@app.route('/devices/<int:device_id>/json')
@login_required
def device_json(device_id):
    """Return device details as JSON for the edit modal."""
    device = get_device_by_id(device_id)
    if not device:
        return jsonify({'error': 'not found'}), 404
    return jsonify({
        'id': device['id'],
        'hostname': device['hostname'],
        'ip_address': device['ip_address'],
        'device_type': device['device_type'],
        'port': device['port'],
        'username': device['username'],
        'enable_secret': device['enable_secret'],
        'description': device['description'],
    })


@app.route('/devices/<int:device_id>/delete', methods=['POST'])
@login_required
@admin_required
def device_delete(device_id):
    device = get_device_by_id(device_id)
    if device:
        log_activity(current_user.id, device_id, 'delete_device', 'success', f'Deleted {device["hostname"]}')
        delete_device(device_id)
        flash(f'Device {device["hostname"]} deleted.', 'success')
    else:
        flash('Device not found.', 'danger')
    return redirect(url_for('devices'))


@app.route('/devices/status/<int:device_id>')
@login_required
def device_status(device_id):
    """Check if a device is online via TCP socket probe on its SSH port."""
    device = get_device_by_id(device_id)
    if not device:
        return jsonify({'online': False})
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((device['ip_address'], device['port']))
        sock.close()
        return jsonify({'online': result == 0})
    except Exception:
        return jsonify({'online': False})


# ── Configure ────────────────────────────────────────────────────

@app.route('/configure', methods=['GET', 'POST'])
@login_required
def configure():
    output = None
    selected_device_id = None

    if request.method == 'POST':
        device_id = request.form.get('device_id', type=int)
        commands_text = request.form.get('commands', '').strip()
        config_mode = request.form.get('config_mode', 'config_set')

        selected_device_id = device_id
        device = get_device_by_id(device_id) if device_id else None

        if not device:
            flash('Please select a valid device.', 'danger')
        elif not commands_text:
            flash('Please enter commands.', 'danger')
        else:
            commands = [c.strip() for c in commands_text.splitlines() if c.strip()]

            # Validate each command
            for cmd in commands:
                safe, msg = sanitize_command(cmd)
                if not safe:
                    flash(msg, 'danger')
                    return redirect(url_for('configure'))

            try:
                conn = connect_to_device(device)
                if config_mode == 'config_set':
                    result = conn.send_config_set(commands)
                else:
                    result = ""
                    for cmd in commands:
                        result += f"\n{device['hostname']}# {cmd}\n"
                        result += conn.send_command(cmd, read_timeout=30)
                conn.disconnect()
                output = result
                log_activity(current_user.id, device_id, 'configure', 'success',
                             f'Pushed {len(commands)} command(s)')
                flash('Configuration applied successfully!', 'success')
            except Exception as e:
                output = f"Error: {str(e)}"
                log_activity(current_user.id, device_id, 'configure', 'error', str(e))
                flash(f'Configuration failed: {str(e)}', 'danger')

    all_devices = get_all_devices()
    return render_template('configure.html', devices=all_devices, output=output,
                           selected_device_id=selected_device_id)


# ── Troubleshoot ─────────────────────────────────────────────────

@app.route('/troubleshoot', methods=['GET', 'POST'])
@login_required
def troubleshoot():
    output = None
    selected_device_id = None

    if request.method == 'POST':
        device_id = request.form.get('device_id', type=int)
        action = request.form.get('action', '').strip()
        custom_cmd = request.form.get('custom_command', '').strip()
        target_ip = request.form.get('target_ip', '').strip()

        selected_device_id = device_id
        device = get_device_by_id(device_id) if device_id else None

        if not device:
            flash('Please select a valid device.', 'danger')
        else:
            # Map action to command
            command_map = {
                'show_version': 'show version',
                'show_interfaces': 'show ip interface brief',
                'show_routes': 'show ip route',
                'show_arp': 'show arp',
                'show_running': 'show running-config',
                'show_log': 'show logging',
            }

            if action == 'ping' and target_ip:
                command = f'ping {target_ip}'
            elif action == 'traceroute' and target_ip:
                command = f'traceroute {target_ip}'
            elif action == 'custom' and custom_cmd:
                safe, msg = sanitize_command(custom_cmd)
                if not safe:
                    flash(msg, 'danger')
                    return redirect(url_for('troubleshoot'))
                command = custom_cmd
            elif action in command_map:
                command = command_map[action]
            else:
                flash('Invalid action or missing parameters.', 'danger')
                all_devices = get_all_devices()
                return render_template('troubleshoot.html', devices=all_devices, output=output,
                                       selected_device_id=selected_device_id)

            try:
                conn = connect_to_device(device)
                result = conn.send_command(command, read_timeout=60)
                conn.disconnect()
                output = f"{device['hostname']}# {command}\n\n{result}"
                log_activity(current_user.id, device_id, 'troubleshoot', 'success', command)
            except Exception as e:
                output = f"Error: {str(e)}"
                log_activity(current_user.id, device_id, 'troubleshoot', 'error', str(e))
                flash(f'Command failed: {str(e)}', 'danger')

    all_devices = get_all_devices()
    return render_template('troubleshoot.html', devices=all_devices, output=output,
                           selected_device_id=selected_device_id)


# ── Backup ───────────────────────────────────────────────────────

@app.route('/backup', methods=['GET', 'POST'])
@login_required
def backup():
    if request.method == 'POST':
        device_id = request.form.get('device_id', type=int)
        device = get_device_by_id(device_id) if device_id else None

        if not device:
            flash('Please select a valid device.', 'danger')
        else:
            try:
                conn = connect_to_device(device)

                # Use appropriate command based on device type
                if device['device_type'] in ('cisco_ios', 'cisco_xe', 'cisco_nxos'):
                    config = conn.send_command('show running-config', read_timeout=60)
                elif device['device_type'] == 'fortinet':
                    config = conn.send_command('show full-configuration', read_timeout=60)
                elif device['device_type'] == 'mikrotik_routeros':
                    config = conn.send_command('/export', read_timeout=60)
                elif device['device_type'] == 'linux':
                    # For Linux, gather key configs
                    config = "# === Network Configuration ===\n"
                    config += conn.send_command('ip addr show', read_timeout=30) + "\n\n"
                    config += "# === Routing Table ===\n"
                    config += conn.send_command('ip route show', read_timeout=30) + "\n\n"
                    config += "# === Firewall Rules ===\n"
                    config += conn.send_command('sudo iptables -L -n -v 2>/dev/null || echo "No iptables"',
                                                read_timeout=30)
                else:
                    config = conn.send_command('show running-config', read_timeout=60)

                conn.disconnect()

                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{device['hostname']}_{timestamp}.txt"
                save_backup(device_id, filename, config)
                log_activity(current_user.id, device_id, 'backup', 'success', filename)
                flash(f'Backup for {device["hostname"]} saved as {filename}', 'success')
            except Exception as e:
                log_activity(current_user.id, device_id, 'backup', 'error', str(e))
                flash(f'Backup failed: {str(e)}', 'danger')

        return redirect(url_for('backup'))

    all_devices = get_all_devices()
    all_backups = get_all_backups()
    return render_template('backup.html', devices=all_devices, backups=all_backups)


@app.route('/backup/<int:backup_id>/view')
@login_required
def backup_view(backup_id):
    b = get_backup_by_id(backup_id)
    if not b:
        flash('Backup not found.', 'danger')
        return redirect(url_for('backup'))
    return jsonify({
        'hostname': b['hostname'],
        'ip_address': b['ip_address'],
        'filename': b['filename'],
        'content': b['content'],
        'created_at': b['created_at'],
    })


@app.route('/backup/<int:backup_id>/download')
@login_required
def backup_download(backup_id):
    b = get_backup_by_id(backup_id)
    if not b:
        flash('Backup not found.', 'danger')
        return redirect(url_for('backup'))
    return Response(
        b['content'],
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename={b["filename"]}'}
    )


@app.route('/backup/compare', methods=['POST'])
@login_required
def backup_compare():
    backup_id_1 = request.form.get('backup_1', type=int)
    backup_id_2 = request.form.get('backup_2', type=int)

    if not backup_id_1 or not backup_id_2:
        return jsonify({'error': 'Please select two backups to compare.'}), 400

    b1 = get_backup_by_id(backup_id_1)
    b2 = get_backup_by_id(backup_id_2)

    if not b1 or not b2:
        return jsonify({'error': 'One or both backups not found.'}), 404

    import difflib
    lines1 = b1['content'].splitlines()
    lines2 = b2['content'].splitlines()
    
    diff = list(difflib.unified_diff(
        lines1, lines2,
        fromfile=b1['filename'],
        tofile=b2['filename'],
        lineterm=''
    ))
    
    return jsonify({'diff': '\n'.join(diff)})


# ── User Management ──────────────────────────────────────────────

@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_required
def users():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        display_name = request.form.get('display_name', '').strip()
        role = request.form.get('role', 'viewer')

        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if not display_name:
            errors.append('Display name is required.')
        if role not in ('admin', 'viewer'):
            errors.append('Invalid role.')
        if get_user_by_username(username):
            errors.append('Username already exists.')

        if errors:
            for e in errors:
                flash(e, 'danger')
        else:
            add_user(username, password, display_name, role)
            log_activity(current_user.id, None, 'add_user', 'success', f'Added user {username} ({role})')
            flash(f'User {username} created successfully!', 'success')

        return redirect(url_for('users'))

    all_users = get_all_users()
    return render_template('users.html', users=all_users)


@app.route('/users/<int:user_id>/edit', methods=['POST'])
@login_required
@admin_required
def user_edit(user_id):
    username = request.form.get('username', '').strip()
    display_name = request.form.get('display_name', '').strip()
    role = request.form.get('role', 'viewer')
    password = request.form.get('password', '').strip()

    errors = []
    if not username or len(username) < 3:
        errors.append('Username must be at least 3 characters.')
    if not display_name:
        errors.append('Display name is required.')
    if role not in ('admin', 'viewer'):
        errors.append('Invalid role.')
    if password and len(password) < 6:
        errors.append('Password must be at least 6 characters.')

    existing = get_user_by_username(username)
    if existing and existing['id'] != user_id:
        errors.append('Username already taken.')

    if errors:
        for e in errors:
            flash(e, 'danger')
    else:
        update_user(user_id, username, display_name, role, password or None)
        log_activity(current_user.id, None, 'edit_user', 'success', f'Edited user {username}')
        flash(f'User {username} updated!', 'success')

    return redirect(url_for('users'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def user_delete(user_id):
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
    else:
        user = get_user_by_id(user_id)
        if user:
            delete_user(user_id)
            log_activity(current_user.id, None, 'delete_user', 'success', f'Deleted user {user["username"]}')
            flash(f'User {user["username"]} deleted.', 'success')
        else:
            flash('User not found.', 'danger')
    return redirect(url_for('users'))


@app.route('/users/<int:user_id>/json')
@login_required
@admin_required
def user_json(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'not found'}), 404
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'display_name': user['display_name'],
        'role': user['role'],
    })


# ── Web SSH Terminal ─────────────────────────────────────────────

@app.route('/terminal')
@login_required
def terminal():
    all_devices = get_all_devices()
    return render_template('terminal.html', devices=all_devices)


# Store active SSH sessions
ssh_sessions = {}


@socketio.on('ssh_connect')
def handle_ssh_connect(data):
    """Handle WebSocket SSH connection request."""
    if not current_user.is_authenticated:
        emit('ssh_output', {'data': '\r\n*** Authentication required ***\r\n'})
        return

    device_id = data.get('device_id')
    device = get_device_by_id(device_id) if device_id else None

    if not device:
        emit('ssh_output', {'data': '\r\n*** Device not found ***\r\n'})
        return

    sid = request.sid
    try:
        import paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=device['ip_address'],
            port=device['port'],
            username=device['username'],
            password=device['password'],
            timeout=30,
            look_for_keys=False,
            allow_agent=False
        )
        channel = ssh.invoke_shell(term='xterm', width=120, height=40)

        ssh_sessions[sid] = {'ssh': ssh, 'channel': channel, 'device_id': device_id}

        log_activity(current_user.id, device_id, 'ssh_connect', 'success',
                     f'SSH to {device["hostname"]} ({device["ip_address"]})')

        emit('ssh_output', {'data': f'\r\n*** Connected to {device["hostname"]} ({device["ip_address"]}) ***\r\n'})

        # Start reading from SSH channel in background thread
        def read_ssh_output():
            try:
                while sid in ssh_sessions:
                    if channel.recv_ready():
                        output = channel.recv(4096).decode('utf-8', errors='replace')
                        socketio.emit('ssh_output', {'data': output}, to=sid)
                    else:
                        socketio.sleep(0.1)
            except Exception:
                socketio.emit('ssh_output', {'data': '\r\n*** Connection closed ***\r\n'}, to=sid)

        thread = threading.Thread(target=read_ssh_output, daemon=True)
        thread.start()

    except Exception as e:
        log_activity(current_user.id, device_id, 'ssh_connect', 'error', str(e))
        emit('ssh_output', {'data': f'\r\n*** Connection failed: {str(e)} ***\r\n'})


@socketio.on('ssh_input')
def handle_ssh_input(data):
    """Handle keystrokes from the web terminal."""
    sid = request.sid
    session = ssh_sessions.get(sid)
    if session and session['channel'].active:
        session['channel'].send(data.get('data', ''))


@socketio.on('ssh_resize')
def handle_ssh_resize(data):
    """Handle terminal resize events."""
    sid = request.sid
    session = ssh_sessions.get(sid)
    if session and session['channel'].active:
        try:
            session['channel'].resize_pty(
                width=data.get('cols', 120),
                height=data.get('rows', 40)
            )
        except Exception:
            pass


@socketio.on('ssh_disconnect')
def handle_ssh_disconnect():
    """Clean up SSH session on disconnect."""
    sid = request.sid
    session = ssh_sessions.pop(sid, None)
    if session:
        try:
            session['channel'].close()
            session['ssh'].close()
        except Exception:
            pass


@socketio.on('disconnect')
def handle_disconnect():
    """Clean up on WebSocket disconnect."""
    handle_ssh_disconnect()


# ── Main ─────────────────────────────────────────────────────────

if __name__ == '__main__':
    from scheduler import init_scheduler
    init_db()
    init_scheduler()
    print("\n" + "=" * 60)
    print("  NetAutomation — Network Automation Platform")
    print("  http://127.0.0.1:5000")
    print("  Default login: admin / admin123")
    print("=" * 60 + "\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
