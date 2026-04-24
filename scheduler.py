from apscheduler.schedulers.background import BackgroundScheduler
from database import get_all_devices, save_backup, log_activity
from datetime import datetime

def perform_device_backup(device):
    from app import connect_to_device # lazy import to avoid circular dependency
    try:
        conn = connect_to_device(device)
        
        if device['device_type'] in ('cisco_ios', 'cisco_xe', 'cisco_nxos'):
            config = conn.send_command('show running-config', read_timeout=60)
        elif device['device_type'] == 'fortinet':
            config = conn.send_command('show full-configuration', read_timeout=60)
        elif device['device_type'] == 'mikrotik_routeros':
            config = conn.send_command('/export', read_timeout=60)
        elif device['device_type'] == 'linux':
            config = "# === Network Configuration ===\n"
            config += conn.send_command('ip addr show', read_timeout=30) + "\n\n"
            config += "# === Routing Table ===\n"
            config += conn.send_command('ip route show', read_timeout=30) + "\n\n"
            config += "# === Firewall Rules ===\n"
            config += conn.send_command('sudo iptables -L -n -v 2>/dev/null || echo "No iptables"', read_timeout=30)
        else:
            config = conn.send_command('show running-config', read_timeout=60)
            
        conn.disconnect()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{device['hostname']}_{timestamp}.txt"
        save_backup(device['id'], filename, config)
        
        # Log as system (assuming user 1 is admin, or we can use None if DB allows)
        # We will use None for user_id to indicate SYSTEM action
        log_activity(None, device['id'], 'scheduled_backup', 'success', filename)
        print(f"  [+] Backup successful for {device['hostname']}")
        
    except Exception as e:
        log_activity(None, device['id'], 'scheduled_backup', 'error', str(e))
        print(f"  [-] Backup failed for {device['hostname']}: {e}")

def run_scheduled_backups():
    print(f"\n[{datetime.now()}] Starting scheduled backups for all devices...")
    devices = get_all_devices()
    for device in devices:
        perform_device_backup(device)
    print(f"[{datetime.now()}] Scheduled backups completed.\n")

def init_scheduler():
    scheduler = BackgroundScheduler(daemon=True)
    # Run everyday at 2:00 AM
    scheduler.add_job(run_scheduled_backups, 'cron', hour=2, minute=0)
    scheduler.start()
    print("[*] Background scheduler started (Daily backups at 02:00 AM)")
