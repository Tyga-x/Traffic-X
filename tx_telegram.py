# tx_telegram.py
import sqlite3
import time
import threading
import requests
import traceback
import fcntl
import os
from flask import Blueprint, request, jsonify
from datetime import datetime, timezone

# Create a Flask Blueprint for Telegram routes
tg_bp = Blueprint('telegram', __name__)

# Database paths
TX_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic_x.db")
XUI_DB_PATH = os.getenv("DB_PATH", "/etc/x-ui/x-ui.db")

# Global variable to keep the lock file alive!
_global_lock_file = None

# === Database Functions ===
def init_tx_db():
    conn = sqlite3.connect(TX_DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tg_users (xui_email TEXT PRIMARY KEY, tg_chat_id TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS notif_log (xui_email TEXT, type TEXT, last_notified REAL, PRIMARY KEY(xui_email, type))''')
    conn.commit()
    conn.close()

def get_setting(key, default=None):
    conn = sqlite3.connect(TX_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else default

def set_setting(key, value):
    conn = sqlite3.connect(TX_DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

init_tx_db()

# === Long Polling Receiver ===
def _polling_worker():
    """Continuously asks Telegram for new messages from users."""
    time.sleep(10) # Wait for app to start
    offset = 0
    
    while True:
        try:
            bot_token = get_setting("bot_token")
            if not bot_token:
                time.sleep(15) # Wait until admin configures the token
                continue
                
            url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
            params = {"timeout": 10, "offset": offset}
            
            r = requests.post(url, json=params, timeout=15)
            data = r.json()
            
            if data.get("ok"):
                for update in data.get("result", []):
                    offset = update["update_id"] + 1
                    if "message" in update:
                        msg = update["message"]
                        chat_id = str(msg["chat"]["id"])
                        text = msg.get("text", "")
                        
                        if text.startswith("/start"):
                            reply = (
                                f"👋 Welcome to Traffic-X Alerts!\n\n"
                                f"Your Telegram Chat ID is: <b>{chat_id}</b>\n\n"
                                f"Please send this ID to the Admin to link your account."
                            )
                            requests.post(f"https://api.telegram.org/bot{bot_token}/sendMessage", json={
                                "chat_id": chat_id,
                                "text": reply,
                                "parse_mode": "HTML"
                            })
        except Exception:
            pass
            
        time.sleep(1)

# === Background Notification Engine ===
def _notification_worker():
    time.sleep(30) # Wait 30s on startup
    
    while True:
        try:
            bot_token = get_setting("bot_token")
            renew_link = get_setting("renew_link", "https://t.me/your_admin")
            
            if not bot_token:
                time.sleep(600)
                continue
                
            now = time.time()
            
            xui_conn = sqlite3.connect(XUI_DB_PATH, timeout=10)
            xui_conn.row_factory = sqlite3.Row
            xui_cur = xui_conn.cursor()
            xui_cur.execute("SELECT email, up, down, total, expiry_time FROM client_traffics")
            users = xui_cur.fetchall()
            xui_conn.close()
            
            tx_conn = sqlite3.connect(TX_DB_PATH, timeout=10)
            tx_conn.row_factory = sqlite3.Row
            tx_cur = tx_conn.cursor()
            
            for user in users:
                email = user["email"]
                if not email: continue
                
                tx_cur.execute("SELECT tg_chat_id FROM tg_users WHERE xui_email=?", (email,))
                tg_row = tx_cur.fetchone()
                if not tg_row or not tg_row["tg_chat_id"]: continue
                
                chat_id = tg_row["tg_chat_id"]
                
                # Rule 1: Expiry Date (3 Days)
                exp_time = user["expiry_time"]
                if exp_time and float(exp_time) > 0:
                    exp_ts = float(exp_time)
                    if exp_ts > 9_999_999_999: exp_ts = exp_ts / 1000.0
                    days_left = (exp_ts - now) / 86400.0
                    
                    if 0 <= days_left <= 3:
                        tx_cur.execute("SELECT last_notified FROM notif_log WHERE xui_email=? AND type='expiry'", (email,))
                        log_row = tx_cur.fetchone()
                        if not log_row or (now - float(log_row["last_notified"]) >= 86400):
                            msg = f"⚠️ <b>Expiry Alert</b>\nHello {email}, your config expires in {int(days_left)} day(s).\nRenew here: {renew_link}"
                            requests.post(f"https://api.telegram.org/bot{bot_token}/sendMessage", json={"chat_id": chat_id, "text": msg, "parse_mode": "HTML"})
                            tx_cur.execute("INSERT OR REPLACE INTO notif_log (xui_email, type, last_notified) VALUES (?, 'expiry', ?)", (email, str(now)))
                            tx_conn.commit()

                # Rule 2: Data Limit (5GB)
                total = user["total"]
                if total and float(total) > 0:
                    used = float(user["up"]) + float(user["down"])
                    remaining_gb = (float(total) - used) / (1024**3)
                    
                    if 0 <= remaining_gb <= 5:
                        tx_cur.execute("SELECT last_notified FROM notif_log WHERE xui_email=? AND type='data'", (email,))
                        log_row = tx_cur.fetchone()
                        if not log_row or (now - float(log_row["last_notified"]) >= 86400):
                            msg = f"📊 <b>Data Limit Alert</b>\nHello {email}, you have less than {int(remaining_gb)} GB remaining.\nRenew here: {renew_link}"
                            requests.post(f"https://api.telegram.org/bot{bot_token}/sendMessage", json={"chat_id": chat_id, "text": msg, "parse_mode": "HTML"})
                            tx_cur.execute("INSERT OR REPLACE INTO notif_log (xui_email, type, last_notified) VALUES (?, 'data', ?)", (email, str(now)))
                            tx_conn.commit()

            tx_conn.close()
        except Exception:
            pass
            
        time.sleep(3600) # Run every 1 hour


# === Backup Engine ===
def send_backup_document():
    """Sends the traffic_x.db file to the Admin's Telegram Chat ID."""
    bot_token = get_setting("bot_token")
    admin_chat_id = get_setting("admin_chat_id")
    
    if not bot_token or not admin_chat_id:
        return False, "Bot token or Admin Chat ID not set."
    if not os.path.exists(TX_DB_PATH):
        return False, "Database file not found."

    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        with open(TX_DB_PATH, "rb") as db_file:
            files = {"document": db_file}
            data = {"chat_id": admin_chat_id, "caption": "📦 Automatic Daily Backup (Traffic-X)"}
            r = requests.post(url, files=files, data=data, timeout=30)
            
        if r.status_code == 200 and r.json().get("ok"):
            return True, "Backup sent successfully."
        return False, f"Telegram API error: {r.text}"
    except Exception as e:
        return False, str(e)

def _backup_worker():
    """Background thread that sends a backup every 24 hours."""
    time.sleep(60) # Wait 1 min on startup
    
    while True:
        try:
            # Check if 24 hours have passed since last backup
            last_backup = float(get_setting("last_backup_time", 0))
            now = time.time()
            
            if now - last_backup >= 86400: # 86400 seconds = 24 hours
                success, msg = send_backup_document()
                if success:
                    set_setting("last_backup_time", str(now))
                # If it fails, it will just try again in 1 hour
        except Exception:
            pass
            
        time.sleep(3600) # Check every 1 hour

# === Start Notifier with File Lock (FIXED) ===
def start_notifier(app):
    """Starts the engine, but ONLY in the first Gunicorn worker."""
    global _global_lock_file # Use the global variable so it stays alive!
    
    try:
        _global_lock_file = open("/tmp/traffic_x_notifier.lock", "w")
        # Try to acquire an exclusive lock (non-blocking)
        fcntl.flock(_global_lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        app.logger.info("Notification Engine started successfully in this worker.")
    except BlockingIOError:
        # Another worker already has the lock. Do not start the threads.
        app.logger.info("Notification Engine already running in another worker. Skipping.")
        return

    # We got the lock! Start the threads.
    t1 = threading.Thread(target=_polling_worker, daemon=True)
    t1.start()
    
    t2 = threading.Thread(target=_notification_worker, daemon=True)
    t2.start()
    
    # Start the Backup Worker
    t3 = threading.Thread(target=_backup_worker, daemon=True)
    t3.start()
