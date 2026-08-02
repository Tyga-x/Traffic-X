# tx_telegram.py
import sqlite3
import time
import threading
import requests
import traceback
from flask import Blueprint, request, jsonify
from datetime import datetime, timezone

# Create a Flask Blueprint for Telegram routes
tg_bp = Blueprint('telegram', __name__)

# Database path (same folder as app.py)
import os
TX_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic_x.db")
XUI_DB_PATH = os.getenv("DB_PATH", "/etc/x-ui/x-ui.db")

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

# Initialize DB when this file is loaded
init_tx_db()

# === Telegram Webhook Route ===
@tg_bp.route("/tg-webhook", methods=["POST"])
def tg_webhook():
    try:
        data = request.get_json()
        if not data or "message" not in data:
            return jsonify({"ok": True})
            
        msg = data["message"]
        chat_id = str(msg["chat"]["id"])
        text = msg.get("text", "")

        if text.startswith("/start"):
            bot_token = get_setting("bot_token")
            if not bot_token:
                return jsonify({"ok": True})
                
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
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": True})

# === Background Notification Engine ===
def _notification_worker():
    time.sleep(30) # Wait 30s on startup
    
    while True:
        try:
            bot_token = get_setting("bot_token")
            renew_link = get_setting("renew_link", "https://t.me/your_admin")
            
            if not bot_token:
                time.sleep(600) # Sleep 10 mins if bot isn't configured
                continue
                
            now = time.time()
            
            # Read x-ui users
            xui_conn = sqlite3.connect(XUI_DB_PATH, timeout=10)
            xui_conn.row_factory = sqlite3.Row
            xui_cur = xui_conn.cursor()
            xui_cur.execute("SELECT email, up, down, total, expiry_time FROM client_traffics")
            users = xui_cur.fetchall()
            xui_conn.close()
            
            # Read TX DB
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
        except Exception as e:
            app.logger.error(f"Notification worker failed:\n{traceback.format_exc()}")
            
        time.sleep(3600) # Run every 1 hour

def start_notifier(app):
    """Call this from app.py to start the background thread"""
    t = threading.Thread(target=_notification_worker, daemon=True)
    t.start()
