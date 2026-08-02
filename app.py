#!/usr/bin/env python3
# Traffic-X: Flask app
# Compatible with systemd ExecStart: gunicorn -w 4 -b 0.0.0.0:$PORT app:app

from __future__ import annotations
from flask import Flask, request, render_template, jsonify
import os
import json
import sqlite3
from datetime import datetime, timezone
import psutil
import requests
import time
import shutil
import subprocess
import threading
import traceback
from typing import Any, Dict, Optional, Union
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from tx_telegram import tg_bp, start_notifier, get_setting, set_setting

app = Flask(__name__)
app.register_blueprint(tg_bp)

# Start the Telegram Notification Background Engine
start_notifier(app)

# === Configuration ===
DB_PATH = os.getenv("DB_PATH", "/etc/x-ui/x-ui.db")
REQUEST_TIMEOUT = 5  # seconds for external HTTP calls

# === Rate Limiting (Prevents DoS and abuse) ===
limiter = Limiter(get_remote_address, app=app, default_limits=["120 per minute"], storage_uri="memory://")

# === Utilities ===
def convert_bytes(byte_size: Optional[Union[int, float, str]]) -> str:
    """Convert byte counts to human-friendly units."""
    if byte_size in (None, "", "Not Available"):
        return "0 Bytes"
    try:
        b = float(byte_size)
    except Exception:
        return "0 Bytes"
    units = ["Bytes", "KB", "MB", "GB", "TB"]
    step = 1024.0
    idx = 0
    while b >= step and idx < len(units) - 1:
        b /= step
        idx += 1
    return f"{round(b, 2)} {units[idx]}"

def get_db() -> sqlite3.Connection:
    """Opens SQLite DB with WAL mode and busy timeout for concurrent reads."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
    except sqlite3.OperationalError:
        pass
    return conn

def parse_expiry(ms_or_s: Optional[Union[int, float]]) -> str:
    """Accepts ms or s epoch; returns UTC ISO-like string, 'Unlimited' or 'Invalid Date'."""
    # If no expiry is set, x-ui saves 0 or None. We return "Unlimited".
    if not ms_or_s:
        return "Unlimited"
    try:
        ts = float(ms_or_s)
        # Double-check if the parsed value is 0
        if ts == 0:
            return "Unlimited"
        # Heuristic: > 9999999999 implies milliseconds
        if ts > 9_999_999_999:
            ts = ts / 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Invalid Date"

def _bytes_to_mbps(delta_bytes: float, seconds: float) -> float:
    if seconds <= 0:
        return 0.0
    return round((delta_bytes * 8.0) / (seconds * 1_000_000.0), 3)

def _safe_json_loads(s: str) -> Dict[str, Any]:
    try:
        return json.loads(s or "{}")
    except json.JSONDecodeError:
        return {}

# === Background Stats Worker (Non-blocking CPU & Net sampling) ===
_stats_lock = threading.Lock()
_stats_cache = {
    "cpu": 0.0,
    "ram": 0.0,
    "disk": 0.0,
    "net_sent": 0,
    "net_recv": 0,
    "net_total_rx_mbps": 0.0,
    "net_total_tx_mbps": 0.0,
    "net_per_nic": {}
}

def _background_stats_worker():
    """Continuously samples CPU and network stats in a background thread."""
    last_total = psutil.net_io_counters()
    last_per = psutil.net_io_counters(pernic=True)
    last_t = time.time()
    
    while True:
        time.sleep(1.0)
        now_t = time.time()
        dt = now_t - last_t
        
        cur_total = psutil.net_io_counters()
        cur_per = psutil.net_io_counters(pernic=True)
        
        per_nic = {}
        for nic, s0 in last_per.items():
            s1 = cur_per.get(nic)
            if not s1: continue
            per_nic[nic] = {
                "rx_mbps": _bytes_to_mbps(s1.bytes_recv - s0.bytes_recv, dt),
                "tx_mbps": _bytes_to_mbps(s1.bytes_sent - s0.bytes_sent, dt)
            }
            
        with _stats_lock:
            _stats_cache["cpu"] = psutil.cpu_percent(interval=None)
            _stats_cache["ram"] = psutil.virtual_memory().percent
            _stats_cache["disk"] = psutil.disk_usage("/").percent
            _stats_cache["net_sent"] = cur_total.bytes_sent
            _stats_cache["net_recv"] = cur_total.bytes_recv
            _stats_cache["net_total_rx_mbps"] = _bytes_to_mbps(cur_total.bytes_recv - last_total.bytes_recv, dt)
            _stats_cache["net_total_tx_mbps"] = _bytes_to_mbps(cur_total.bytes_sent - last_total.bytes_sent, dt)
            _stats_cache["net_per_nic"] = per_nic
            
        last_total = cur_total
        last_per = cur_per
        last_t = now_t

# Start the background thread
psutil.cpu_percent(interval=None) # Prime the CPU counter
_t = threading.Thread(target=_background_stats_worker, daemon=True)
_t.start()

# === Caches & Locks ===
_loc_cache = {"t": 0.0, "data": {}}
_nethogs_lock = threading.Lock()
_nethogs_cache = {"t": 0.0, "data": None}

# === Routes ===
@app.route("/")
def home():
    try:
        return render_template("index.html")
    except Exception:
        return jsonify({"ok": True, "message": "Traffic-X API is running. Add templates/index.html for UI."})

@app.route("/usage", methods=["POST"])
@limiter.limit("30 per minute")
def usage():
    """
    Lookup a user by email or id in x-ui's client_traffics,
    and cross-reference inbound settings to fetch totalGB and enable flag.
    """
    user_input = request.form.get("user_input", "").strip()
    if not user_input:
        return jsonify({"error": "user_input is required"}), 400

    if not os.path.exists(DB_PATH):
        return jsonify({"error": f"Database not found at {DB_PATH}"}), 500

    conn = get_db()
    try:
        cur = conn.cursor()
        query = (
            "SELECT email, up, down, total, expiry_time, inbound_id "
            "FROM client_traffics WHERE email = ? OR id = ?"
        )
        cur.execute(query, (user_input, user_input))
        row = cur.fetchone()
                
        if not row:
            try:
                return render_template("not_found.html", user_input=user_input), 404
            except Exception:
                return jsonify({"error": "No data found for this user."}), 404

        email = row["email"]
        up = convert_bytes(row["up"])
        down = convert_bytes(row["down"])
        total = convert_bytes(row["total"])
        expiry_date = parse_expiry(row["expiry_time"])

        totalGB = "Unlimited"
        user_status = "Disabled"

        cur.execute("SELECT settings FROM inbounds WHERE id = ?", (row["inbound_id"],))
        inbound_row = cur.fetchone()
        if inbound_row:
            inbound_data = _safe_json_loads(inbound_row["settings"])
            for client in inbound_data.get("clients", []):
                if client.get("email") == email:
                    # x-ui saves 0 for totalGB if it's unlimited
                    gb_val = client.get("totalGB", 0)
                    if gb_val == 0 or gb_val == "0":
                        totalGB = "Unlimited"
                    else:
                        totalGB = convert_bytes(gb_val)
                        
                    user_status = "Enabled" if client.get("enable", True) else "Disabled"
                    break
    except Exception as e:
        app.logger.error("Usage endpoint failed:\n%s", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close() # Explicitly close to prevent FD leaks

    try:
        return render_template(
            "result.html",
            email=email,
            up=up,
            down=down,
            total=total,
            expiry_date=expiry_date,
            totalGB=totalGB,
            user_status=user_status,
        )
    except Exception:
        return jsonify(
            dict(
                email=email,
                up=up,
                down=down,
                total=total,
                expiry_date=expiry_date,
                totalGB=totalGB,
                user_status=user_status,
            )
        )

@app.route("/update-status", methods=["POST"])
@limiter.limit("10 per minute")
def update_status():
    """Placeholder endpoint—extend with real logic as needed."""
    try:
        data = request.get_json(silent=True) or {}
        new_status = data.get("status")
        app.logger.info("update-status called with: %s", new_status)
        return jsonify({"status": "success", "message": "Status updated"})
    except Exception as e:
        app.logger.error("Update-status failed:\n%s", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

@app.route("/server-status")
@limiter.limit("60 per minute")
def server_status():
    """Returns cached CPU, RAM, Disk %, and network stats."""
    try:
        with _stats_lock:
            status = {
                "cpu": _stats_cache["cpu"],
                "ram": _stats_cache["ram"],
                "disk": _stats_cache["disk"],
                "net_sent": convert_bytes(_stats_cache["net_sent"]),
                "net_recv": convert_bytes(_stats_cache["net_recv"]),
            }
        return jsonify(status)
    except Exception as e:
        app.logger.error("Server-status failed:\n%s", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

@app.route("/server-location")
@limiter.limit("30 per minute")
def server_location():
    """Geo/IP using ip-api.com (cached for 1 hour to prevent rate-limit bans)."""
    now = time.time()
    # Serve from cache if it's less than 1 hour old
    if now - _loc_cache["t"] < 3600 and _loc_cache["data"]:
        return jsonify(_loc_cache["data"])
        
    try:
        # Using HTTP because ip-api.com free tier blocks HTTPS.
        # This is a server-side request, so HTTP is perfectly safe here.
        r = requests.get("http://ip-api.com/json/", timeout=REQUEST_TIMEOUT)
        data = r.json() if r.ok else {}
        result = {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "ip": data.get("query", "Unknown"),
        }
        # Save to cache
        _loc_cache["data"] = result
        _loc_cache["t"] = now
        return jsonify(result)
    except Exception as e:
        app.logger.error("Server-location failed:\n%s", traceback.format_exc())
        return jsonify({"country": "Unknown", "city": "Unknown", "ip": "Unknown"}), 200

@app.route("/cloud-provider")
@limiter.limit("30 per minute")
def cloud_provider():
    """Try to infer cloud provider from DMI sys_vendor with multiple fallbacks."""
    try:
        provider = "Unknown"
        vendor = ""
        
        # Some VPS/Containers don't populate sys_vendor, so we check multiple files
        paths = [
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/board_vendor",
            "/sys/class/dmi/id/bios_vendor"
        ]
        
        for path in paths:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    vendor = f.read().strip().lower()
                if vendor:
                    break
                    
        if "amazon" in vendor or "ec2" in vendor:
            provider = "AWS"
        elif "digital" in vendor or "do droplet" in vendor:
            provider = "DigitalOcean"
        elif "linode" in vendor:
            provider = "Linode"
        elif "google" in vendor or "gce" in vendor:
            provider = "Google Cloud"
        elif "microsoft" in vendor or "azure" in vendor:
            provider = "Azure"
        elif "ovh" in vendor:
            provider = "OVH"
        elif "hetzner" in vendor:
            provider = "Hetzner"
        elif "vultr" in vendor:
            provider = "Vultr"
        elif "vmware" in vendor:
            provider = "VMware"
        elif "xen" in vendor:
            provider = "Xen"
        elif "kvm" in vendor:
            provider = "KVM"
        elif "openvz" in vendor or "virtuozzo" in vendor:
            provider = "OpenVZ"
        elif "lxc" in vendor:
            provider = "LXC"
            
        return jsonify({"provider": provider})
    except Exception as e:
        app.logger.error("Cloud-provider failed:\n%s", traceback.format_exc())
        return jsonify({"provider": "Unknown"}), 200

@app.route("/net-live")
@limiter.limit("60 per minute")
def net_live():
    """Returns live network rates (Mbps) from the background cache."""
    try:
        with _stats_lock:
            data = {
                "total": {
                    "rx_mbps": _stats_cache["net_total_rx_mbps"],
                    "tx_mbps": _stats_cache["net_total_tx_mbps"],
                },
                "per_nic": _stats_cache["net_per_nic"]
            }
        return jsonify(data)
    except Exception as e:
        app.logger.error("Net-live failed:\n%s", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

@app.route("/net-connections")
@limiter.limit("20 per minute")
def net_connections():
    """
    1-second per-connection snapshot via `nethogs`.
    Locked and cached to prevent process flooding.
    """
    now = time.time()
    
    # Return cached data if called within 2 seconds
    if now - _nethogs_cache["t"] < 2.0 and _nethogs_cache["data"] is not None:
        return jsonify(_nethogs_cache["data"])
        
    # Prevent concurrent spawns of nethogs
    if not _nethogs_lock.acquire(blocking=False):
        return jsonify({"available": False, "message": "Busy collecting data. Try again in a moment."}), 429
        
    try:
        if not shutil.which("nethogs"):
            return jsonify({"available": False, "message": "nethogs not installed"}), 200

        out = subprocess.check_output(
            ["sudo", "-n", "nethogs", "-t", "-c", "1", "-d", "1"],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )

        rows = []
        for raw in out.splitlines():
            line = raw.strip()
            if not line or line.startswith("Refreshing:"):
                continue
            parts = line.split()
            if len(parts) < 6:
                continue
            iface, pid, user = parts[0], parts[1], parts[2]
            sent_kbs, recv_kbs = parts[-2], parts[-1]
            process = " ".join(parts[3:-2])

            def kb_to_mbps(s: str) -> float:
                try:
                    return round((float(s) * 8.0) / 1000.0, 3)
                except Exception:
                    return 0.0

            rows.append(
                {
                    "iface": iface,
                    "pid": pid,
                    "user": user,
                    "process": process,
                    "tx_mbps": kb_to_mbps(sent_kbs),
                    "rx_mbps": kb_to_mbps(recv_kbs),
                }
            )

        result = {"available": True, "rows": rows}
        _nethogs_cache["data"] = result
        _nethogs_cache["t"] = now
        return jsonify(result)
    except subprocess.CalledProcessError as e:
        return jsonify({"available": False, "message": "Failed to run nethogs. Check sudoers."}), 200
    except subprocess.TimeoutExpired:
        return jsonify({"available": False, "message": "nethogs timed out"}), 200
    except Exception as e:
        app.logger.error("Net-connections failed:\n%s", traceback.format_exc())
        return jsonify({"available": False, "message": "Internal server error"}), 500
    finally:
        _nethogs_lock.release()

@app.route("/ping")
def ping():
    return jsonify({"status": "success", "message": "Pong!"})

# === WSGI entry ===
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
