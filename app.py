#!/usr/bin/env python3
# Traffic-X: Flask app
# Compatible with systemd ExecStart: gunicorn -w 4 -b 0.0.0.0:$PORT app:app

from __future__ import annotations
from flask import Flask, request, render_template, jsonify
import os
import json
import sqlite3
from datetime import datetime
import psutil
import requests
import time
import shutil
import subprocess
from typing import Any, Dict, Optional

app = Flask(__name__)

# === Configuration ===
DB_PATH = os.getenv("DB_PATH", "/etc/x-ui/x-ui.db")
REQUEST_TIMEOUT = 5  # seconds for external HTTP calls

# === Utilities ===
def convert_bytes(byte_size: Optional[int | float | str]) -> str:
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

def open_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def parse_expiry(ms_or_s: Optional[int | float]) -> str:
    """Accepts ms or s epoch; returns UTC ISO-like string or 'Invalid Date'."""
    if ms_or_s is None:
        return "Invalid Date"
    try:
        ts = float(ms_or_s)
        # Heuristic: > 9999999999 implies milliseconds
        if ts > 9_999_999_999:
            ts = ts / 1000.0
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
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

# === Routes ===
@app.route("/")
def home():
    # Expecting templates/index.html in repo
    try:
        return render_template("index.html")
    except Exception:
        return jsonify({"ok": True, "message": "Traffic-X API is running. Add templates/index.html for UI."})

@app.route("/usage", methods=["POST"])
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

    try:
        with open_db(DB_PATH) as conn:
            cur = conn.cursor()
            query = (
                "SELECT email, up, down, total, expiry_time, inbound_id "
                "FROM client_traffics WHERE email = ? OR id = ?"
            )
            cur.execute(query, (user_input, user_input))
            row = cur.fetchone()
            if not row:
                return "No data found for this user.", 404

            email = row["email"]
            up = convert_bytes(row["up"])
            down = convert_bytes(row["down"])
            total = convert_bytes(row["total"])
            expiry_date = parse_expiry(row["expiry_time"])

            totalGB = "Not Available"
            user_status = "Disabled"

            cur.execute("SELECT settings FROM inbounds WHERE id = ?", (row["inbound_id"],))
            inbound_row = cur.fetchone()
            if inbound_row:
                inbound_data = _safe_json_loads(inbound_row["settings"])
                for client in inbound_data.get("clients", []):
                    if client.get("email") == email:
                        totalGB = convert_bytes(client.get("totalGB", "Not Available"))
                        user_status = "Enabled" if client.get("enable", True) else "Disabled"
                        break

        # Expecting templates/result.html (Jinja)
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
            # Fallback JSON if template missing
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/update-status", methods=["POST"])
def update_status():
    """Placeholder endpoint—extend with real logic as needed."""
    try:
        data = request.get_json(silent=True) or {}
        new_status = data.get("status")
        # TODO: Implement actual status mutation if required.
        app.logger.info("update-status called with: %s", new_status)
        return jsonify({"status": "success", "message": "Status updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/server-status")
def server_status():
    """CPU, RAM, Disk %, and cumulative network counters since boot."""
    try:
        net_io = psutil.net_io_counters()
        status = {
            "cpu": psutil.cpu_percent(interval=1),
            "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage("/").percent,
            "net_sent": convert_bytes(net_io.bytes_sent),
            "net_recv": convert_bytes(net_io.bytes_recv),
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/server-location")
def server_location():
    """Geo/IP using ip-api.com (no key, best-effort)."""
    try:
        r = requests.get("http://ip-api.com/json/", timeout=REQUEST_TIMEOUT)
        data = r.json() if r.ok else {}
        return jsonify(
            {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "ip": data.get("query", "Unknown"),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/cloud-provider")
def cloud_provider():
    """Try to infer cloud provider from DMI sys_vendor."""
    try:
        provider = "Unknown"
        path = "/sys/class/dmi/id/sys_vendor"
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                vendor = f.read().strip().lower()
            if "amazon" in vendor:
                provider = "AWS"
            elif "digital" in vendor:
                provider = "DigitalOcean"
            elif "linode" in vendor:
                provider = "Linode"
            elif "google" in vendor:
                provider = "Google Cloud"
            elif "microsoft" in vendor or "azure" in vendor:
                provider = "Azure"
        return jsonify({"provider": provider})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/net-live")
def net_live():
    """
    Live network rates (Mbps) sampled over ~1s.
    Returns:
    {
      "total": {"rx_mbps": float, "tx_mbps": float},
      "per_nic": {"eth0": {"rx_mbps":..., "tx_mbps":...}, ...}
    }
    """
    try:
        t0 = time.time()
        c0_total = psutil.net_io_counters()
        c0_per = psutil.net_io_counters(pernic=True)
        time.sleep(1.0)
        t1 = time.time()
        c1_total = psutil.net_io_counters()
        c1_per = psutil.net_io_counters(pernic=True)
        dt = t1 - t0

        total = {
            "rx_mbps": _bytes_to_mbps(c1_total.bytes_recv - c0_total.bytes_recv, dt),
            "tx_mbps": _bytes_to_mbps(c1_total.bytes_sent - c0_total.bytes_sent, dt),
        }

        per_nic: Dict[str, Dict[str, float]] = {}
        for nic, s0 in c0_per.items():
            s1 = c1_per.get(nic)
            if not s1:
                continue
            per_nic[nic] = {
                "rx_mbps": _bytes_to_mbps(s1.bytes_recv - s0.bytes_recv, dt),
                "tx_mbps": _bytes_to_mbps(s1.bytes_sent - s0.bytes_sent, dt),
            }

        return jsonify({"total": total, "per_nic": per_nic})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/net-connections")
def net_connections():
    """
    1-second per-connection snapshot via `nethogs`.
    Requires: `sudo apt install nethogs` and sudoers permission for the service user.
    Format:
    {
      "available": bool,
      "rows": [
        {"iface","pid","user","process","tx_mbps","rx_mbps"}, ...
      ],
      "message": optional
    }
    """
    try:
        if not shutil.which("nethogs"):
            return jsonify({"available": False, "message": "nethogs not installed"}), 200

        # -t text mode, -c 1 one iteration, -d 1 delay=1s
        out = subprocess.check_output(
            ["sudo", "nethogs", "-t", "-c", "1", "-d", "1"],
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
            # Expected (approx): iface pid user process(with-spaces...) sent_KBs recv_KBs
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

        return jsonify({"available": True, "rows": rows})
    except subprocess.CalledProcessError as e:
        return jsonify({"available": False, "message": e.output}), 200
    except subprocess.TimeoutExpired:
        return jsonify({"available": False, "message": "nethogs timed out"}), 200
    except Exception as e:
        return jsonify({"available": False, "message": str(e)}), 200

@app.route("/ping")
def ping():
    return jsonify({"status": "success", "message": "Pong!"})

# === WSGI entry ===
if __name__ == "__main__":
    # For local dev/testing. In production, systemd starts gunicorn with app:app
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
