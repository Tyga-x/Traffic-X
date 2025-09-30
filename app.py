# @fileOverview Check usage stats of X-SL
# @author MasterHide
# © 2025 x404 MASTER™ — MIT License
#
# You may not reproduce or distribute this work, in whole or in part,
# without the express written consent of the copyright owner.
# For more information, visit: https://t.me/Dark_Evi

from flask import Flask, request, render_template, jsonify, send_file
import sqlite3
import json
import psutil
import requests
from datetime import datetime
import os
import io

# NEW: uses separate builders (vless/vmess/trojan/ss + QR)
from tx_builders import build_best

app = Flask(__name__)

# Keep the same default DB path; allow override via env
db_path = os.getenv("DB_PATH", "/etc/x-ui/x-ui.db")

def convert_bytes(byte_size):
    """Convert bytes to a human-readable format (MB, GB, TB)."""
    if byte_size is None:
        return "0 Bytes"
    if byte_size < 1024:
        return f"{byte_size} Bytes"
    elif byte_size < 1024 * 1024:
        return f"{round(byte_size / 1024, 2)} KB"
    elif byte_size < 1024 * 1024 * 1024:
        return f"{round(byte_size / (1024 * 1024), 2)} MB"
    elif byte_size < 1024 * 1024 * 1024 * 1024:
        return f"{round(byte_size / (1024 * 1024 * 1024), 2)} GB"
    else:
        return f"{round(byte_size / (1024 * 1024 * 1024 * 1024), 2)} TB"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/usage', methods=['POST'])
def usage():
    """
    ORIGINAL route (unchanged UI): takes email/ID from form,
    shows usage + expiry + per-user enable status.
    """
    try:
        user_input = request.form.get('user_input')  # Get input from the form
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Query to fetch client traffic by email or id (same as before)
        query = '''
            SELECT email, up, down, total, expiry_time, inbound_id
            FROM client_traffics
            WHERE email = ? OR id = ?
        '''
        cursor.execute(query, (user_input, user_input))
        row = cursor.fetchone()

        if row:
            email, up, down, total, expiry_time, inbound_id = row

            # Expiry (handles ms or s)
            expiry_date = "Invalid Date"
            if expiry_time and isinstance(expiry_time, (int, float)):
                expiry_timestamp = expiry_time / 1000 if expiry_time > 9999999999 else expiry_time
                try:
                    expiry_date = datetime.utcfromtimestamp(expiry_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, OSError):
                    expiry_date = "Invalid Date"

            # Per-user totalGB + enable flag from inbounds.settings
            inbound_query = 'SELECT settings FROM inbounds WHERE id = ?'
            cursor.execute(inbound_query, (inbound_id,))
            inbound_row = cursor.fetchone()

            totalGB = "Not Available"
            user_status = "Disabled"  # default if user not found
            if inbound_row:
                settings = inbound_row[0]
                try:
                    inbound_data = json.loads(settings)
                    for client in inbound_data.get('clients', []):
                        if client.get('email') == email:
                            totalGB = client.get('totalGB', "Not Available")
                            user_status = "Enabled" if client.get('enable', True) else "Disabled"
                            break
                except json.JSONDecodeError:
                    totalGB = "Invalid JSON Data"

            conn.close()

            # Convert to human-readable strings
            up_str = convert_bytes(up)
            down_str = convert_bytes(down)
            total_str = convert_bytes(total)
            totalGB_str = convert_bytes(totalGB) if totalGB != "Not Available" else totalGB

            return render_template(
                'result.html',
                email=email,
                up=up_str,
                down=down_str,
                total=total_str,
                expiry_date=expiry_date,
                totalGB=totalGB_str,
                user_status=user_status
            )
        else:
            conn.close()
            return "No data found for this user."
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user_config')
def user_config():
    """
    NEW route used by result.html (Client Config card):
      GET /user_config?username=<email>
    Builds a single best client link from local DB (no panel API),
    plus a QR (PNG data URI) and a suggested filename.
    """
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({"error": "username required"}), 400

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        # Find the inbound row that contains that client's email inside settings.clients[]
        cur.execute("""
          SELECT i.id, i.protocol, i.port, i.remark, i.stream_settings, i.settings, c.value
            FROM inbounds i, json_each(json_extract(i.settings,'$.clients')) c
           WHERE json_extract(c.value,'$.email') = ?
           LIMIT 1
        """, (username,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return jsonify({"error": "user not found"}), 404

        inbound = {
            "id": row[0],
            "protocol": row[1],
            "port": row[2],
            "remark": row[3],
            "stream_settings": row[4],  # TEXT(JSON)
            "settings": row[5]          # TEXT(JSON)
        }
        client = json.loads(row[6]) if row[6] else {}

        built = build_best(inbound, client)  # -> {protocol, vless_link/vmess_link/trojan_link/ss_link, config_text, qr_datauri, ...}

        # Ensure filename includes username for clarity
        if built.get("config_filename") and username not in built["config_filename"]:
            proto = (built.get("protocol") or "config").lower()
            built["config_filename"] = f"{username}_{proto}.txt"

        return jsonify({"username": username, **built})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/download_config')
def download_config():
    """
    NEW: generates a .txt file for the client config (used by Download button).
    """
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({"error": "username required"}), 400

    # Reuse the same builder output
    with app.test_client() as c:
        r = c.get(f"/user_config?username={username}")
    if r.status_code != 200:
        return r

    j = r.get_json() or {}
    text = j.get("config_text", "")
    name = j.get("config_filename", "config.txt")

    buf = io.BytesIO(text.encode())
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=name, mimetype="text/plain")

@app.route('/update-status', methods=['POST'])
def update_status():
    """
    ORIGINAL route (unchanged contract). Stub: you can wire to DB if needed.
    """
    try:
        data = request.get_json()
        new_status = data.get('status')  # True or False
        print(f"Updating status to: {new_status}")
        return jsonify({"status": "success", "message": "Status updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/server-status')
def server_status():
    """Returns real-time CPU, RAM, and Disk usage."""
    try:
        status = {
            "cpu": psutil.cpu_percent(interval=1),
            "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/server-location')
def server_location():
    """Fetches server location based on public IP."""
    try:
        response = requests.get("http://ip-api.com/json/", timeout=5)
        data = response.json()
        return jsonify({
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "ip": data.get("query", "Unknown")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/ping')
def ping():
    """Endpoint for ping test."""
    return jsonify({"status": "success", "message": "Pong!"})

if __name__ == '__main__':
    # IMPORTANT: Use env var PORT; fall back to 5000
    port = int(os.getenv("PORT", "5000"))
    app.run(host='0.0.0.0', port=port, debug=False)
