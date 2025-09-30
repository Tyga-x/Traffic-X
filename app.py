# @fileOverview Check usage stats of X-SL
# author MasterHide, updated with DB-based link builders
from flask import Flask, request, render_template, jsonify, send_file
import sqlite3, json, psutil, requests, os, io
from datetime import datetime
from tx_builders import build_best  # NEW

app = Flask(__name__)
db_path = os.getenv("DB_PATH", "/etc/x-ui/x-ui.db")  # same path, env override allowed

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
    try:
        user_input = request.form.get('user_input')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = '''SELECT email, up, down, total, expiry_time, inbound_id 
                   FROM client_traffics WHERE email = ? OR id = ?'''
        cursor.execute(query, (user_input, user_input))
        row = cursor.fetchone()
        if row:
            email, up, down, total, expiry_time, inbound_id = row
            expiry_date = "Invalid Date"
            if expiry_time and isinstance(expiry_time, (int, float)):
                expiry_timestamp = expiry_time / 1000 if expiry_time > 9999999999 else expiry_time
                try:
                    expiry_date = datetime.utcfromtimestamp(expiry_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, OSError):
                    expiry_date = "Invalid Date"

            inbound_query = '''SELECT settings FROM inbounds WHERE id = ?'''
            cursor.execute(inbound_query, (inbound_id,))
            inbound_row = cursor.fetchone()
            totalGB = "Not Available"
            user_status = "Disabled"
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

            up = convert_bytes(up)
            down = convert_bytes(down)
            total = convert_bytes(total)
            totalGB = convert_bytes(totalGB) if totalGB != "Not Available" else totalGB
            return render_template(
                'result.html',
                email=email,
                up=up,
                down=down,
                total=total,
                expiry_date=expiry_date,
                totalGB=totalGB,
                user_status=user_status
            )
        else:
            conn.close()
            return "No data found for this user."
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/update-status', methods=['POST'])
def update_status():
    try:
        data = request.get_json()
        new_status = data.get('status')
        print(f"Updating status to: {new_status}")
        return jsonify({"status": "success", "message": "Status updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/server-status')
def server_status():
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
    return jsonify({"status": "success", "message": "Pong!"})

# ========= NEW: Build client config from local DB (no panel API) =========
@app.route('/user_config')
def user_config():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({"error": "username required"}), 400
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
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

        built = build_best(inbound, client)
        if built.get("config_filename") and username not in built["config_filename"]:
            proto = (built.get("protocol") or "config").lower()
            built["config_filename"] = f"{username}_{proto}.txt"

        return jsonify({"username": username, **built})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/download_config')
def download_config():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({"error": "username required"}), 400

    with app.test_client() as c:
        r = c.get(f"/user_config?username={username}")
    if r.status_code != 200:
        return r

    j = r.get_json() or {}
    text = j.get("config_text", "")
    name = j.get("config_filename", "config.txt")
    buf = io.BytesIO(text.encode()); buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=name, mimetype="text/plain")

if __name__ == '__main__':
    # When run directly (debug off for parity with gunicorn)
    app.run(host='0.0.0.0', port=5000, debug=False)
