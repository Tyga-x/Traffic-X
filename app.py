from flask import Flask, request, render_template, jsonify, send_file
import sqlite3, json, os, io, psutil, requests
from datetime import datetime
from tx_builders import build_best  # <-- centralized builders (VLESS/VMess/Trojan/SS)

app = Flask(__name__)

# ---- Config (read-only DB) ----
db_path = os.getenv("DB_PATH", "/etc/x-ui/x-ui.db")
fallback_domain = os.getenv("DOMAIN", "localhost")


# ================== helpers ==================
def convert_bytes(byte_size):
    if byte_size is None: return "0 Bytes"
    if byte_size < 1024: return f"{byte_size} Bytes"
    if byte_size < 1024*1024: return f"{round(byte_size/1024,2)} KB"
    if byte_size < 1024*1024*1024: return f"{round(byte_size/(1024*1024),2)} MB"
    if byte_size < 1024*1024*1024*1024: return f"{round(byte_size/(1024*1024*1024),2)} GB"
    return f"{round(byte_size/(1024*1024*1024*1024),2)} TB"


# ================== routes ==================
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/usage", methods=["POST"])
def usage():
    """
    Existing behavior preserved:
    - Accepts a user identifier (email or id)
    - Reads latest usage from client_traffics
    - Enriches with per-client totalGB + enable flag from inbounds.settings.clients
    - Renders result.html with the same variables the page expects
    """
    try:
        user_input = request.form.get("user_input")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        query = """SELECT email, up, down, total, expiry_time, inbound_id
                   FROM client_traffics
                   WHERE email = ? OR id = ?"""
        cursor.execute(query, (user_input, user_input))
        row = cursor.fetchone()

        if row:
            email, up, down, total, expiry_time, inbound_id = row

            # expiry
            expiry_date = "Invalid Date"
            if expiry_time and isinstance(expiry_time, (int, float)):
                expiry_timestamp = expiry_time / 1000 if expiry_time > 9999999999 else expiry_time
                try:
                    expiry_date = datetime.utcfromtimestamp(expiry_timestamp).strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, OSError):
                    expiry_date = "Invalid Date"

            # get client info inside inbound.settings
            inbound_query = "SELECT settings FROM inbounds WHERE id = ?"
            cursor.execute(inbound_query, (inbound_id,))
            inbound_row = cursor.fetchone()

            totalGB = "Not Available"
            user_status = "Disabled"

            if inbound_row:
                settings = inbound_row[0]
                try:
                    inbound_data = json.loads(settings)
                    for client in inbound_data.get("clients", []):
                        if client.get("email") == email:
                            totalGB = client.get("totalGB", "Not Available")
                            user_status = "Enabled" if client.get("enable", True) else "Disabled"
                            break
                except json.JSONDecodeError:
                    totalGB = "Invalid JSON Data"

            conn.close()

            def _fmt(n): return convert_bytes(n)
            return render_template(
                "result.html",
                email=email,
                up=_fmt(up),
                down=_fmt(down),
                total=_fmt(total),
                expiry_date=expiry_date,
                totalGB=convert_bytes(totalGB) if totalGB != "Not Available" else totalGB,
                user_status=user_status
            )
        else:
            conn.close()
            return "No data found for this user."
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/update-status", methods=["POST"])
def update_status():
    # Kept as a no-op that returns success (UI toggle posts here)
    try:
        data = request.get_json() or {}
        _ = data.get("status")
        return jsonify({"status": "success", "message": "Status updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/server-status")
def server_status():
    try:
        net_io = psutil.net_io_counters()
        status = {
            "cpu": psutil.cpu_percent(interval=1),
            "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage("/").percent,
            "net_sent": convert_bytes(net_io.bytes_sent),
            "net_recv": convert_bytes(net_io.bytes_recv)
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/server-location")
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


@app.route("/cloud-provider")
def cloud_provider():
    try:
        provider = "Unknown"
        if os.path.exists("/sys/class/dmi/id/sys_vendor"):
            with open("/sys/class/dmi/id/sys_vendor", "r") as f:
                vendor = f.read().strip().lower()
                if "amazon" in vendor: provider = "AWS"
                elif "digital" in vendor: provider = "DigitalOcean"
                elif "linode" in vendor: provider = "Linode"
                elif "google" in vendor: provider = "Google Cloud"
        return jsonify({"provider": provider})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ================== NEW: user_config + download (using tx_builders) ==================
@app.route("/user_config")
def user_config():
    """
    Fetch inbound + client by username (email) from x-ui.db and
    return a complete link + qr for VLESS/VMess/Trojan/SS (ws/tls/grpc/alpn/fp/allowInsecure/flow etc.)
    """
    username = request.args.get("username", "").strip()
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
            "stream_settings": row[4],  # TEXT (JSON)
            "settings": row[5]          # TEXT (JSON with clients and top-level keys)
        }
        client = json.loads(row[6]) if row[6] else {}

        built = build_best(inbound, client)  # from tx_builders.py

        # ensure filename has username prefix for UX
        if built.get("config_filename") and username not in built["config_filename"]:
            proto = (built.get("protocol") or "config").lower()
            built["config_filename"] = f"{username}_{proto}.txt"

        return jsonify({"username": username, **built})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/download_config")
def download_config():
    username = request.args.get("username", "").strip()
    if not username:
        return jsonify({"error": "username required"}), 400

    r = app.test_client().get(f"/user_config?username={username}")
    if r.status_code != 200:
        return r

    j = r.get_json() or {}
    text = j.get("config_text", "")
    name = j.get("config_filename", "config.txt")

    buf = io.BytesIO(text.encode())
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=name, mimetype="text/plain")


@app.route("/ping")
def ping():
    return jsonify({"status": "success", "message": "Pong!"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
