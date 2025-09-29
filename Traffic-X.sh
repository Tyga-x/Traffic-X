#!/bin/bash
# @fileOverview Check usage stats of X-SL
# @author MasterHide
# @Copyright © 2025 x404 MASTER™
# @license MIT
#
# You may not reproduce or distribute this work, in whole or in part, 
# without the express written consent of the copyright owner.
#
# For more information, visit: https://t.me/Dark_Evi

# Function to display the menu

show_menu() {
    echo "Welcome to Traffic-X Installer/Uninstaller"
    echo "Please choose an option:"
    echo "1. Run Traffic-X (Install)"
    echo "2. Uninstall Traffic-X"
    echo "3. Exit"
}

while true; do
    show_menu
    read -p "Enter your choice [1-3]: " CHOICE
    case $CHOICE in
        1) echo "Proceeding with Traffic-X installation..."; break ;;
        2) echo "Uninstalling Traffic-X..."; bash <(curl -s https://raw.githubusercontent.com/Tyga-x/Traffic-X/main/rm-TX.sh); echo "Traffic-X has been uninstalled."; exit 0 ;;
        3) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice. Please select a valid option [1-3]." ;;
    esac
done

echo "Enter your OS username (e.g., ubuntu):"
read USERNAME
echo "Enter your server domain or IP (e.g., my.domain.com):"
read SERVER_IP
echo "Enter the port (default: 5000):"
read PORT
PORT=${PORT:-5000}

echo "Enter the version to install (e.g., v1.0.1) or leave blank for latest:"
read VERSION
if [ -z "$VERSION" ]; then VERSION="latest"; fi

echo "Updating packages..."
sudo apt update

echo "Installing required dependencies..."
sudo apt install -y python3-pip python3-venv git sqlite3 socat unzip curl

echo "Downloading Traffic-X version $VERSION..."
if [ "$VERSION" == "latest" ]; then
    DOWNLOAD_URL="https://github.com/Tyga-x/Traffic-X/archive/refs/heads/main.zip"
else
    DOWNLOAD_URL="https://github.com/Tyga-x/Traffic-X/archive/refs/tags/$VERSION.zip"
fi

cd /home/$USERNAME || exit 1
if curl -L "$DOWNLOAD_URL" -o Traffic-X.zip; then
    echo "Extracting..."
    unzip -o Traffic-X.zip -d /home/$USERNAME
    EXTRACTED_DIR=$(ls /home/$USERNAME | grep "Traffic-X-" | head -n 1)
    rm -rf /home/$USERNAME/Traffic-X
    mv "/home/$USERNAME/$EXTRACTED_DIR" /home/$USERNAME/Traffic-X
    rm Traffic-X.zip
else
    echo "Failed to download Traffic-X. Exiting."
    exit 1
fi

if [ ! -d "/home/$USERNAME/Traffic-X/templates" ]; then
    echo "Templates directory missing. Exiting."
    exit 1
fi

echo "Setting up virtualenv..."
cd /home/$USERNAME/Traffic-X || exit 1
python3 -m venv venv
source venv/bin/activate

echo "Installing Python deps..."
pip install --upgrade pip
# IMPORTANT: qrcode[pil] is needed for QR generation
pip install flask gunicorn psutil requests qrcode[pil]

# Optional: SSL via acme.sh (kept from your flow)
echo "Configuring SSL (optional)..."
export DOMAIN="$SERVER_IP"
mkdir -p /var/lib/Traffic-X/certs
sudo chown -R $USERNAME:$USERNAME /var/lib/Traffic-X/certs

if [ -f "/var/lib/Traffic-X/certs/$DOMAIN.cer" ] && [ -f "/var/lib/Traffic-X/certs/$DOMAIN.cer.key" ]; then
    echo "Existing cert found."
    SSL_CONTEXT="--certfile=/var/lib/Traffic-X/certs/$DOMAIN.cer --keyfile=/var/lib/Traffic-X/certs/$DOMAIN.cer.key"
else
    echo "Attempting to issue cert via acme.sh..."
    curl https://get.acme.sh | sh -s email=$USERNAME@$SERVER_IP
    ~/.acme.sh/acme.sh --issue --force --standalone -d "$DOMAIN" \
        --fullchain-file "/var/lib/Traffic-X/certs/$DOMAIN.cer" \
        --key-file "/var/lib/Traffic-X/certs/$DOMAIN.cer.key"
    sudo chown $USERNAME:$USERNAME /var/lib/Traffic-X/certs/$DOMAIN.cer
    sudo chown $USERNAME:$USERNAME /var/lib/Traffic-X/certs/$DOMAIN.cer.key
    if [ -f "/var/lib/Traffic-X/certs/$DOMAIN.cer" ] && [ -f "/var/lib/Traffic-X/certs/$DOMAIN.cer.key" ]; then
        SSL_CONTEXT="--certfile=/var/lib/Traffic-X/certs/$DOMAIN.cer --keyfile=/var/lib/Traffic-X/certs/$DOMAIN.cer.key"
    else
        echo "SSL issuance failed. Running without SSL."
        SSL_CONTEXT=""
    fi
fi

echo "Writing app.py..."
cat > app.py <<'EOL'
from flask import Flask, request, render_template, jsonify, send_file
import sqlite3, json, os, base64, io, psutil, requests, time, shutil, subprocess
from datetime import datetime
import qrcode

app = Flask(__name__)

# ---- Config (read-only DB) ----
db_path = os.getenv("DB_PATH", "/etc/x-ui/x-ui.db")
fallback_domain = os.getenv("DOMAIN", "localhost")

# ================== helpers (existing style preserved) ==================
def convert_bytes(byte_size):
    if byte_size is None: return "0 Bytes"
    if byte_size < 1024: return f"{byte_size} Bytes"
    if byte_size < 1024*1024: return f"{round(byte_size/1024,2)} KB"
    if byte_size < 1024*1024*1024: return f"{round(byte_size/(1024*1024),2)} MB"
    if byte_size < 1024*1024*1024*1024: return f"{round(byte_size/(1024*1024*1024),2)} GB"
    return f"{round(byte_size/(1024*1024*1024*1024),2)} TB"

def _json(text):
    if not text: return {}
    try:
        return json.loads(text)
    except Exception:
        try:
            return json.loads(str(text).replace("'", '"'))
        except Exception:
            return {}

def _server_host(stream):
    # Prefer TLS SNI -> WS Host -> fallback DOMAIN
    tls = stream.get("tlsSettings", {}) if isinstance(stream, dict) else {}
    ws  = stream.get("wsSettings", {}) if isinstance(stream, dict) else {}
    return tls.get("serverName") or (ws.get("headers", {}) or {}).get("Host") or fallback_domain

def _client_key(client):
    # vless/vmess -> id/uuid; trojan -> password
    return client.get("id") or client.get("uuid") or client.get("password")

def _qr_data_uri(text):
    qr = qrcode.QRCode(border=1)
    qr.add_data(text); qr.make(fit=True)
    img = qr.make_image()
    buf = io.BytesIO(); img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

# ================== link builders (VLESS / VMess / Trojan) ==================
def _build_vless(client, inbound):
    stream = _json(inbound.get("stream_settings"))
    net = stream.get("network","tcp")                              # tcp/ws/grpc
    host = _server_host(stream)
    path = (stream.get("wsSettings",{}) or {}).get("path","/")     # ws path
    sec  = stream.get("security","none")                           # none/tls
    uid  = _client_key(client)
    port = str(inbound.get("port"))
    from urllib.parse import quote
    tag = quote(client.get("email") or inbound.get("remark") or "node")

    q = f"type={net}&security={sec}&encryption=none"
    if net == "ws":
        q += f"&path={path}"
        wsh = (stream.get("wsSettings",{}) or {}).get("headers",{}).get("Host","")
        if wsh: q += f"&host={wsh}"
    elif net == "grpc":
        svc = (stream.get("grpcSettings",{}) or {}).get("serviceName","")
        q += f"&mode=gun&serviceName={svc}"

    return f"vless://{uid}@{host}:{port}?{q}#{tag}"

def _build_vmess_link(client, inbound):
    # vmess://<base64(JSON)>
    stream = _json(inbound.get("stream_settings"))
    net = stream.get("network","tcp")
    host = _server_host(stream)
    path = (stream.get("wsSettings",{}) or {}).get("path","/")
    sec  = stream.get("security","none")
    vm = {
        "v":"2",
        "ps": client.get("email") or inbound.get("remark") or "node",
        "add": host,
        "port": str(inbound.get("port")),
        "id":  _client_key(client),
        "aid": "0",
        "net": net,
        "type":"none",
        "host": (stream.get("wsSettings",{}) or {}).get("headers",{}).get("Host",""),
        "path": path,
        "tls":  "" if sec=="none" else sec
    }
    b64 = base64.b64encode(json.dumps(vm, separators=(",",":")).encode()).decode()
    return "vmess://" + b64, vm

def _build_trojan_link(client, inbound):
    # trojan://password@host:port?security=tls&sni=...&alpn=http/1.1,http2[&type=ws&path=/...&host=...]#tag
    stream = _json(inbound.get("stream_settings"))
    net = stream.get("network","tcp")
    host = _server_host(stream)
    sec  = stream.get("security","tls")  # trojan usually with tls
    tls  = (stream.get("tlsSettings", {}) or {})
    sni  = tls.get("serverName") or host
    pwd  = _client_key(client)           # trojan uses "password"
    port = str(inbound.get("port"))
    from urllib.parse import quote
    tag  = quote(client.get("email") or inbound.get("remark") or "node")

    # optional ALPN
    alpn = tls.get("alpn")
    if isinstance(alpn, list): alpn = ",".join(alpn)

    q = f"security={sec}&sni={sni}"
    if alpn: q += f"&alpn={alpn}"

    if net == "ws":
        ws  = (stream.get("wsSettings", {}) or {})
        path = ws.get("path", "/")
        wsh  = (ws.get("headers", {}) or {}).get("Host", "")
        q += f"&type=ws&path={path}"
        if wsh: q += f"&host={wsh}"
    elif net == "grpc":
        svc = (stream.get("grpcSettings", {}) or {}).get("serviceName", "")
        q += f"&type=grpc&serviceName={svc}"

    return f"trojan://{pwd}@{host}:{port}?{q}#{tag}"

# ================== existing routes (kept) ==================
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
            def _fmt(n): return convert_bytes(n)
            return render_template('result.html',
                                   email=email,
                                   up=_fmt(up),
                                   down=_fmt(down),
                                   total=_fmt(total),
                                   expiry_date=expiry_date,
                                   totalGB=convert_bytes(totalGB) if totalGB!="Not Available" else totalGB,
                                   user_status=user_status)
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
        net_io = psutil.net_io_counters()
        status = {
            "cpu": psutil.cpu_percent(interval=1),
            "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent,
            "net_sent": convert_bytes(net_io.bytes_sent),
            "net_recv": convert_bytes(net_io.bytes_recv)
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/server-location')
def server_location():
    try:
        response = requests.get("http://ip-api.com/json/")
        data = response.json()
        return jsonify({
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "ip": data.get("query", "Unknown")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/cloud-provider')
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

# ================== NEW: user_config + download (read-only) ==================
@app.route('/user_config')
def user_config():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({"error":"username required"}), 400
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
          SELECT i.id, i.protocol, i.port, i.remark, i.stream_settings, c.value
          FROM inbounds i, json_each(json_extract(i.settings,'$.clients')) c
          WHERE json_extract(c.value,'$.email') = ?
          LIMIT 1
        """, (username,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return jsonify({"error":"user not found"}), 404

        inbound = { "id": row[0], "protocol": row[1], "port": row[2], "remark": row[3], "stream_settings": row[4] }
        client = _json(row[5])
        proto = (inbound["protocol"] or "").lower()

        vless = vmess_link = trojan_link = None
        vmess_json = None

        if proto == "vless":
            vless = _build_vless(client, inbound)
            config_text = vless
            config_name = f"{username}_vless.txt"
        elif proto == "vmess":
            vmess_link, vmess_json = _build_vmess_link(client, inbound)
            config_text = vmess_link
            config_name = f"{username}_vmess.txt"
        elif proto == "trojan":
            trojan_link = _build_trojan_link(client, inbound)
            config_text = trojan_link
            config_name = f"{username}_trojan.txt"
        else:
            # best-effort default (keep compatible)
            vless = _build_vless(client, inbound)
            config_text = vless
            config_name = f"{username}_config.txt"

        return jsonify({
            "username": username,
            "protocol": inbound["protocol"],
            "vless_link": vless,
            "vmess_link": vmess_link,
            "vmess_json": vmess_json,
            "trojan_link": trojan_link,
            "qr_datauri": _qr_data_uri(config_text),
            "config_filename": config_name,
            "config_text": config_text
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/download_config')
def download_config():
    username = request.args.get('username','').strip()
    if not username:
        return jsonify({"error":"username required"}), 400
    r = app.test_client().get(f"/user_config?username={username}")
    if r.status_code != 200:
        return r
    j = r.get_json()
    text = (j or {}).get("config_text","")
    name = (j or {}).get("config_filename","config.txt")
    buf = io.BytesIO(text.encode()); buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=name, mimetype="text/plain")

@app.route('/ping')
def ping():
    return jsonify({"status": "success", "message": "Pong!"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT","5000")), debug=False)
EOL

echo "Fixing DB permissions..."
sudo chmod 644 /etc/x-ui/x-ui.db
sudo chown $USERNAME:$USERNAME /etc/x-ui/x-ui.db

if sudo systemctl is-active --quiet traffic-x; then
    echo "Stopping existing Traffic-X..."
    sudo systemctl stop traffic-x
fi

echo "Writing systemd service..."
cat > /etc/systemd/system/traffic-x.service <<EOL
[Unit]
Description=Traffic-X Web App
After=network.target

[Service]
User=$USERNAME
WorkingDirectory=/home/$USERNAME/Traffic-X
ExecStart=/bin/bash -c 'source /home/$USERNAME/Traffic-X/venv/bin/activate && exec gunicorn -w 4 -b 0.0.0.0:$PORT $SSL_CONTEXT app:app'
Environment="DB_PATH=/etc/x-ui/x-ui.db"
Environment="DOMAIN=$SERVER_IP"
Environment="PORT=$PORT"
Restart=always
RestartSec=5
StandardOutput=append:/var/log/traffic-x.log
StandardError=append:/var/log/traffic-x.log
SyslogIdentifier=traffic-x

[Install]
WantedBy=multi-user.target
EOL

echo "Enabling + starting service..."
sudo systemctl daemon-reload
sudo systemctl enable traffic-x
sudo systemctl start traffic-x

# Display success message
echo "Installation complete! Your server is running at http://$SERVER_IP:$PORT"
if [ -n "$SSL_CONTEXT" ]; then
    echo "SSL is enabled. Access the app securely at https://$SERVER_IP:$PORT"
else
    echo "SSL is disabled. Access the app at http://$SERVER_IP:$PORT"
fi
