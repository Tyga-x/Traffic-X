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

# ---------- NEW: write the tx_builders module ----------
echo "Writing tx_builders.py..."
cat > tx_builders.py <<'PYEOF'
# tx_builders.py — centralized builders for VLESS / VMess / Trojan / Shadowsocks
import os, json, base64, io
from typing import Dict, Any, Tuple, Optional

try:
    import qrcode
except Exception:
    qrcode = None

FALLBACK_DOMAIN = os.getenv("DOMAIN", "localhost")

def jload(s):
    if not s: return {}
    if isinstance(s, dict): return s
    try: return json.loads(s)
    except Exception:
        try: return json.loads(str(s).replace("'", '"'))
        except Exception: return {}

def server_host(stream: Dict[str, Any]) -> str:
    tls = stream.get("tlsSettings", {}) if isinstance(stream, dict) else {}
    ws  = stream.get("wsSettings", {}) if isinstance(stream, dict) else {}
    return tls.get("serverName") or (ws.get("headers", {}) or {}).get("Host") or FALLBACK_DOMAIN

def client_key(client: Dict[str, Any]) -> str:
    return client.get("id") or client.get("uuid") or client.get("password") or ""

def qr_data_uri(text: str) -> Optional[str]:
    if not (qrcode and text): return None
    qr = qrcode.QRCode(border=1)
    qr.add_data(text); qr.make(fit=True)
    img = qr.make_image()
    buf = io.BytesIO(); img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

def build_vless(client: Dict[str, Any], inbound: Dict[str, Any]) -> str:
    stream = jload(inbound.get("stream_settings"))
    net = stream.get("network", "tcp")
    host = server_host(stream)
    sec  = stream.get("security", "none")
    port = str(inbound.get("port"))
    uid  = client_key(client)
    qs = [f"type={net}", f"security={sec}", "encryption=none"]
    if net == "ws":
        ws = stream.get("wsSettings", {}) or {}
        path = ws.get("path", "/")
        host_header = (ws.get("headers", {}) or {}).get("Host", "")
        qs.append(f"path={path}")
        if host_header: qs.append(f"host={host_header}")
    elif net == "grpc":
        g = stream.get("grpcSettings", {}) or {}
        svc = g.get("serviceName", "")
        qs.append("mode=gun")
        if svc: qs.append(f"serviceName={svc}")
    flow = client.get("flow")
    if flow: qs.append(f"flow={flow}")
    from urllib.parse import quote
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"vless://{uid}@{host}:{port}?{'&'.join(qs)}#{tag}"

def build_vmess(client: Dict[str, Any], inbound: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    stream = jload(inbound.get("stream_settings"))
    net = stream.get("network", "tcp")
    host = server_host(stream)
    sec  = stream.get("security", "none")
    ws   = stream.get("wsSettings", {}) or {}
    path = ws.get("path", "/")
    vm = {
        "v":"2",
        "ps": client.get("email") or inbound.get("remark") or "node",
        "add": host,
        "port": str(inbound.get("port")),
        "id":  client_key(client),
        "aid": "0",
        "net": net,
        "type":"none",
        "host": (ws.get("headers", {}) or {}).get("Host",""),
        "path": path,
        "tls": "" if sec=="none" else sec
    }
    b64 = base64.b64encode(json.dumps(vm, separators=(",",":")).encode()).decode()
    return "vmess://" + b64, vm

def build_trojan(client: Dict[str, Any], inbound: Dict[str, Any]) -> str:
    stream = jload(inbound.get("stream_settings"))
    net = stream.get("network","tcp")
    host = server_host(stream)
    sec  = stream.get("security","tls")
    tls  = (stream.get("tlsSettings", {}) or {})
    sni  = tls.get("serverName") or host
    alpn = tls.get("alpn")
    pwd  = client_key(client)
    port = str(inbound.get("port"))
    qs = [f"security={sec}", f"sni={sni}"]
    if isinstance(alpn, list) and alpn:
        qs.append("alpn=" + ",".join(alpn))
    if net == "ws":
        ws = stream.get("wsSettings", {}) or {}
        path = ws.get("path","/")
        host_header = (ws.get("headers", {}) or {}).get("Host","")
        qs += ["type=ws", f"path={path}"]
        if host_header: qs.append(f"host={host_header}")
    elif net == "grpc":
        g = stream.get("grpcSettings", {}) or {}
        svc = g.get("serviceName","")
        qs += ["type=grpc"]
        if svc: qs.append(f"serviceName={svc}")
    from urllib.parse import quote
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"trojan://{pwd}@{host}:{port}?{'&'.join(qs)}#{tag}"

def build_ss(client: Dict[str, Any], inbound: Dict[str, Any]) -> Optional[str]:
    method = client.get("method")
    pwd = client.get("password")
    if not (method and pwd): return None
    stream = jload(inbound.get("stream_settings"))
    host = server_host(stream)
    port = str(inbound.get("port"))
    from urllib.parse import quote
    userinfo = base64.urlsafe_b64encode(f"{method}:{pwd}".encode()).decode().rstrip("=")
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"ss://{userinfo}@{host}:{port}#{tag}"

def build_best(inbound: Dict[str, Any], client: Dict[str, Any]) -> Dict[str, Any]:
    proto = (inbound.get("protocol") or "").lower()
    out = {
        "protocol": proto,
        "vless_link": None,
        "vmess_link": None,
        "vmess_json": None,
        "trojan_link": None,
        "ss_link": None,
        "config_text": "",
        "config_filename": "",
        "qr_datauri": None
    }
    link = ""
    if proto == "vless":
        link = out["vless_link"] = build_vless(client, inbound)
        out["config_filename"] = f"{client.get('email','user')}_vless.txt"
    elif proto == "vmess":
        link, vmj = build_vmess(client, inbound)
        out["vmess_link"] = link
        out["vmess_json"] = vmj
        out["config_filename"] = f"{client.get('email','user')}_vmess.txt"
    elif proto == "trojan":
        link = out["trojan_link"] = build_trojan(client, inbound)
        out["config_filename"] = f"{client.get('email','user')}_trojan.txt"
    elif proto == "shadowsocks":
        link = out["ss_link"] = build_ss(client, inbound) or ""
        out["config_filename"] = f"{client.get('email','user')}_ss.txt"
    else:
        link = out["vless_link"] = build_vless(client, inbound)
        out["protocol"] = "vless"
        out["config_filename"] = f"{client.get('email','user')}_config.txt"
    out["config_text"] = link
    out["qr_datauri"] = qr_data_uri(link) if link else None
    return out
PYEOF

echo "Writing app.py..."
cat > app.py <<'EOL'
from flask import Flask, request, render_template, jsonify, send_file
import sqlite3, json, os, base64, io, psutil, requests, time, shutil, subprocess
from datetime import datetime
from tx_builders import build_best   # NEW: centralized builders

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
        client = json.loads(row[5]) if row[5] else {}

        built = build_best(inbound, client)
        # Keep filename UX with username prefix
        if built.get("config_filename") and username not in built["config_filename"]:
            proto = (built.get("protocol") or "config").lower()
            built["config_filename"] = f"{username}_{proto}.txt"

        return jsonify({"username": username, **built})
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
