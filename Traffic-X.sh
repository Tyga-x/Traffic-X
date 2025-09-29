#!/bin/bash
# === Traffic-X (Final) — Installer/Updater with SSL preserved + tx_builders integration ===
# Keeps your original flow, adds robust /user_config powered by tx_builders.py

set -e

show_menu() {
    echo "Welcome to Traffic-X Installer/Uninstaller"
    echo "Please choose an option:"
    echo "1. Run Traffic-X (Install/Update)"
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

echo "Enter your OS username (default: root):"
read USERNAME
USERNAME=${USERNAME:-root}

echo "Enter your server domain or IP (e.g., my.domain.com):"
read SERVER_IP
if [ -z "$SERVER_IP" ]; then
  echo "A domain or IP is required."
  exit 1
fi

echo "Enter the port (default: 5000):"
read PORT
PORT=${PORT:-5000}

echo "Updating packages..."
apt update -y

echo "Installing required dependencies..."
apt install -y python3-pip python3-venv git sqlite3 socat unzip curl

# App dir
APP_DIR="/home/$USERNAME/Traffic-X"
[ "$USERNAME" = "root" ] && APP_DIR="/root/Traffic-X"
mkdir -p "$APP_DIR"
cd "$APP_DIR"

echo "Setting up virtualenv..."
python3 -m venv venv
source venv/bin/activate

echo "Installing Python deps..."
pip install --upgrade pip
# NOTE: qrcode[pil] is needed for QR generation
pip install flask gunicorn psutil requests qrcode[pil]

# ===== SSL (kept from your flow) =====
echo "Configuring SSL (optional/auto with acme.sh)..."
export DOMAIN="$SERVER_IP"
CERT_DIR="/var/lib/Traffic-X/certs"
mkdir -p "$CERT_DIR"
chown -R $USERNAME:$USERNAME "$CERT_DIR"

SSL_CERT="$CERT_DIR/$DOMAIN.cer"
SSL_KEY="$CERT_DIR/$DOMAIN.cer.key"
SSL_CONTEXT=""

if [ -f "$SSL_CERT" ] && [ -f "$SSL_KEY" ]; then
    echo "Existing cert found."
    SSL_CONTEXT="--certfile=$SSL_CERT --keyfile=$SSL_KEY"
else
    echo "Attempting to issue cert via acme.sh..."
    curl https://get.acme.sh | sh -s email=$USERNAME@$SERVER_IP
    ~/.acme.sh/acme.sh --issue --force --standalone -d "$DOMAIN" \
        --fullchain-file "$SSL_CERT" \
        --key-file "$SSL_KEY" || true
    chown $USERNAME:$USERNAME "$SSL_CERT" "$SSL_KEY" || true
    if [ -f "$SSL_CERT" ] && [ -f "$SSL_KEY" ]; then
        SSL_CONTEXT="--certfile=$SSL_CERT --keyfile=$SSL_KEY"
    else
        echo "SSL issuance failed or skipped. Running without SSL."
        SSL_CONTEXT=""
    fi
fi

echo "Writing tx_builders.py..."
cat > tx_builders.py <<'PYEOF'
# tx_builders.py — robust builders for VLESS / VMess / Trojan / SS with full Xray/XUI options
import os, json, base64, io
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote
try:
    import qrcode
except Exception:
    qrcode = None

FALLBACK_DOMAIN = os.getenv("DOMAIN", "localhost")

def _jload(x: Any) -> Dict[str, Any]:
    if not x: return {}
    if isinstance(x, dict): return x
    try: return json.loads(x)
    except Exception:
        try: return json.loads(str(x).replace("'", '"'))
        except Exception: return {}

def _server_host(stream: Dict[str, Any], inbound_settings: Dict[str, Any]) -> str:
    tls = stream.get("tlsSettings", {}) or {}
    ws  = stream.get("wsSettings", {}) or {}
    if tls.get("serverName"): return tls["serverName"]
    if (ws.get("headers") or {}).get("Host"): return (ws.get("headers") or {})["Host"]
    for key in ("domain","host","address","serverName"):
        if inbound_settings.get(key): return inbound_settings[key]
    return FALLBACK_DOMAIN

def _client_id(client: Dict[str, Any]) -> str:
    return client.get("id") or client.get("uuid") or client.get("password") or ""

def _qr_data_uri(text: str) -> Optional[str]:
    if not (qrcode and text): return None
    qr = qrcode.QRCode(border=1); qr.add_data(text); qr.make(fit=True)
    img = qr.make_image(); buf = io.BytesIO(); img.save(buf, format="PNG")
    import base64 as _b64
    return "data:image/png;base64," + _b64.b64encode(buf.getvalue()).decode()

def _norm(v):
    if isinstance(v, bool): return "1" if v else "0"
    if v is None: return ""
    return str(v)

def _gather_extra_params(inbound_settings: Dict[str, Any], stream: Dict[str, Any], client: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    tls = stream.get("tlsSettings", {}) or {}
    alpn = tls.get("alpn")
    if isinstance(alpn, (list, tuple)) and alpn:
        out["alpn"] = ",".join(map(str, alpn))
    elif isinstance(alpn, str) and alpn:
        out["alpn"] = alpn
    if "allowInsecure" in tls:
        out["allowInsecure"] = _norm(tls["allowInsecure"])
    if "allowInsecure" in inbound_settings:
        out["allowInsecure"] = _norm(inbound_settings["allowInsecure"])
    for k in ("fp","fingerprint","flow","fallback","realityPublicKey"):
        if client.get(k) is not None: out[k] = _norm(client[k])
        elif inbound_settings.get(k) is not None: out[k] = _norm(inbound_settings[k])
    reserved = {"clients","stream_settings","sniffing"}
    for k,v in inbound_settings.items():
        if k in reserved: continue
        if isinstance(v,(dict,list)): continue
        out.setdefault(k,_norm(v))
    for k,v in client.items():
        if k in ("email","id","uuid","password"): continue
        if isinstance(v,(dict,list)): continue
        out.setdefault(k,_norm(v))
    return out

def build_vless(client: Dict[str, Any], inbound: Dict[str, Any]) -> str:
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings") or {})
    net = stream.get("network","tcp")
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    uid = _client_id(client)
    qs = {"type":net, "encryption":"none"}
    sec = stream.get("security") or inbound_settings.get("security") or "none"
    qs["security"] = sec
    if net == "ws":
        ws = stream.get("wsSettings", {}) or {}
        qs["path"] = ws.get("path","/")
        host_header = (ws.get("headers") or {}).get("Host")
        if host_header: qs["host"] = host_header
    if net == "grpc":
        g = stream.get("grpcSettings", {}) or {}
        svc = g.get("serviceName")
        if svc: qs.update({"mode":"gun","serviceName":svc})
    flow = client.get("flow") or inbound_settings.get("flow")
    if flow: qs["flow"] = str(flow)
    qs.update(_gather_extra_params(inbound_settings, stream, client))
    ordered_keys = ["type","security","encryption","path","host","mode","serviceName","flow"]
    ordered = []; [ordered.append((k,qs.pop(k))) for k in ordered_keys if k in qs]
    for k,v in qs.items(): ordered.append((k,v))
    encoded = "&".join(f"{quote(str(k))}={quote(str(v))}" for k,v in ordered if v is not None)
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"vless://{uid}@{host}:{port}?{encoded}#{tag}"

def build_vmess(client: Dict[str, Any], inbound: Dict[str, Any]):
    import base64 as _b64, json as _json
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings") or {})
    net = stream.get("network","tcp")
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    ws = stream.get("wsSettings", {}) or {}
    path = ws.get("path","/")
    sec = stream.get("security") or inbound_settings.get("security") or "none"
    vm = {
        "v":"2","ps": client.get("email") or inbound.get("remark") or "node",
        "add":host,"port":port,"id":_client_id(client),
        "aid": str(client.get("alterId") or client.get("aid") or 0),
        "net": net, "type": "none",
        "host": (ws.get("headers") or {}).get("Host",""),
        "path": path, "tls": "" if sec=="none" else sec
    }
    extras = _gather_extra_params(inbound_settings, stream, client)
    if extras: vm["_ext"] = extras
    b64 = _b64.b64encode(_json.dumps(vm, separators=(",",":")).encode()).decode()
    return "vmess://" + b64, vm

def build_trojan(client: Dict[str, Any], inbound: Dict[str, Any]) -> str:
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings") or {})
    net = stream.get("network","tcp")
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    pwd = _client_id(client)
    sec = stream.get("security") or inbound_settings.get("security") or "tls"
    qs = {"security": sec}
    tls = stream.get("tlsSettings", {}) or {}
    sni = tls.get("serverName") or inbound_settings.get("sni") or host
    if sni: qs["sni"] = sni
    if net == "ws":
        ws = stream.get("wsSettings", {}) or {}
        qs.update({"type":"ws","path":ws.get("path","/")})
        host_header = (ws.get("headers") or {}).get("Host")
        if host_header: qs["host"] = host_header
    elif net == "grpc":
        g = stream.get("grpcSettings", {}) or {}
        qs["type"] = "grpc"
        if g.get("serviceName"): qs["serviceName"] = g["serviceName"]
    qs.update(_gather_extra_params(inbound_settings, stream, client))
    ordered_keys = ["security","sni","alpn","type","path","host","serviceName"]
    ordered = []; [ordered.append((k,qs.pop(k))) for k in ordered_keys if k in qs]
    for k,v in qs.items(): ordered.append((k,v))
    encoded = "&".join(f"{quote(str(k))}={quote(str(v))}" for k,v in ordered if v is not None)
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"trojan://{pwd}@{host}:{port}?{encoded}#{tag}"

def build_ss(client: Dict[str, Any], inbound: Dict[str, Any]) -> Optional[str]:
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings") or {})
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    method = client.get("method") or inbound_settings.get("method")
    pwd = client.get("password") or inbound_settings.get("password")
    if not (method and pwd): return None
    import base64 as _b64
    userinfo = _b64.urlsafe_b64encode(f"{method}:{pwd}".encode()).decode().rstrip("=")
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"ss://{userinfo}@{host}:{port}#{tag}"

def build_best(inbound, client):
    proto = (inbound.get("protocol") or "").lower()
    res = {"protocol": proto, "vless_link": None, "vmess_link": None, "vmess_json": None,
           "trojan_link": None, "ss_link": None, "config_text": "", "config_filename": "", "qr_datauri": None}
    if proto == "vless":
        link = res["vless_link"] = build_vless(client, inbound)
        res["config_text"] = link; res["config_filename"] = f"{client.get('email','user')}_vless.txt"
    elif proto == "vmess":
        link, vmj = build_vmess(client, inbound)
        res["vmess_link"] = link; res["vmess_json"] = vmj
        res["config_text"] = link; res["config_filename"] = f"{client.get('email','user')}_vmess.txt"
    elif proto == "trojan":
        link = res["trojan_link"] = build_trojan(client, inbound)
        res["config_text"] = link; res["config_filename"] = f"{client.get('email','user')}_trojan.txt"
    elif proto in ("shadowsocks","ss"):
        link = res["ss_link"] = build_ss(client, inbound)
        res["config_text"] = link or ""; res["config_filename"] = f"{client.get('email','user')}_ss.txt"
    else:
        link = res["vless_link"] = build_vless(client, inbound)
        res["config_text"] = link; res["config_filename"] = f"{client.get('email','user')}_config.txt"
        res["protocol"] = "vless"
    if res["config_text"] and qrcode:
        res["qr_datauri"] = _qr_data_uri(res["config_text"])
    return res
PYEOF

echo "Writing app.py..."
cat > app.py <<'PYEOF'
from flask import Flask, request, render_template, jsonify, send_file
import sqlite3, json, os, io, psutil, requests
from datetime import datetime
from tx_builders import build_best

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

# ================== user_config (NEW, via tx_builders) ==================
@app.route("/user_config")
def user_config():
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

        built = build_best(inbound, client)
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
PYEOF

# Keep your templates folder (index.html/result.html) in the repo; app.py will render them.
mkdir -p templates

echo "Creating/Updating systemd service..."
LOG=/var/log/traffic-x.log
touch "$LOG"; chown "$USERNAME":"$USERNAME" "$LOG" || true

cat > /etc/systemd/system/traffic-x.service <<EOF
[Unit]
Description=Traffic-X Web App
After=network.target

[Service]
User=$USERNAME
WorkingDirectory=$APP_DIR
Environment="DB_PATH=/etc/x-ui/x-ui.db"
Environment="DOMAIN=$SERVER_IP"
Environment="PORT=$PORT"
# Expand SSL flags if present
ExecStart=/bin/bash -lc 'source $APP_DIR/venv/bin/activate && exec gunicorn -w 4 -b 0.0.0.0:$PORT $SSL_CONTEXT app:app'
Restart=always
RestartSec=5
StandardOutput=append:$LOG
StandardError=append:$LOG

[Install]
WantedBy=multi-user.target
EOF

echo "Fixing x-ui.db permissions..."
chmod 644 /etc/x-ui/x-ui.db || true
chown $USERNAME:$USERNAME /etc/x-ui/x-ui.db || true

systemctl daemon-reload
systemctl enable traffic-x
systemctl restart traffic-x

if [ -n "$SSL_CONTEXT" ]; then
  echo "✅ Done! HTTPS: https://$SERVER_IP:$PORT"
else
  echo "✅ Done! HTTP:  http://$SERVER_IP:$PORT"
fi
