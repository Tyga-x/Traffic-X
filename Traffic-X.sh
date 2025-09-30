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

# ---------------- Menu ----------------
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

# ---------------- Prompts ----------------
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

# ---------------- System deps ----------------
echo "Updating packages..."
sudo apt update

echo "Installing required dependencies..."
sudo apt install -y python3-pip python3-venv git sqlite3 socat unzip curl

# ---------------- Pull project ----------------
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

# ---------------- Python venv ----------------
echo "Setting up virtualenv..."
cd /home/$USERNAME/Traffic-X || exit 1
python3 -m venv venv
source venv/bin/activate

echo "Installing Python deps..."
pip install --upgrade pip
# NOTE: qrcode[pil] adds QR generation; rest unchanged
pip install flask gunicorn psutil requests qrcode[pil]

# ---------------- SSL (same behavior as your script) ----------------
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

# ---------------- app.py (kept minimal; calls tx_builders.py) ----------------
echo "Writing app.py..."
cat > app.py <<'EOP'
from flask import Flask, request, render_template, jsonify, send_file
import sqlite3, json, os, io, psutil, requests
from datetime import datetime
from tx_builders import build_best

app = Flask(__name__)
DB_PATH = os.getenv("DB_PATH", "/etc/x-ui/x-ui.db")

def convert_bytes(byte_size):
    if byte_size is None: return "0 Bytes"
    if byte_size < 1024: return f"{byte_size} Bytes"
    if byte_size < 1024*1024: return f"{round(byte_size/1024,2)} KB"
    if byte_size < 1024*1024*1024: return f"{round(byte_size/(1024*1024),2)} MB"
    if byte_size < 1024*1024*1024*1024: return f"{round(byte_size/(1024*1024*1024),2)} GB"
    return f"{round(byte_size/(1024*1024*1024*1024),2)} TB"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/usage', methods=['POST'])
def usage():
    try:
        user_input = request.form.get('user_input')
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""SELECT email, up, down, total, expiry_time, inbound_id
                       FROM client_traffics WHERE email=? OR id=?""", (user_input, user_input))
        row = cur.fetchone()
        if not row:
            conn.close()
            return "No data found for this user."
        email, up, down, total, expiry_time, inbound_id = row

        expiry_date = "Invalid Date"
        if expiry_time and isinstance(expiry_time, (int, float)):
            ts = expiry_time / 1000 if expiry_time > 9999999999 else expiry_time
            try: expiry_date = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            except Exception: expiry_date = "Invalid Date"

        cur.execute("SELECT settings FROM inbounds WHERE id=?", (inbound_id,))
        inbound_row = cur.fetchone()
        totalGB = "Not Available"; user_status = "Disabled"
        if inbound_row:
            try:
                inbound_data = json.loads(inbound_row[0])
                for c in inbound_data.get('clients', []):
                    if c.get('email') == email:
                        totalGB = c.get('totalGB', "Not Available")
                        user_status = "Enabled" if c.get('enable', True) else "Disabled"
                        break
            except Exception:
                totalGB = "Invalid JSON Data"
        conn.close()

        return render_template('result.html',
            email=email,
            up=convert_bytes(up),
            down=convert_bytes(down),
            total=convert_bytes(total),
            expiry_date=expiry_date,
            totalGB=convert_bytes(totalGB) if totalGB!="Not Available" else totalGB,
            user_status=user_status
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user_config')
def user_config():
    username = request.args.get('username','').strip()
    if not username: return jsonify({"error":"username required"}), 400
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
          SELECT i.id, i.protocol, i.port, i.remark, i.stream_settings, i.settings, c.value
            FROM inbounds i, json_each(json_extract(i.settings,'$.clients')) c
           WHERE json_extract(c.value,'$.email') = ?
           LIMIT 1
        """, (username,))
        row = cur.fetchone(); conn.close()
        if not row: return jsonify({"error":"user not found"}), 404

        inbound = {
            "id": row[0], "protocol": row[1], "port": row[2], "remark": row[3],
            "stream_settings": row[4], "settings": row[5]
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
    username = request.args.get('username','').strip()
    if not username: return jsonify({"error":"username required"}), 400
    with app.test_client() as c:
        r = c.get(f"/user_config?username={username}")
    if r.status_code != 200: return r
    j = r.get_json() or {}
    text = j.get("config_text",""); name = j.get("config_filename","config.txt")
    buf = io.BytesIO(text.encode()); buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=name, mimetype="text/plain")

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
        data = requests.get("http://ip-api.com/json/", timeout=5).json()
        return jsonify({"country": data.get("country","Unknown"), "city": data.get("city","Unknown"), "ip": data.get("query","Unknown")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/ping')
def ping():
    return jsonify({"status":"success","message":"Pong!"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT","5000")), debug=False)
EOP

# ---------------- tx_builders.py (separate module) ----------------
echo "Writing tx_builders.py..."
cat > tx_builders.py <<'EOP'
import os, json, base64, io
from urllib.parse import quote, urlencode
from typing import Any, Dict, Optional
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

def _arr_first(x): 
    return x[0] if isinstance(x, list) and x else x

def _norm(v):
    if isinstance(v, bool): return "1" if v else "0"
    return "" if v is None else str(v)

def _qr_data_uri(text: str) -> Optional[str]:
    if not (qrcode and text): return None
    qr = qrcode.QRCode(border=1); qr.add_data(text); qr.make(fit=True)
    img = qr.make_image(); buf = io.BytesIO(); img.save(buf, format="PNG")
    import base64 as b64
    return "data:image/png;base64," + b64.b64encode(buf.getvalue()).decode()

def _get_network(stream): return (stream.get("network") or "tcp").lower()
def _get_security(stream):
    sec = (stream.get("security") or "").lower()
    return sec if sec in ("tls","reality","xtls","none") else "none"

def _tls_settings(stream): return stream.get("tlsSettings") or {}
def _reality_settings(stream): return stream.get("realitySettings") or {}
def _ws_settings(stream): return stream.get("wsSettings") or {}
def _grpc_settings(stream): return stream.get("grpcSettings") or {}
def _tcp_settings(stream): return stream.get("tcpSettings") or {}
def _kcp_settings(stream): return stream.get("kcpSettings") or {}
def _quic_settings(stream): return stream.get("quicSettings") or {}
def _http_settings(stream): return stream.get("httpSettings") or {}
def _xhttp_settings(stream): return stream.get("xhttpSettings") or {}

def _external_proxy_dest(stream):
    ext = stream.get("externalProxy")
    if isinstance(ext, list) and ext and isinstance(ext[0], dict):
        d = ext[0].get("dest")
        if d: return str(d)
    return None

def _get_network_path(stream, network):
    if network == "tcp":
        tcp = _tcp_settings(stream); hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http":
            req = tcp.get("request") or {}; return _arr_first(req.get("path")) or "/"
        return "/"
    if network == "ws":
        return (_ws_settings(stream) or {}).get("path") or "/"
    if network in ("http","xhttp"):
        hs = _http_settings(stream); xhs = _xhttp_settings(stream)
        if hs.get("path"): return _arr_first(hs.get("path")) or "/"
        if xhs.get("path"): return xhs.get("path") or "/"
        return "/"
    if network == "grpc":
        return (_grpc_settings(stream) or {}).get("serviceName") or ""
    if network == "kcp":
        return (_kcp_settings(stream) or {}).get("seed") or ""
    if network == "quic":
        return (_quic_settings(stream) or {}).get("key") or ""
    return "/"

def _get_network_host(stream, network):
    if network == "tcp":
        tcp = _tcp_settings(stream); hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http":
            req = tcp.get("request") or {}; headers = req.get("headers") or {}
            return _arr_first(headers.get("Host")) or ""
        return ""
    if network == "ws":
        ws = _ws_settings(stream); return ws.get("host") or (ws.get("headers") or {}).get("Host") or ""
    if network in ("http","xhttp"):
        hs = _http_settings(stream); xhs = _xhttp_settings(stream)
        if xhs.get("host"): return xhs.get("host")
        h = hs.get("host"); return _arr_first(h) if isinstance(h, list) else (h or "")
    return ""

def _server_host(stream, inbound_settings):
    return (_external_proxy_dest(stream)
            or _tls_settings(stream).get("serverName")
            or _get_network_host(stream,"ws")
            or inbound_settings.get("domain")
            or inbound_settings.get("host")
            or inbound_settings.get("address")
            or FALLBACK_DOMAIN)

def _client_id(client):
    return client.get("id") or client.get("uuid") or client.get("password") or ""

def _gather_tls_params(stream):
    out = {}
    tls = _tls_settings(stream)
    if tls.get("serverName"): out["sni"] = _norm(tls["serverName"])
    fp = tls.get("fingerprint") or tls.get("fp")
    if fp: out["fp"] = _norm(fp)
    alpn = tls.get("alpn")
    if isinstance(alpn, list) and alpn: out["alpn"] = ",".join(map(str, alpn))
    elif isinstance(alpn, str) and alpn: out["alpn"] = alpn
    ain = tls.get("allowInsecure") or (tls.get("settings") or {}).get("allowInsecure")
    if ain is not None: out["allowInsecure"] = _norm(ain)
    return out

def _gather_reality_params(stream):
    out = {}
    rs = _reality_settings(stream)
    if rs.get("publicKey"): out["pbk"] = _norm(rs["publicKey"])
    if rs.get("shortId"): out["sid"] = _norm(rs["shortId"])
    if rs.get("spiderX"): out["spx"] = _norm(rs["spiderX"])
    if rs.get("fingerprint"): out["fp"] = _norm(rs["fingerprint"])
    return out

def build_vless(client, inbound):
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings"))
    net = _get_network(stream); sec = _get_security(stream)
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    uid = _client_id(client)

    # xhttp: special encoding
    if net == "xhttp":
        network_host = _get_network_host(stream, "xhttp") or host
        raw_path = _get_network_path(stream, "xhttp") or "/"
        from urllib.parse import quote
        double_encoded = quote(quote(raw_path)).lower()
        q = {
            "security":"none","encryption":"", "headerType":"",
            "type":"xhttp", "host":network_host, "path":double_encoded
        }
        tag = quote(client.get("email") or inbound.get("remark") or "node")
        return f"vless://{uid}@{host}:{port}/?{urlencode({k:v for k,v in q.items() if v is not None})}#{tag}"

    params = {"type": net, "encryption": "none", "path": _get_network_path(stream, net)}
    network_host = _get_network_host(stream, net)
    if network_host: params["host"] = network_host

    if net == "tcp":
        tcp = _tcp_settings(stream); hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http": params["headerType"] = "http"
    if net == "grpc":
        gs = _grpc_settings(stream)
        params["mode"] = "multi" if gs.get("multiMode") else "gun"
        if gs.get("serviceName"): params["serviceName"] = gs["serviceName"]
    if net == "kcp":
        ks = _kcp_settings(stream)
        params["headerType"] = (ks.get("header") or {}).get("type") or "none"
        if ks.get("seed"): params["seed"] = ks["seed"]
    if net == "quic":
        qs = _quic_settings(stream)
        params["quicSecurity"] = qs.get("security") or "none"
        params["key"] = qs.get("key") or ""
        params["headerType"] = (qs.get("header") or {}).get("type") or "none"

    if sec == "tls":
        params["security"] = "tls"; params.update(_gather_tls_params(stream))
    elif sec == "reality":
        params["security"] = "reality"; params.update(_gather_reality_params(stream))
    else:
        params["security"] = "none"

    flow = client.get("flow") or inbound_settings.get("flow")
    if flow: params["flow"] = str(flow)

    ordered = ["type","security","encryption","path","host","headerType","mode","serviceName","flow","seed","quicSecurity","key","alpn","sni","fp","allowInsecure"]
    tmp = params.copy()
    kv = [(k, tmp.pop(k)) for k in ordered if k in tmp] + list(tmp.items())
    enc = "&".join(f"{quote(str(k))}={quote(str(v))}" for k,v in kv if v not in (None,""))
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"vless://{uid}@{host}:{port}?{enc}#{tag}"

def build_vmess(client, inbound):
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings"))
    net = _get_network(stream); sec = _get_security(stream)
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    uid = _client_id(client)
    path = _get_network_path(stream, net)

    vm = {
        "v": "2",
        "ps": client.get("email") or inbound.get("remark") or "node",
        "add": host,
        "port": port,
        "id": uid,
        "aid": 0,
        "net": net,
        "type": "none",
        "path": path,
        "tls": "tls" if sec=="tls" else ("reality" if sec=="reality" else "none"),
    }

    if net == "tcp":
        tcp = _tcp_settings(stream); hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http":
            vm["type"] = "http"
            req = tcp.get("request") or {}; headers = req.get("headers") or {}
            h = _arr_first(headers.get("Host")) if isinstance(headers.get("Host"), list) else headers.get("Host")
            if h: vm["host"] = h
    elif net == "ws":
        ws = _ws_settings(stream); h = ws.get("host") or (ws.get("headers") or {}).get("Host") or ""
        if h: vm["host"] = h
    elif net == "grpc":
        gs = _grpc_settings(stream); vm["type"] = "multi" if gs.get("multiMode") else "gun"
        if gs.get("serviceName"): vm["servicename"] = gs["serviceName"]
    elif net == "kcp":
        ks = _kcp_settings(stream); vm["type"] = (ks.get("header") or {}).get("type") or "none"
    elif net == "quic":
        qs = _quic_settings(stream); vm["type"] = (qs.get("header") or {}).get("type") or "none"; vm["host"] = qs.get("security") or "none"
    elif net in ("http","xhttp"):
        hs = _http_settings(stream); xhs = _xhttp_settings(stream); vm["type"] = "http"
        h = xhs.get("host") or hs.get("host"); h = _arr_first(h) if isinstance(h,list) else h
        if h: vm["host"] = h

    tls_params = _gather_tls_params(stream)
    if "sni" in tls_params: vm["sni"] = tls_params["sni"]
    if "fp" in tls_params: vm["fp"] = tls_params["fp"]
    if "alpn" in tls_params: vm["alpn"] = tls_params["alpn"]
    if "allowInsecure" in tls_params: vm["allowInsecure"] = tls_params["allowInsecure"]

    if sec == "reality":
        r = _gather_reality_params(stream)
        if r.get("pbk"): vm["pbk"] = r["pbk"]
        if r.get("sid"): vm["sid"] = r["sid"]
        if r.get("spx"): vm["spx"] = r["spx"]
        if r.get("fp"):  vm["fp"]  = r["fp"]

    b64 = base64.b64encode(json.dumps(vm, separators=(",",":")).encode()).decode()
    return "vmess://" + b64, vm

def build_trojan(client, inbound):
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings"))
    net = _get_network(stream); sec = _get_security(stream)
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    pwd = _client_id(client)

    params = {"type": net, "path": _get_network_path(stream, net)}
    h = _get_network_host(stream, net)
    if h: params["host"] = h

    if net == "grpc":
        gs = _grpc_settings(stream)
        params["mode"] = "multi" if gs.get("multiMode") else "gun"
        if gs.get("serviceName"): params["serviceName"] = gs["serviceName"]
    if net == "tcp":
        tcp = _tcp_settings(stream); hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http": params["headerType"] = "http"

    if sec == "tls":
        params["security"] = "tls"; params.update(_gather_tls_params(stream))
    elif sec == "reality":
        params["security"] = "reality"; params.update(_gather_reality_params(stream))

    ordered = ["security","sni","alpn","fp","allowInsecure","type","path","host","mode","serviceName","headerType"]
    tmp = params.copy()
    kv = [(k, tmp.pop(k)) for k in ordered if k in tmp] + list(tmp.items())
    enc = "&".join(f"{quote(str(k))}={quote(str(v))}" for k,v in kv if v not in (None,""))
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"trojan://{pwd}@{host}:{port}?{enc}#{tag}"

def build_ss(client, inbound):
    inbound_settings = _jload(inbound.get("settings"))
    host = _server_host(_jload(inbound.get("stream_settings")), inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    method = client.get("method") or inbound_settings.get("method")
    pwd = client.get("password") or inbound_settings.get("password")
    if not (method and pwd): return None
    userinfo = base64.urlsafe_b64encode(f"{method}:{pwd}".encode()).decode().rstrip("=")
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"ss://{userinfo}@{host}:{port}#{tag}"

def build_best(inbound, client):
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
    if proto == "vless":
        link = out["vless_link"] = build_vless(client, inbound)
        out["config_text"] = link; out["config_filename"] = f"{client.get('email','user')}_vless.txt"
    elif proto == "vmess":
        link, vmj = build_vmess(client, inbound)
        out["vmess_link"] = link; out["vmess_json"] = vmj
        out["config_text"] = link; out["config_filename"] = f"{client.get('email','user')}_vmess.txt"
    elif proto == "trojan":
        link = out["trojan_link"] = build_trojan(client, inbound)
        out["config_text"] = link; out["config_filename"] = f"{client.get('email','user')}_trojan.txt"
    elif proto in ("shadowsocks","ss"):
        link = out["ss_link"] = build_ss(client, inbound)
        out["config_text"] = link or ""; out["config_filename"] = f"{client.get('email','user')}_ss.txt"
    else:
        link = out["vless_link"] = build_vless(client, inbound)
        out["config_text"] = link; out["config_filename"] = f"{client.get('email','user')}_config.txt"; out["protocol"] = "vless"
    if out["config_text"] and qrcode:
        out["qr_datauri"] = _qr_data_uri(out["config_text"])
    return out
EOP

# ---------------- Permissions + service ----------------
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

echo "Installation complete! Your server is running at http://$SERVER_IP:$PORT"
if [ -n "$SSL_CONTEXT" ]; then
    echo "SSL is enabled. Access the app securely at https://$SERVER_IP:$PORT"
else
    echo "SSL is disabled. Access the app at http://$SERVER_IP:$PORT"
fi
