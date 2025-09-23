#!/usr/bin/env bash
set -euo pipefail

# Traffic-X universal installer
# Works on Ubuntu 20.04/22.04/24.04 without 80/443 by using DNS-01 (Cloudflare).
# Author: you; License: MIT

### ---- Preconditions ---------------------------------------------------------
if ! command -v lsb_release >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y lsb-release
fi
DISTRO=$(lsb_release -si || echo Ubuntu)
RELEASE=$(lsb_release -sr || echo 22.04)
if [[ "$DISTRO" != "Ubuntu" ]]; then
  echo "This installer targets Ubuntu. Detected: $DISTRO $RELEASE"
fi

if ! pidof systemd >/dev/null 2>&1; then
  echo "systemd not found/running. Aborting."
  exit 1
fi

### ---- Menu -----------------------------------------------------------------
show_menu() {
  echo "Welcome to Traffic-X Installer/Uninstaller"
  echo "Please choose an option:"
  echo "1. Run Traffic-X (Install)"
  echo "2. Uninstall Traffic-X"
  echo "3. Exit"
}
while true; do
  show_menu
  read -r -p "Enter your choice [1-3]: " CHOICE
  case "$CHOICE" in
    1) echo "Proceeding with Traffic-X installation..."; break;;
    2) bash <(curl -s https://raw.githubusercontent.com/Tyga-x/Traffic-X/main/rm-TX.sh); exit 0;;
    3) exit 0;;
    *) echo "Invalid choice. Please select a valid option [1-3].";;
  esac
done

### ---- Inputs ----------------------------------------------------------------
read -r -p "Enter your server domain (e.g. example.com): " DOMAIN
DOMAIN=${DOMAIN:-}
if [[ -z "$DOMAIN" ]]; then echo "Domain is required."; exit 1; fi

read -r -p "Enter the port (default: 5000): " PORT
PORT=${PORT:-5000}

# Optional Cloudflare DNS-01 (recommended). If empty, we’ll do self-signed.
echo "If you use Cloudflare and want valid SSL on ANY port, provide:"
read -r -p "  Cloudflare API Token (optional, empty to skip): " CF_TOKEN
# (Token needs Zone:DNS:Edit at minimum for your zone)

read -r -p "Enter the version (e.g., v1.0.1) or leave blank for latest: " VERSION
VERSION=${VERSION:-latest}

### ---- Warn about Cloudflare port policy ------------------------------------
cat <<'NOTE'

Heads up on Cloudflare:
- If your DNS record is proxied (orange cloud), HTTP/HTTPS only pass on specific ports.
- Common HTTPS ports that work via proxy: 443, 2053, 2083, 2087, 2096, 8443.
- Port 5000 does NOT proxy. If you must keep orange-cloud, pick 2053/2083/8443/etc.
- If you want any random port (e.g., 5000), set the DNS record to "DNS only" (gray cloud).

NOTE

### ---- Create a service user safely ------------------------------------------
# Don’t assume 'ubuntu' exists. Create/use 'trafficx' system user.
SERVICE_USER=trafficx
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
SERVICE_HOME=$(getent passwd "$SERVICE_USER" | cut -d: -f6)
APP_DIR="$SERVICE_HOME/Traffic-X"
LOG_FILE="/var/log/traffic-x.log"
CERT_DIR="/var/lib/Traffic-X/certs"
DB_PATH="/etc/x-ui/x-ui.db"

### ---- Packages ---------------------------------------------------------------
echo "Updating packages..."
apt-get update -y
echo "Installing dependencies..."
apt-get install -y python3 python3-venv python3-pip git unzip curl socat sqlite3

### ---- Fetch app --------------------------------------------------------------
echo "Downloading Traffic-X $VERSION ..."
if [[ "$VERSION" == "latest" ]]; then
  DL_URL="https://github.com/Tyga-x/Traffic-X/archive/refs/heads/main.zip"
else
  DL_URL="https://github.com/Tyga-x/Traffic-X/archive/refs/tags/$VERSION.zip"
fi

TMP_ZIP="/tmp/Traffic-X.zip"
curl -fL "$DL_URL" -o "$TMP_ZIP"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"
unzip -q "$TMP_ZIP" -d "$SERVICE_HOME"
EXTRACTED_DIR=$(find "$SERVICE_HOME" -maxdepth 1 -type d -name "Traffic-X*" | head -n1)
rsync -a "$EXTRACTED_DIR"/ "$APP_DIR"/
rm -f "$TMP_ZIP"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$APP_DIR"

# Ensure templates present
if [[ ! -d "$APP_DIR/templates" ]]; then
  echo "Templates directory missing in repo. Aborting."
  exit 1
fi

### ---- Python venv ------------------------------------------------------------
echo "Setting up virtual environment..."
sudo -u "$SERVICE_USER" python3 -m venv "$APP_DIR/venv"
sudo -u "$SERVICE_USER" bash -lc "$APP_DIR/venv/bin/pip install --upgrade pip"
sudo -u "$SERVICE_USER" bash -lc "$APP_DIR/venv/bin/pip install flask gunicorn psutil requests"

### ---- Cert directory ---------------------------------------------------------
mkdir -p "$CERT_DIR"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$CERT_DIR"

### ---- TLS with no 80/443: DNS-01 via Cloudflare or self-signed --------------
CERT_FILE="$CERT_DIR/$DOMAIN.cer"
KEY_FILE="$CERT_DIR/$DOMAIN.cer.key"
USE_TLS=0

if [[ -n "$CF_TOKEN" ]]; then
  echo "Attempting Let’s Encrypt via DNS-01 (Cloudflare)…"
  # Install acme.sh if needed
  if [[ ! -x "/root/.acme.sh/acme.sh" ]]; then
    curl https://get.acme.sh | sh -s email="admin@$DOMAIN"
  fi
  export CF_Token="$CF_TOKEN"
  export CF_Account_ID=""   # not required for token-only global API token
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  # Use dns_cf (no port 80/443 needed)
  /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --keylength ec-256 \
    --fullchain-file "$CERT_FILE" --key-file "$KEY_FILE" || true

  if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
    echo "DNS-01 certificate issued."
    chown "$SERVICE_USER":"$SERVICE_USER" "$CERT_FILE" "$KEY_FILE"
    USE_TLS=1
  else
    echo "DNS-01 issuance failed. Will fall back to self-signed."
  fi
fi

if [[ "$USE_TLS" -eq 0 ]]; then
  echo "Generating self-signed TLS cert (fallback)…"
  openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
    -keyout "$KEY_FILE" -out "$CERT_FILE" -days 365 \
    -subj "/CN=$DOMAIN"
  chown "$SERVICE_USER":"$SERVICE_USER" "$CERT_FILE" "$KEY_FILE"
  USE_TLS=1
fi

### ---- Write robust app.py ----------------------------------------------------
# Replace the app with a resilient version (env-driven DB path, safer conversions)
cat > "$APP_DIR/app.py" <<'PY'
from flask import Flask, request, render_template, jsonify
import os, sqlite3, json, psutil, requests
from datetime import datetime

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "/etc/x-ui/x-ui.db")

def convert_bytes(val):
    try:
        if val is None: return "0 Bytes"
        b = int(val)
        units = ["Bytes", "KB", "MB", "GB", "TB"]
        i = 0
        while b >= 1024 and i < len(units)-1:
            b /= 1024.0
            i += 1
        return f"{round(b, 2)} {units[i]}"
    except Exception:
        return "0 Bytes"

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/usage", methods=["POST"])
def usage():
    user_input = request.form.get("user_input","").strip()
    if not user_input:
        return "Empty input.", 400
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        cur = conn.cursor()
        # accept id (numeric) OR email
        q = """SELECT email, up, down, total, expiry_time, inbound_id
               FROM client_traffics
               WHERE email = ? OR id = ?"""
        maybe_id = None
        try:
            maybe_id = int(user_input)
        except Exception:
            maybe_id = -1
        cur.execute(q, (user_input, maybe_id))
        row = cur.fetchone()
        if not row:
            conn.close()
            return "No data found for this user.", 404

        email, up, down, total, expiry_time, inbound_id = row

        # expiry timestamp in ms or s
        expiry_date = "Invalid Date"
        if isinstance(expiry_time, (int, float)):
            ts = expiry_time / 1000 if expiry_time > 9999999999 else expiry_time
            try:
                expiry_date = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                expiry_date = "Invalid Date"

        totalGB = "Not Available"
        user_status = "Disabled"
        cur.execute("SELECT settings FROM inbounds WHERE id = ?", (inbound_id,))
        inbound_row = cur.fetchone()
        if inbound_row and inbound_row[0]:
            try:
                inbound_data = json.loads(inbound_row[0])
                for c in inbound_data.get("clients", []):
                    if c.get("email") == email:
                        totalGB = c.get("totalGB", "Not Available")
                        user_status = "Enabled" if c.get("enable", True) else "Disabled"
                        break
            except Exception:
                totalGB = "Invalid JSON Data"

        conn.close()
        return render_template(
            "result.html",
            email=email,
            up=convert_bytes(up),
            down=convert_bytes(down),
            total=convert_bytes(total),
            expiry_date=expiry_date,
            totalGB=convert_bytes(totalGB) if isinstance(totalGB,(int,float,str)) and str(totalGB).isdigit() else totalGB,
            user_status=user_status
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/server-status")
def server_status():
    try:
        return jsonify({
            "cpu": psutil.cpu_percent(interval=1),
            "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/server-location")
def server_location():
    try:
        r = requests.get("http://ip-api.com/json/", timeout=5)
        d = r.json()
        return jsonify({
            "country": d.get("country","Unknown"),
            "city": d.get("city","Unknown"),
            "ip": d.get("query","Unknown")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/ping")
def ping():
    return jsonify({"status":"success","message":"Pong!"})

PY
chown "$SERVICE_USER":"$SERVICE_USER" "$APP_DIR/app.py"

### ---- Permissions for x-ui DB (readable by service) -------------------------
if [[ -f "$DB_PATH" ]]; then
  chmod 644 "$DB_PATH" || true
  chown root:root "$DB_PATH" || true
fi

### ---- Systemd unit (correct var expansion & TLS flags) ----------------------
# We avoid single quotes so variables expand; we pass certs via Environment=.
SERVICE_FILE="/etc/systemd/system/traffic-x.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Traffic-X Web App
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
Environment=DB_PATH=$DB_PATH
Environment=PORT=$PORT
Environment=DOMAIN=$DOMAIN
Environment=CERT_FILE=$CERT_FILE
Environment=KEY_FILE=$KEY_FILE
ExecStart=$APP_DIR/venv/bin/gunicorn -w 4 -b 0.0.0.0:\${PORT} \\
  --certfile "\${CERT_FILE}" --keyfile "\${KEY_FILE}" app:app
Restart=always
RestartSec=2
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE

[Install]
WantedBy=multi-user.target
EOF

touch "$LOG_FILE"
chown "$SERVICE_USER":"$SERVICE_USER" "$LOG_FILE"

systemctl daemon-reload
systemctl enable traffic-x
systemctl restart traffic-x

echo
echo "Installation complete!"
echo "App URL (HTTPS): https://$DOMAIN:$PORT"
echo "Certs: $CERT_FILE  $KEY_FILE"
echo "Log:   $LOG_FILE"
