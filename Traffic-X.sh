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


# Main menu logic
while true; do
show_menu
read -p "Enter your choice [1-3]: " CHOICE
case $CHOICE in
1)
echo "Proceeding with Traffic-X installation..."
break
;;
2)
echo "Uninstalling Traffic-X..."
bash <(curl -s https://raw.githubusercontent.com/Tyga-x/Traffic-X/main/rm-TX.sh)
echo "Traffic-X has been uninstalled."
exit 0
;;
3)
echo "Exiting..."
exit 0
;;
*)
echo "Invalid choice. Please select a valid option [1-3]."
;;
esac
done


# Ask user for necessary information
echo "Enter your OS username (e.g., ubuntu):"
read USERNAME
echo "Enter your server domain (e.g.your_domain.com):"
read SERVER_IP
echo "Enter the port (default: 5000):"
read PORT
PORT=${PORT:-5000}


# Ask user for the version to install
echo "Enter the version to install (e.g., v1.0.1) or leave blank for the latest version:"
read VERSION
if [ -z "$VERSION" ]; then
VERSION="latest"
fi


# Install required dependencies
echo "Updating packages..."
sudo apt update
fi

echo "Setting up Python virtual environment..."
cd /home/$USERNAME/Traffic-X
python3 -m venv venv
source venv/bin/activate

echo "Installing Flask, Gunicorn, and dependencies..."
pip install --upgrade pip
pip install flask gunicorn psutil requests

# Blitz needs pymongo (safe to install always)
if [ "$PANEL" = "blitz" ]; then
  pip install pymongo
fi

echo "Configuring domain..."
export DOMAIN=$SERVER_IP

# SSL folder
mkdir -p /var/lib/Traffic-X/certs
sudo chown -R $USERNAME:$USERNAME /var/lib/Traffic-X/certs

# SSL check / creation
if [ -f "/var/lib/Traffic-X/certs/$DOMAIN.cer" ] && [ -f "/var/lib/Traffic-X/certs/$DOMAIN.cer.key" ]; then
  echo "Valid SSL certificate already exists."
  SSL_CONTEXT="--certfile=/var/lib/Traffic-X/certs/$DOMAIN.cer --keyfile=/var/lib/Traffic-X/certs/$DOMAIN.cer.key"
else
  echo "Generating SSL certificate..."
  curl https://get.acme.sh | sh -s email=$USERNAME@$SERVER_IP
  ~/.acme.sh/acme.sh --issue --force --standalone -d "$DOMAIN" \
    --fullchain-file "/var/lib/Traffic-X/certs/$DOMAIN.cer" \
    --key-file "/var/lib/Traffic-X/certs/$DOMAIN.cer.key" || true
  sudo chown $USERNAME:$USERNAME /var/lib/Traffic-X/certs/$DOMAIN.cer || true
  sudo chown $USERNAME:$USERNAME /var/lib/Traffic-X/certs/$DOMAIN.cer.key || true
  if [ ! -f "/var/lib/Traffic-X/certs/$DOMAIN.cer" ] || [ ! -f "/var/lib/Traffic-X/certs/$DOMAIN.cer.key" ]; then
    echo "Failed to generate SSL certificates. Disabling SSL."
    SSL_CONTEXT=""
  else
    echo "SSL certificates generated successfully."
    SSL_CONTEXT="--certfile=/var/lib/Traffic-X/certs/$DOMAIN.cer --keyfile=/var/lib/Traffic-X/certs/$DOMAIN.cer.key"
  fi
fi

# Generate app.py (unified, switches by PANEL)
cat > app.py <<'EOL'
from flask import Flask, request, render_template, jsonify
import sqlite3, json, psutil, requests, os
from datetime import datetime

app = Flask(__name__)
PANEL = os.getenv("PANEL", "xui").lower()
db_path = os.getenv("DB_PATH", "/etc/x-ui/x-ui.db")  # X-UI default
PORT = int(os.getenv("PORT", "5000"))

def convert_bytes(byte_size):
    if byte_size is None: return "0 Bytes"
    if byte_size < 1024: return f"{byte_size} Bytes"
    if byte_size < 1024*1024: return f"{round(byte_size/1024,2)} KB"
    if byte_size < 1024*1024*1024: return f"{round(byte_size/(1024*1024),2)} MB"
    if byte_size < 1024*1024*1024*1024: return f"{round(byte_size/(1024*1024*1024),2)} GB"
    return f"{round(byte_size/(1024*1024*1024*1024),2)} TB"

def _ts_to_str(ts):
    if not ts: return "Invalid Date"
    try:
        n = float(ts); 
        if n > 9999999999: n /= 1000.0
        return datetime.utcfromtimestamp(n).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    try:
        return datetime.fromisoformat(str(ts).replace("Z","").replace("T"," ")).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Invalid Date"

def fetch_usage_xui(user_input):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    q = '''SELECT email, up, down, total, expiry_time, inbound_id
           FROM client_traffics WHERE email = ? OR id = ?'''
    cursor.execute(q, (user_input, user_input))
    row = cursor.fetchone()
    if not row:
        conn.close(); return None
    email, up, down, total, expiry_time, inbound_id = row
    expiry_date = _ts_to_str(expiry_time)

    cursor.execute('SELECT settings FROM inbounds WHERE id = ?', (inbound_id,))
    inbound_row = cursor.fetchone()
    totalGB = "Not Available"; user_status = "Disabled"
    if inbound_row:
        settings = inbound_row[0]
        try:
            inbound_data = json.loads(settings)
            for c in inbound_data.get('clients', []):
                if c.get('email') == email:
                    totalGB = c.get('totalGB', "Not Available")
                    user_status = "Enabled" if c.get('enable', True) else "Disabled"
                    break
        except json.JSONDecodeError:
            totalGB = "Invalid JSON Data"
    conn.close()
    return {
        "email": email,
        "up": convert_bytes(up),
        "down": convert_bytes(down),
        "total": convert_bytes(total),
        "expiry_date": expiry_date,
        "totalGB": convert_bytes(totalGB) if isinstance(totalGB,(int,float)) else totalGB,
        "user_status": user_status
    }

def fetch_usage_blitz(user_input):
    try:
        from pymongo import MongoClient
    except Exception:
        return None
    uri = os.getenv("MONGO_URI","mongodb://127.0.0.1:27017")
    dbn = os.getenv("MONGO_DB","blitz_panel")
    coln= os.getenv("MONGO_COLLECTION","users")
    client = MongoClient(uri, serverSelectionTimeoutMS=1500)
    try:
        client.admin.command("ping")
    except Exception:
        return None
    col = client[dbn][coln]
    doc = col.find_one({"$or":[
        {"email": str(user_input)},
        {"id": str(user_input)},
        {"username": str(user_input)},
        {"name": str(user_input)}
    ]})
    if not doc:
        return None

    def pick(d,*names,default=None):
        for n in names:
            if n in d and d[n] is not None: return d[n]
        for n in names:
            cur=d; ok=True
            for p in n.split("."):
                if isinstance(cur,dict) and p in cur: cur=cur[p]
                else: ok=False; break
            if ok and cur is not None: return cur
        return default
    def to_int(x):
        try:
            if x is None: return 0
            if isinstance(x,(int,float)): return int(x)
            return int(float(str(x)))
        except: return 0

    up_raw    = to_int(pick(doc,"up","upload","u","traffic.up",default=0))
    down_raw  = to_int(pick(doc,"down","download","d","traffic.down",default=0))
    total_raw = to_int(pick(doc,"total","quota","limit","traffic.total",default=0))
    enabled   = bool(pick(doc,"enable","enabled","active",default=True))
    expiry    = pick(doc,"expiry_time","expiry","expire","expire_at","expireAt",default=None)
    ident     = str(pick(doc,"email","id","username","name",default=user_input))

    return {
        "email": ident,
        "up": convert_bytes(up_raw),
        "down": convert_bytes(down_raw),
        "total": convert_bytes(total_raw),
        "expiry_date": _ts_to_str(expiry),
        "totalGB": "Not Available",
        "user_status": "Enabled" if enabled else "Disabled",
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/usage', methods=['POST'])
def usage():
    try:
        user_input = request.form.get('user_input')
        rec = fetch_usage_blitz(user_input) if PANEL == "blitz" else fetch_usage_xui(user_input)
        if not rec: return "No data found for this user."
        return render_template('result.html', **rec)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/update-status', methods=['POST'])
def update_status():
    try:
        data = request.get_json()
        new_status = bool(data.get('status'))
        # Optional persist for Blitz (needs user key sent from front-end)
        if PANEL == "blitz":
            try:
                from pymongo import MongoClient
                uri = os.getenv("MONGO_URI","mongodb://127.0.0.1:27017")
                dbn = os.getenv("MONGO_DB","blitz_panel")
                coln= os.getenv("MONGO_COLLECTION","users")
                key = data.get('user')
                if key:
                    MongoClient(uri)[dbn][coln].update_one(
                        {"$or":[{"email":key},{"id":key},{"username":key},{"name":key}]},
                        {"$set":{"enable": new_status}}
                    )
            except Exception:
                pass
        return jsonify({"status":"success","message":"Status updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/server-status')
def server_status():
    try:
        net = psutil.net_io_counters()
        return jsonify({
            "cpu": psutil.cpu_percent(interval=1),
            "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent,
            "net_sent": convert_bytes(net.bytes_sent),
            "net_recv": convert_bytes(net.bytes_recv)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/server-location')
def server_location():
    try:
        r = requests.get("http://ip-api.com/json/")
        d = r.json()
        return jsonify({"country": d.get("country","Unknown"),
                        "city": d.get("city","Unknown"),
                        "ip": d.get("query","Unknown")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/cloud-provider')
def cloud_provider():
    try:
        provider="Unknown"; p="/sys/class/dmi/id/sys_vendor"
        if os.path.exists(p):
            v=open(p).read().strip().lower()
            if "amazon" in v: provider="AWS"
            elif "digital" in v: provider="DigitalOcean"
            elif "linode" in v: provider="Linode"
            elif "google" in v: provider="Google Cloud"
        return jsonify({"provider": provider})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/ping')
def ping():
    return jsonify({"status":"success","message":"Pong!"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
EOL

# Permissions for X-UI DB (if using X-UI)
if [ "$PANEL" = "xui" ]; then
  echo "Setting permissions for the X-UI database file..."
  sudo chmod 644 /etc/x-ui/x-ui.db || true
  sudo chown $USERNAME:$USERNAME /etc/x-ui/x-ui.db || true
fi

# If service exists, stop before replacing
if sudo systemctl is-active --quiet traffic-x; then
  echo "Stopping existing Traffic-X service..."
  sudo systemctl stop traffic-x
fi

# Create systemd service
echo "Setting up systemd service..."
sudo tee /etc/systemd/system/traffic-x.service >/dev/null <<EOL
[Unit]
Description=Traffic-X Web App
After=network.target

[Service]
User=$USERNAME
WorkingDirectory=/home/$USERNAME/Traffic-X
ExecStart=/bin/bash -c 'source /home/$USERNAME/Traffic-X/venv/bin/activate && exec gunicorn -w 4 -b 0.0.0.0:$PORT $SSL_CONTEXT app:app'
Environment="PORT=$PORT"
Environment="PANEL=$PANEL"
Environment="DB_PATH=/etc/x-ui/x-ui.db"
Environment="MONGO_URI=mongodb://127.0.0.1:27017"
Environment="MONGO_DB=blitz_panel"
Environment="MONGO_COLLECTION=users"
Restart=always
RestartSec=5
StandardOutput=append:/var/log/traffic-x.log
StandardError=append:/var/log/traffic-x.log
SyslogIdentifier=traffic-x

[Install]
WantedBy=multi-user.target
EOL

echo "Enabling service..."
sudo systemctl daemon-reload
sudo systemctl enable traffic-x
sudo systemctl start traffic-x

echo "Installation complete! Your server is running at http://$SERVER_IP:$PORT"
if [ -n "$SSL_CONTEXT" ]; then
  echo "SSL enabled → https://$SERVER_IP:$PORT"
else
  echo "SSL disabled → http://$SERVER_IP:$PORT"
fi
