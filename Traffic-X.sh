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

# Install Python3, pip, git, socat, and other required dependencies
echo "Installing required dependencies..."
sudo apt install -y python3-pip python3-venv git sqlite3 socat unzip curl

# Construct the download URL based on the version
echo "Downloading Traffic-X version $VERSION..."
if [ "$VERSION" == "latest" ]; then
    DOWNLOAD_URL="https://github.com/Tyga-x/Traffic-X/archive/refs/heads/main.zip"
else
    DOWNLOAD_URL="https://github.com/Tyga-x/Traffic-X/archive/refs/tags/$VERSION.zip"
fi

cd /home/$USERNAME
if curl -L "$DOWNLOAD_URL" -o Traffic-X.zip; then
    echo "Download successful. Extracting files..."
    unzip -o Traffic-X.zip -d /home/$USERNAME
    EXTRACTED_DIR=$(ls /home/$USERNAME | grep "Traffic-X-" | head -n 1)
    mv "/home/$USERNAME/$EXTRACTED_DIR" /home/$USERNAME/Traffic-X
    rm Traffic-X.zip
else
    echo "Failed to download Traffic-X version $VERSION. Exiting."
    exit 1
fi

# Verify the templates directory exists
if [ -d "/home/$USERNAME/Traffic-X/templates" ]; then
    echo "Templates directory found."
else
    echo "Templates directory not found. Exiting."
    exit 1
fi

# Set up a virtual environment
echo "Setting up the Python virtual environment..."
cd /home/$USERNAME/Traffic-X
python3 -m venv venv
source venv/bin/activate

# Install Flask, Gunicorn, and any other required Python libraries
echo "Installing Flask, Gunicorn, and dependencies..."
pip install --upgrade pip
pip install flask gunicorn psutil requests

# Configure the Flask app to run on the specified port
echo "Configuring Flask app..."
export DOMAIN=$SERVER_IP

# Create a custom directory for SSL certificates
mkdir -p /var/lib/Traffic-X/certs
sudo chown -R $USERNAME:$USERNAME /var/lib/Traffic-X/certs

# Check if valid certificate already exists
if [ -f "/var/lib/Traffic-X/certs/$DOMAIN.cer" ] && [ -f "/var/lib/Traffic-X/certs/$DOMAIN.cer.key" ]; then
    echo "Valid SSL certificate already exists."
    SSL_CONTEXT="--certfile=/var/lib/Traffic-X/certs/$DOMAIN.cer --keyfile=/var/lib/Traffic-X/certs/$DOMAIN.cer.key"
else
    echo "Generating SSL certificate..."
    curl https://get.acme.sh | sh -s email=$USERNAME@$SERVER_IP
    ~/.acme.sh/acme.sh --issue --force --standalone -d "$DOMAIN" \
        --fullchain-file "/var/lib/Traffic-X/certs/$DOMAIN.cer" \
        --key-file "/var/lib/Traffic-X/certs/$DOMAIN.cer.key"
    # Fix ownership of the generated certificates
    sudo chown $USERNAME:$USERNAME /var/lib/Traffic-X/certs/$DOMAIN.cer
    sudo chown $USERNAME:$USERNAME /var/lib/Traffic-X/certs/$DOMAIN.cer.key
    # Verify certificate generation
    if [ ! -f "/var/lib/Traffic-X/certs/$DOMAIN.cer" ] || [ ! -f "/var/lib/Traffic-X/certs/$DOMAIN.cer.key" ]; then
        echo "Failed to generate SSL certificates. Disabling SSL."
        SSL_CONTEXT=""
    else
        echo "SSL certificates generated successfully."
        SSL_CONTEXT="--certfile=/var/lib/Traffic-X/certs/$DOMAIN.cer --keyfile=/var/lib/Traffic-X/certs/$DOMAIN.cer.key"
    fi
fi

# Generate app.py with SSL context handling (optional, only if needed)
cat > app.py <<EOL
from flask import Flask, request, render_template, jsonify
import sqlite3
import json
import psutil
import requests
from datetime import datetime

app = Flask(__name__)
db_path = "/etc/x-ui/x-ui.db"  # Adjust path if necessary

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
        user_input = request.form.get('user_input')  # Get input from the form
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Query to fetch client data
        query = '''SELECT email, up, down, total, expiry_time, inbound_id FROM client_traffics WHERE email = ? OR id = ?'''
        cursor.execute(query, (user_input, user_input))
        row = cursor.fetchone()
        if row:
            email, up, down, total, expiry_time, inbound_id = row
            # **Fixed expiry time handling**
            expiry_date = "Invalid Date"
            if expiry_time and isinstance(expiry_time, (int, float)):
                expiry_timestamp = expiry_time / 1000 if expiry_time > 9999999999 else expiry_time
                try:
                    expiry_date = datetime.utcfromtimestamp(expiry_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, OSError):
                    expiry_date = "Invalid Date"
            # Query to fetch totalGB and user-specific enable status
            inbound_query = '''SELECT settings FROM inbounds WHERE id = ?'''
            cursor.execute(inbound_query, (inbound_id,))
            inbound_row = cursor.fetchone()
            totalGB = "Not Available"
            user_status = "Disabled"  # Default to "Disabled" if user is not found
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
            # Convert to human-readable format
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
        new_status = data.get('status')  # True or False
        # Update the status in the database (implement this logic)
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
        response = requests.get("http://ip-api.com/json/")
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
    app.run(host='0.0.0.0', port=$PORT, debug=False)
EOL

# Set permissions for the database file
echo "Setting permissions for the database file..."
sudo chmod 644 /etc/x-ui/x-ui.db
sudo chown $USERNAME:$USERNAME /etc/x-ui/x-ui.db

# Stop any existing instance of the Flask app
if sudo systemctl is-active --quiet traffic-x; then
    echo "Stopping existing Traffic-X service..."
    sudo systemctl stop traffic-x
fi

# Create a systemd service to keep the Flask app running with Gunicorn
echo "Setting up systemd service..."
cat > /etc/systemd/system/traffic-x.service <<EOL
[Unit]
Description=Traffic-X Web App
After=network.target

[Service]
User=$USERNAME
WorkingDirectory=/home/$USERNAME/Traffic-X
ExecStart=/bin/bash -c 'source /home/$USERNAME/Traffic-X/venv/bin/activate && exec gunicorn -w 4 -b 0.0.0.0:$PORT $SSL_CONTEXT app:app'
Environment="DB_PATH=/etc/x-ui/x-ui.db"
Restart=always
RestartSec=5
StandardOutput=append:/var/log/traffic-x.log
StandardError=append:/var/log/traffic-x.log
SyslogIdentifier=traffic-x

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd and enable the service
echo "Enabling the service to start on boot..."
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
