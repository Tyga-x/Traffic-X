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
            bash <(curl -s https://github.com/Tyga-x/Traffic-X/raw/main/rm-TX.sh)
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
echo "Enter your server domain (e.g. your_domain.com or IP):"
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
pip install flask gunicorn psutil requests 'qrcode[pil]'

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
        --key-file "/var/lib/Traffic-X/certs/$DOMAIN.cer.key" || true
    # Fix ownership of the generated certificates
    sudo chown $USERNAME:$USERNAME /var/lib/Traffic-X/certs/$DOMAIN.cer || true
    sudo chown $USERNAME:$USERNAME /var/lib/Traffic-X/certs/$DOMAIN.cer.key || true
    # Verify certificate generation
    if [ ! -f "/var/lib/Traffic-X/certs/$DOMAIN.cer" ] || [ ! -f "/var/lib/Traffic-X/certs/$DOMAIN.cer.key" ]; then
        echo "Failed to generate SSL certificates. Disabling SSL."
        SSL_CONTEXT=""
    else
        echo "SSL certificates generated successfully."
        SSL_CONTEXT="--certfile=/var/lib/Traffic-X/certs/$DOMAIN.cer --keyfile=/var/lib/Traffic-X/certs/$DOMAIN.cer.key"
    fi
fi

# =================== Write tx_builders.py (NEW) ===================
cat > tx_builders.py <<'PYEOF'
<PASTE tx_builders.py FROM SECTION 3 BELOW VERBATIM>
PYEOF

# =================== Write app.py (UPDATED) ===================
cat > app.py <<EOL
<PASTE app.py FROM SECTION 2 BELOW VERBATIM>
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
Environment="DOMAIN=$SERVER_IP"
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
