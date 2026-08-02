#!/bin/bash
# @fileOverview Check usage stats of X-SL
# @author MasterHide
# @Copyright © 2025 x404 MASTER™
# @license MIT

set -euo pipefail

# -------- UI: Menu --------
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
        2)
            echo "Uninstalling Traffic-X..."
            bash <(curl -s https://raw.githubusercontent.com/Tyga-x/Traffic-X/main/rm-TX.sh) || true
            echo "Traffic-X has been uninstalled."
            exit 0
            ;;
        3) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice. Please select a valid option [1-3]." ;;
    esac
done

# -------- Auto-detect username (Safe) --------
# Never run the web app as root. Create a dedicated user if needed.
USERNAME="${SUDO_USER:-$(whoami)}"

if [[ "$USERNAME" == "root" || -z "$USERNAME" ]]; then
    USERNAME="traffic-x"
    if ! id -u "$USERNAME" &>/dev/null; then
        echo "Creating dedicated system user '$USERNAME'..."
        sudo useradd -m -s /bin/bash "$USERNAME"
    fi
fi

HOME_DIR=$(eval echo "~$USERNAME")

if [[ ! -d "$HOME_DIR" ]]; then
    echo "Home directory $HOME_DIR not found. Falling back to /opt/traffic-x"
    HOME_DIR="/opt/traffic-x"
    sudo mkdir -p "$HOME_DIR"
    sudo chown -R "$USERNAME:$USERNAME" "$HOME_DIR"
fi

echo -e "✅ System user set to: \033[1;33m$USERNAME\033[0m"

# -------- Ask for domain & port --------
while true; do
    read -p "Enter your server domain (e.g. your_domain.com): " DOMAIN
    if [[ -n "$DOMAIN" ]]; then
        break
    fi
    echo "Domain cannot be empty. Please try again."
done

read -p "Enter the port (default: 5000): " PORT
PORT=${PORT:-5000}

# -------- Version --------
read -p "Enter the version to install (e.g., v1.0.1) or leave blank for latest: " VERSION
VERSION="${VERSION:-latest}"

# -------- System deps --------
echo "Updating packages..."
sudo apt update
echo "Installing required dependencies..."
sudo apt install -y python3-pip python3-venv git sqlite3 socat unzip curl

# -------- Download Traffic-X --------
echo "Downloading Traffic-X version $VERSION..."
if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/Tyga-x/Traffic-X/archive/refs/heads/main.zip"
else
    DOWNLOAD_URL="https://github.com/Tyga-x/Traffic-X/archive/refs/tags/$VERSION.zip"
fi

cd "$HOME_DIR"
if curl -L "$DOWNLOAD_URL" -o Traffic-X.zip; then
    echo "Download successful. Extracting files..."
    unzip -o Traffic-X.zip -d "$HOME_DIR"
    
    # Safe extraction folder detection
    EXTRACTED_DIR=$(find "$HOME_DIR" -maxdepth 1 -type d -name "Traffic-X-*" | head -n 1)
    if [[ -z "$EXTRACTED_DIR" || ! -d "$EXTRACTED_DIR" ]]; then
        echo "ERROR: Failed to extract Traffic-X. The download might be corrupted."
        exit 1
    fi
    
    rm -rf "$HOME_DIR/Traffic-X"
    mv "$EXTRACTED_DIR" "$HOME_DIR/Traffic-X"
    rm -f Traffic-X.zip
    sudo chown -R "$USERNAME:$USERNAME" "$HOME_DIR/Traffic-X"
else
    echo "Failed to download Traffic-X version $VERSION. Exiting."
    exit 1
fi

# -------- Verify repo structure --------
if [ ! -d "$HOME_DIR/Traffic-X/templates" ]; then
  echo "Templates directory not found in repo. Exiting."
  exit 1
fi
if [ ! -f "$HOME_DIR/Traffic-X/app.py" ]; then
  echo "ERROR: app.py not found in repo."
  exit 1
fi

# -------- Python venv + deps --------
echo "Setting up the Python virtual environment..."
cd "$HOME_DIR/Traffic-X"
sudo -u "$USERNAME" python3 -m venv venv
if [ -f "requirements.txt" ]; then
  sudo -u "$USERNAME" venv/bin/pip install --upgrade pip
  sudo -u "$USERNAME" venv/bin/pip install -r requirements.txt
else
  sudo -u "$USERNAME" venv/bin/pip install --upgrade pip
  sudo -u "$USERNAME" venv/bin/pip install "flask==2.2.5" "werkzeug==2.2.3" gunicorn psutil requests
fi

# -------- SSL setup --------
SSL_CONTEXT=""
CERT_DIR="/var/lib/Traffic-X/certs"
sudo mkdir -p "$CERT_DIR"
sudo chown -R "$USERNAME:$USERNAME" "$CERT_DIR"

if [[ -f "$CERT_DIR/$DOMAIN.cer" && -f "$CERT_DIR/$DOMAIN.cer.key" ]]; then
    echo "Valid SSL certificate already exists."
    SSL_CONTEXT="--certfile=$CERT_DIR/$DOMAIN.cer --keyfile=$CERT_DIR/$DOMAIN.cer.key"
else
    echo "Generating SSL certificate..."
    curl https://get.acme.sh | sh -s email="$USERNAME@$DOMAIN" || true

    ACME="$HOME_DIR/.acme.sh/acme.sh"
    if [[ ! -x "$ACME" ]]; then
        ACME="/root/.acme.sh/acme.sh"
    fi

    "$ACME" --set-default-ca --server letsencrypt || true

    if command -v ufw >/dev/null 2>&1; then
        sudo ufw allow 80/tcp || true
        sudo ufw allow 443/tcp || true
    fi

    # Free up port 80
    sudo systemctl stop nginx 2>/dev/null || true
    sudo systemctl stop apache2 2>/dev/null || true

    ISSUE_OK=0
    if "$ACME" --issue --force --standalone -d "$DOMAIN" \
        --fullchain-file "$CERT_DIR/$DOMAIN.cer" \
        --key-file "$CERT_DIR/$DOMAIN.cer.key"; then
        ISSUE_OK=1
    else
        echo "HTTP-01 failed, retrying with ALPN on :443..."
        if "$ACME" --issue --force --alpn -d "$DOMAIN" \
            --fullchain-file "$CERT_DIR/$DOMAIN.cer" \
            --key-file "$CERT_DIR/$DOMAIN.cer.key"; then
            ISSUE_OK=1
        fi
    fi

    if [[ $ISSUE_OK -eq 1 ]]; then
        sudo chown "$USERNAME:$USERNAME" "$CERT_DIR/$DOMAIN.cer" "$CERT_DIR/$DOMAIN.cer.key" || true
        echo "SSL certificates generated successfully."
        SSL_CONTEXT="--certfile=$CERT_DIR/$DOMAIN.cer --keyfile=$CERT_DIR/$DOMAIN.cer.key"
    else
        echo "Failed to generate SSL certificates. Continuing without SSL."
        SSL_CONTEXT=""
    fi
fi

# -------- DB permissions (SAFE METHOD) --------
echo "Setting read permissions for the database file..."
if [ -f "/etc/x-ui/x-ui.db" ]; then
  # DO NOT chown this file! x-ui owns it. We just make it world-readable.
  sudo chmod 644 /etc/x-ui/x-ui.db
else
  echo "WARNING: /etc/x-ui/x-ui.db not found. The app will start, but usage queries will fail."
fi

# -------- systemd service --------
SERVICE_FILE="/etc/systemd/system/traffic-x.service"

if systemctl is-active --quiet traffic-x; then
    echo "Stopping existing Traffic-X service..."
    sudo systemctl stop traffic-x
fi

echo "Setting up systemd service..."
sudo tee "$SERVICE_FILE" >/dev/null <<EOL
[Unit]
Description=Traffic-X Web App
After=network.target

[Service]
User=$USERNAME
Group=$USERNAME
WorkingDirectory=$HOME_DIR/Traffic-X
Environment="DB_PATH=/etc/x-ui/x-ui.db"
# Directly use venv binaries to avoid bash environment leaks
ExecStart=$HOME_DIR/Traffic-X/venv/bin/gunicorn -w 4 -b 0.0.0.0:$PORT $SSL_CONTEXT app:app
Restart=always
RestartSec=5

# Security & Resource Limits
LimitNOFILE=65535
MemoryMax=512M

# Logging to systemd journal (prevents disk full crashes)
StandardOutput=journal
StandardError=journal
SyslogIdentifier=traffic-x

[Install]
WantedBy=multi-user.target
EOL

echo "Enabling the service to start on boot..."
sudo systemctl daemon-reload
sudo systemctl enable traffic-x
sudo systemctl start traffic-x

# -------- Final messages --------
PROTO="http"
[ -n "$SSL_CONTEXT" ] && PROTO="https"
echo "========================================================="
echo "✅ Installation complete! TRAFFIC - X is Running Now."
echo "➡️  Access it at: $PROTO://$DOMAIN:$PORT"
[ -z "$SSL_CONTEXT" ] && echo "⚠️ SSL is disabled. (Cert generation failed or not present.)"
echo "📜 View logs with: sudo journalctl -u traffic-x -f"
echo "========================================================="
