#!/bin/bash
# @fileOverview Traffic-X Installer/Uninstaller
# @author MasterHide
# @license MIT

set -euo pipefail

# -------- UI: Menu (same as before) --------
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
            bash <(curl -s https://raw.githubusercontent.com/Tyga-x/Traffic-X/main/rm-TX.sh)
            echo "Traffic-X has been uninstalled."
            exit 0
            ;;
        3) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice. Please select a valid option [1-3]." ;;
    esac
done

# -------- NEW: Auto-detect username safely --------
# Prefer SUDO_USER when run via sudo; fall back to whoami; final fallback: prompt.
USERNAME="${SUDO_USER:-$(whoami)}"
if [[ -z "$USERNAME" || "$USERNAME" == "root" ]]; then
  POSSIBLE_USER="$(logname 2>/dev/null || true)"
  if [[ -n "${POSSIBLE_USER:-}" && "${POSSIBLE_USER}" != "root" ]]; then
    USERNAME="$POSSIBLE_USER"
  fi
fi
read -p "Detected system user: '$USERNAME'. Press Enter to accept or type another: " USERNAME_INPUT
if [[ -n "${USERNAME_INPUT:-}" ]]; then USERNAME="$USERNAME_INPUT"; fi
HOME_DIR=$(eval echo "~$USERNAME")
if [[ ! -d "$HOME_DIR" ]]; then
  echo "User '$USERNAME' does not have a valid home directory ($HOME_DIR)."
  exit 1
fi

# -------- Ask for domain & port (same UX) --------
read -p "Enter your server domain (e.g. your_domain.com): " DOMAIN
read -p "Enter the port (default: 5000): " PORT
PORT=${PORT:-5000}

# -------- Version (same UX) --------
read -p "Enter the version to install (e.g., v1.0.1) or leave blank for latest: " VERSION
VERSION="${VERSION:-latest}"

# -------- System deps --------
echo "Updating packages..."
sudo apt update
echo "Installing required dependencies..."
sudo apt install -y python3-pip python3-venv git sqlite3 socat unzip curl

# -------- Download Traffic-X (same logic, clearer var names) --------
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
    EXTRACTED_DIR=$(ls -1 "$HOME_DIR" | grep -E "^Traffic-X-" | head -n 1)
    rm -rf "$HOME_DIR/Traffic-X"
    mv "$HOME_DIR/$EXTRACTED_DIR" "$HOME_DIR/Traffic-X"
    rm Traffic-X.zip
else
    echo "Failed to download Traffic-X version $VERSION. Exiting."
    exit 1
fi

# -------- Verify repo structure (app.py now required from repo) --------
if [ ! -d "$HOME_DIR/Traffic-X/templates" ]; then
  echo "Templates directory not found in repo. Exiting."
  exit 1
fi
if [ ! -f "$HOME_DIR/Traffic-X/app.py" ]; then
  echo "ERROR: app.py not found in repo at $HOME_DIR/Traffic-X/app.py"
  echo "Please add your app.py to the repository and re-run this installer."
  exit 1
fi

# -------- Python venv + deps --------
echo "Setting up the Python virtual environment..."
cd "$HOME_DIR/Traffic-X"
python3 -m venv venv
source venv/bin/activate
echo "Installing Python dependencies..."
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
  pip install -r requirements.txt
else
  # Pin Flask + Werkzeug to compatible versions
  pip install "flask==2.2.5" "werkzeug==2.2.3" gunicorn psutil requests
fi
deactivate


# -------- SSL setup (robust + fixed acme.sh path) --------
SSL_CONTEXT=""   # initialize so it's always defined (avoids 'unbound variable')
CERT_DIR="/var/lib/Traffic-X/certs"
sudo mkdir -p "$CERT_DIR"
sudo chown -R "$USERNAME:$USERNAME" "$CERT_DIR"

if [[ -f "$CERT_DIR/$DOMAIN.cer" && -f "$CERT_DIR/$DOMAIN.cer.key" ]]; then
    echo "Valid SSL certificate already exists."
    SSL_CONTEXT="--certfile=$CERT_DIR/$DOMAIN.cer --keyfile=$CERT_DIR/$DOMAIN.cer.key"
else
    echo "Generating SSL certificate..."
    # Install acme.sh (idempotent)
    curl https://get.acme.sh | sh -s email="$USERNAME@$DOMAIN" || true

    # Resolve acme.sh path correctly (works even when run with sudo)
    ACME="$HOME/.acme.sh/acme.sh"
    if [[ "$HOME" == "/root" && -n "${SUDO_USER:-}" ]]; then
        ACME="/home/$SUDO_USER/.acme.sh/acme.sh"
    fi
    # Fallback to HOME_DIR if needed
    if [[ ! -x "$ACME" && -n "${HOME_DIR:-}" ]]; then
        ACME="$HOME_DIR/.acme.sh/acme.sh"
    fi
    # Final fallback
    if [[ ! -x "$ACME" ]]; then
        ACME="$HOME/.acme.sh/acme.sh"
    fi

    # Use Let's Encrypt
    "$ACME" --set-default-ca --server letsencrypt || true

    # Best-effort: open 80/443 (won't fail script if ufw absent)
    if command -v ufw >/dev/null 2>&1; then
        sudo ufw allow 80/tcp || true
        sudo ufw allow 443/tcp || true
    fi

    # Best-effort: free up port 80 during issuance
    sudo systemctl stop nginx 2>/dev/null || true
    sudo systemctl stop apache2 2>/dev/null || true

    ISSUE_OK=0
    # Try HTTP-01 (standalone on :80)
    if "$ACME" --issue --force --standalone -d "$DOMAIN" \
        --fullchain-file "$CERT_DIR/$DOMAIN.cer" \
        --key-file "$CERT_DIR/$DOMAIN.cer.key"; then
        ISSUE_OK=1
    else
        echo "HTTP-01 failed, retrying with IPv6 standalone..."
        if "$ACME" --issue --force --standalone --listen-v6 -d "$DOMAIN" \
            --fullchain-file "$CERT_DIR/$DOMAIN.cer" \
            --key-file "$CERT_DIR/$DOMAIN.cer.key"; then
            ISSUE_OK=1
        else
            echo "IPv6 standalone failed, trying ALPN on :443..."
            if "$ACME" --issue --force --alpn -d "$DOMAIN" \
                --fullchain-file "$CERT_DIR/$DOMAIN.cer" \
                --key-file "$CERT_DIR/$DOMAIN.cer.key"; then
                ISSUE_OK=1
            fi
        fi
    fi

    # Fix ownership & set SSL_CONTEXT when we have certs
    if [[ $ISSUE_OK -eq 1 && -f "$CERT_DIR/$DOMAIN.cer" && -f "$CERT_DIR/$DOMAIN.cer.key" ]]; then
        sudo chown "$USERNAME:$USERNAME" "$CERT_DIR/$DOMAIN.cer" "$CERT_DIR/$DOMAIN.cer.key" || true
        echo "SSL certificates generated successfully."
        SSL_CONTEXT="--certfile=$CERT_DIR/$DOMAIN.cer --keyfile=$CERT_DIR/$DOMAIN.cer.key"
    else
        echo "Failed to generate SSL certificates. Continuing without SSL."
        SSL_CONTEXT=""
    fi
fi
# -------- end SSL setup --------

# -------- DB permissions (same as before) --------
echo "Setting permissions for the database file..."
if [ -f "/etc/x-ui/x-ui.db" ]; then
  sudo chmod 644 /etc/x-ui/x-ui.db
  sudo chown "$USERNAME:$USERNAME" /etc/x-ui/x-ui.db
else
  echo "WARNING: /etc/x-ui/x-ui.db not found. The app will still start, but usage queries will fail until the DB exists."
fi

# -------- systemd service (uses repo's app.py) --------
SERVICE_FILE="/etc/systemd/system/traffic-x.service"

# Stop existing service if running
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
WorkingDirectory=$HOME_DIR/Traffic-X
Environment="DB_PATH=/etc/x-ui/x-ui.db"
ExecStart=/bin/bash -lc 'source $HOME_DIR/Traffic-X/venv/bin/activate && exec gunicorn -w 4 -b 0.0.0.0:$PORT $SSL_CONTEXT app:app'
Restart=always
RestartSec=5
StandardOutput=append:/var/log/traffic-x.log
StandardError=append:/var/log/traffic-x.log
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
echo "Installation complete! Your server is running at $PROTO://$DOMAIN:$PORT"
[ -z "$SSL_CONTEXT" ] && echo "SSL is disabled. (Cert generation failed or not present.)"
