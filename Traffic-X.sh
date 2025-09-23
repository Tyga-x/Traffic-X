sudo bash -c 'cat > /usr/local/bin/checker-x' <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

# === Traffic-X universal installer / manager ===
# Ubuntu 20.04/22.04/24.04. No 80/443 required (DNS-01 or self-signed).
# Global command: checker-x
# Colors
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; CYAN='\033[1;36m'; NC='\033[0m'
info(){ echo -e "${CYAN}[INFO]${NC} $*"; }
ok(){ echo -e "${GREEN}[OK]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR]${NC} $*"; }
die(){ err "$*"; exit 1; }

# Globals
SERVICE_NAME="traffic-x"
SERVICE_USER="trafficx"
SERVICE_HOME="/home/${SERVICE_USER}"
APP_DIR="${SERVICE_HOME}/Traffic-X"
LOG_FILE="/var/log/traffic-x.log"
CERT_DIR="/var/lib/Traffic-X/certs"
DB_PATH="/etc/x-ui/x-ui.db"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
REPO_HEAD_ZIP="https://github.com/Tyga-x/Traffic-X/archive/refs/heads/main.zip"
CF_ALLOWED_HTTPS_PORTS="443, 2053, 2083, 2087, 2096, 8443"

# Sanity
require_root(){ [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; command -v systemctl >/dev/null || die "systemd required."; }
ensure_ubuntu(){
  if ! command -v lsb_release >/dev/null 2>&1; then apt-get update -y && apt-get install -y lsb-release; fi
  local dist; dist=$(lsb_release -si || echo Ubuntu)
  [[ "$dist" == "Ubuntu" ]] || warn "Detected $dist. Script targets Ubuntu; continuing."
}

# Helpers
fresh_cleanup(){
  info "Stopping & removing previous ${SERVICE_NAME}..."
  systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
  systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
  rm -f "${UNIT_FILE}" || true
  systemctl daemon-reload || true
  rm -rf "${APP_DIR}" || true
  ok "Clean slate."
}
ensure_user(){
  id -u "${SERVICE_USER}" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
  mkdir -p "${SERVICE_HOME}"; chown -R "${SERVICE_USER}:${SERVICE_USER}" "${SERVICE_HOME}"
}
install_prereqs(){
  info "Installing prerequisites..."
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip git unzip curl socat sqlite3 openssl rsync
  ok "Prerequisites ready."
}
fetch_app(){
  local version="$1" dl="$REPO_HEAD_ZIP"
  [[ -n "${version}" && "${version}" != "latest" ]] && dl="https://github.com/Tyga-x/Traffic-X/archive/refs/tags/${version}.zip"
  info "Downloading Traffic-X (${version})..."
  local tmp="/tmp/Traffic-X.zip"; curl -fL "${dl}" -o "${tmp}"
  mkdir -p "${APP_DIR}"
  unzip -q "${tmp}" -d "${SERVICE_HOME}"
  local extracted; extracted=$(find "${SERVICE_HOME}" -maxdepth 1 -type d -name "Traffic-X*" | head -n1)
  rsync -a "${extracted}/" "${APP_DIR}/"
  rm -f "${tmp}"
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
  [[ -d "${APP_DIR}/templates" ]] || die "Templates missing in repo."
  [[ -f "${APP_DIR}/app.py" ]] || die "app.py missing in repo."
  ok "Fetched to ${APP_DIR}"
}
setup_venv(){
  info "Creating Python venv..."
  sudo -u "${SERVICE_USER}" python3 -m venv "${APP_DIR}/venv"
  sudo -u "${SERVICE_USER}" bash -lc "${APP_DIR}/venv/bin/pip install --upgrade pip"
  sudo -u "${SERVICE_USER}" bash -lc "${APP_DIR}/venv/bin/pip install flask gunicorn psutil requests"
  ok "venv ready."
}
prepare_paths(){
  mkdir -p "${CERT_DIR}"; touch "${LOG_FILE}"
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "${CERT_DIR}" "${LOG_FILE}"
  if [[ -f "${DB_PATH}" ]]; then chmod 644 "${DB_PATH}" || true; chown root:root "${DB_PATH}" || true; else warn "x-ui DB not found at ${DB_PATH} (usage page needs it)."; fi
}
issue_cert_dns01_or_selfsigned(){
  local domain="$1" cf_token="${2-}" cert_file="${CERT_DIR}/${domain}.cer" key_file="${CERT_DIR}/${domain}.cer.key"
  if [[ -n "${cf_token}" ]]; then
    info "Trying Let’s Encrypt (DNS-01 via Cloudflare) for ${domain}..."
    [[ -x "/root/.acme.sh/acme.sh" ]] || curl https://get.acme.sh | sh -s email="admin@${domain}"
    export CF_Token="${cf_token}" CF_Account_ID=""
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    set +e
    /root/.acme.sh/acme.sh --issue --dns dns_cf -d "${domain}" --keylength ec-256 \
      --fullchain-file "${cert_file}" --key-file "${key_file}"
    local rc=$?; set -e
    if [[ $rc -eq 0 && -s "${cert_file}" && -s "${key_file}" ]]; then
      chown "${SERVICE_USER}:${SERVICE_USER}" "${cert_file}" "${key_file}"
      ok "Issued valid cert."
      echo "${cert_file}:${key_file}"; return 0
    else warn "DNS-01 failed; using self-signed."; fi
  fi
  info "Generating self-signed cert for ${domain} (1y)..."
  openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
    -keyout "${key_file}" -out "${cert_file}" -days 365 -subj "/CN=${domain}"
  chown "${SERVICE_USER}:${SERVICE_USER}" "${cert_file}" "${key_file}"
  ok "Self-signed ready (browsers will warn)."
  echo "${cert_file}:${key_file}"
}
write_unit(){
  local domain="$1" port="$2" cert_file="$3" key_file="$4"
  info "Writing systemd unit..."
  cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=Traffic-X Web App
After=network-online.target
Wants=network-online.target

[Service]
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
Environment=DB_PATH=${DB_PATH}
Environment=PORT=${port}
Environment=DOMAIN=${domain}
Environment=CERT_FILE=${cert_file}
Environment=KEY_FILE=${key_file}
ExecStart=${APP_DIR}/venv/bin/gunicorn -w 4 -b 0.0.0.0:\${PORT} \\
  --certfile "\${CERT_FILE}" --keyfile "\${KEY_FILE}" app:app
Restart=always
RestartSec=2
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  ok "Unit saved."
}
start_service(){
  systemctl restart "${SERVICE_NAME}"
  sleep 1
  systemctl --no-pager -l status "${SERVICE_NAME}" | sed -n '1,20p' || true
  ss -ltnp | grep -E ":$(systemctl show -p Environment ${SERVICE_NAME} | sed -n 's/.*PORT=\([0-9]*\).*/\1/p')" || true
}
install_logrotate(){
  info "Configuring logrotate..."
  cat > /etc/logrotate.d/traffic-x <<'ROT'
/var/log/traffic-x.log {
  weekly
  rotate 8
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
}
ROT
  ok "Logrotate set."
}

# Commands
cmd_install(){
  echo -e "${BLUE}Traffic-X Installation${NC}"
  read -r -p "$(echo -e "${CYAN}Enter domain (e.g. example.com): ${NC}")" DOMAIN
  [[ -n "${DOMAIN}" ]] || die "Domain required."
  read -r -p "$(echo -e "${CYAN}Enter port [default 5000]: ${NC}")" PORT || true; PORT=${PORT:-5000}
  echo -e "${YELLOW}If Cloudflare is proxied (orange cloud), HTTPS ports allowed:${NC} ${CF_ALLOWED_HTTPS_PORTS}"
  echo -e "${YELLOW}Port 5000 will NOT proxy via Cloudflare. Use DNS-only (gray cloud) if you insist.${NC}"
  read -r -p "$(echo -e "${CYAN}Cloudflare API Token for DNS-01 (optional): ${NC}")" CF_TOKEN || true
  read -r -p "$(echo -e "${CYAN}Version tag (e.g. v1.0.1) or blank for latest: ${NC}")" VERSION || true; VERSION=${VERSION:-latest}

  fresh_cleanup
  ensure_user
  install_prereqs
  fetch_app "${VERSION}"
  setup_venv
  prepare_paths
  local pair; pair=$(issue_cert_dns01_or_selfsigned "${DOMAIN}" "${CF_TOKEN}")
  local CERT_FILE="${pair%%:*}" KEY_FILE="${pair##*:}"
  write_unit "${DOMAIN}" "${PORT}" "${CERT_FILE}" "${KEY_FILE}"
  install_logrotate
  start_service
  echo; ok "Installation complete!"
  echo -e "${GREEN}App URL (HTTPS):${NC} https://${DOMAIN}:${PORT}"
  echo -e "${GREEN}Certs:${NC} ${CERT_FILE}  ${KEY_FILE}"
  echo -e "${GREEN}Log:${NC}   ${LOG_FILE}"
}
cmd_uninstall(){
  info "Uninstalling ${SERVICE_NAME}..."
  systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
  systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
  rm -f "${UNIT_FILE}"; systemctl daemon-reload || true
  rm -rf "${APP_DIR}"
  ok "Uninstalled. Certs/log kept: ${CERT_DIR}, ${LOG_FILE}"
}
cmd_status(){ systemctl --no-pager -l status "${SERVICE_NAME}" || true; echo; ss -ltnp | grep -E '(:[0-9]+)' | grep "${SERVICE_NAME}" || true; }
cmd_start(){ systemctl start "${SERVICE_NAME}"; ok "Started."; }
cmd_stop(){ systemctl stop  "${SERVICE_NAME}"; ok "Stopped."; }
cmd_restart(){ systemctl restart "${SERVICE_NAME}"; ok "Restarted."; }
cmd_logs(){ tail -n 50 "${LOG_FILE}" || true; }
cmd_follow(){ tail -f "${LOG_FILE}"; }
cmd_change_port(){
  local newp; read -r -p "$(echo -e "${CYAN}Enter new port:${NC} ")" newp
  [[ "${newp}" =~ ^[0-9]+$ ]] || die "Invalid port."
  info "Switching port to ${newp}..."
  sed -i "s/^Environment=PORT=.*/Environment=PORT=${newp}/" "${UNIT_FILE}"
  systemctl daemon-reload; systemctl restart "${SERVICE_NAME}"
  ok "Port changed to ${newp}. CF-proxy allowed: ${CF_ALLOWED_HTTPS_PORTS}"
}

# Menu
show_menu(){
  clear
  echo -e "${BLUE}=== Traffic-X Manager (checker-x) ===${NC}"
  echo "1) Install / Reinstall (fresh)"
  echo "2) Uninstall"
  echo "3) Start"
  echo "4) Stop"
  echo "5) Restart"
  echo "6) Status"
  echo "7) Tail last 50 log lines"
  echo "8) Follow logs"
  echo "9) Change Port"
  echo "0) Exit"
  echo
}
main_menu(){
  ensure_ubuntu
  while true; do
    show_menu
    read -r -p "Select: " c
    case "$c" in
      1) cmd_install ;;
      2) cmd_uninstall ;;
      3) cmd_start ;;
      4) cmd_stop ;;
      5) cmd_restart ;;
      6) cmd_status ;;
      7) cmd_logs ;;
      8) cmd_follow ;;
      9) cmd_change_port ;;
      0) exit 0 ;;
      *) warn "Invalid option" ;;
    esac
    echo -e "${YELLOW}Press Enter to continue...${NC}"; read -r || true
  done
}

# Entry
require_root
case "${1-}" in
  install)      cmd_install ;;
  uninstall)    cmd_uninstall ;;
  start)        cmd_start ;;
  stop)         cmd_stop ;;
  restart)      cmd_restart ;;
  status)       cmd_status ;;
  logs)         cmd_logs ;;
  follow)       cmd_follow ;;
  change-port)  cmd_change_port ;;
  "" )          main_menu ;;
  * )           echo "Usage: checker-x [install|uninstall|start|stop|restart|status|logs|follow|change-port]"; exit 2 ;;
esac
SCRIPT
sudo chmod +x /usr/local/bin/checker-x
