#!/usr/bin/env bash
# =============================================================================
# Traffic-X universal installer / manager bootstrap
# Ubuntu 20.04/22.04/24.04
# SSL: Let's Encrypt via HTTP-01 (port 80, standalone). No Cloudflare token.
# Installs global command: checker-x
# Author: x404 MASTER™ (adapted) | License: MIT
# =============================================================================
set -euo pipefail

# ========== [Section] Colors & Messages ======================================
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; CYAN='\033[1;36m'; NC='\033[0m'
info(){ echo -e "${CYAN}[INFO]${NC} $*"; }
ok(){ echo -e "${GREEN}[OK]${NC}  $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR]${NC}  $*"; }
die(){ err "$*"; exit 1; }

# ========== [Section] Globals ================================================
SERVICE_NAME="traffic-x"
SERVICE_USER="trafficx"
SERVICE_HOME="/home/${SERVICE_USER}"
APP_DIR="${SERVICE_HOME}/Traffic-X"
LOG_FILE="/var/log/traffic-x.log"
CERT_DIR="/var/lib/Traffic-X/certs"
DB_PATH="/etc/x-ui/x-ui.db"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
REPO_HEAD_ZIP="https://github.com/Tyga-x/Traffic-X/archive/refs/heads/main.zip"

# ========== [Section] Sanity Checks ==========================================
require_root(){ [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; command -v systemctl >/dev/null || die "systemd required."; }
ensure_ubuntu(){
  if ! command -v lsb_release >/dev/null 2>&1; then apt-get update -y && apt-get install -y lsb-release; fi
  local dist; dist=$(lsb_release -si || echo Ubuntu)
  [[ "$dist" == "Ubuntu" ]] || warn "Detected $dist. Script targets Ubuntu; continuing."
}

# ========== [Section] Helper Functions =======================================
fresh_cleanup(){
  info "Stopping & removing previous ${SERVICE_NAME}..."
  systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
  systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
  rm -f "${UNIT_FILE}" || true
  systemctl daemon-reload || true
  rm -rf "${APP_DIR}" || true
  ok "Clean slate ready."
}
ensure_user(){
  id -u "${SERVICE_USER}" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
  mkdir -p "${SERVICE_HOME}"; chown -R "${SERVICE_USER}:${SERVICE_USER}" "${SERVICE_HOME}"
}
install_prereqs(){
  info "Installing prerequisites..."
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip git unzip curl socat sqlite3 openssl rsync
  ok "Prerequisites installed."
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
  ok "App fetched to ${APP_DIR}"
}
setup_venv(){
  info "Creating Python venv..."
  sudo -u "${SERVICE_USER}" python3 -m venv "${APP_DIR}/venv"
  sudo -u "${SERVICE_USER}" bash -lc "${APP_DIR}/venv/bin/pip install --upgrade pip"
  sudo -u "${SERVICE_USER}" bash -lc "${APP_DIR}/venv/bin/pip install flask gunicorn psutil requests"
  ok "Python venv ready."
}
prepare_paths(){
  mkdir -p "${CERT_DIR}"; touch "${LOG_FILE}"
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "${CERT_DIR}" "${LOG_FILE}"
  if [[ -f "${DB_PATH}" ]]; then chmod 644 "${DB_PATH}" || true; chown root:root "${DB_PATH}" || true
  else warn "x-ui DB not found at ${DB_PATH}. The /usage page will 404 until x-ui is installed."
  fi
}

# ========== [Section] SSL via HTTP-01 on Port 80 (Let’s Encrypt) =============
# Frees port 80, issues fullchain/key with acme.sh --standalone, restores services.
issue_cert_http01_or_selfsigned(){
  local domain="$1"
  local cert_file="${CERT_DIR}/${domain}.cer"
  local key_file="${CERT_DIR}/${domain}.cer.key"

  info "Preparing HTTP-01 issuance on port 80 for ${domain}…"

  # 1) Free port 80 temporarily
  systemctl stop nginx 2>/dev/null || true
  systemctl stop apache2 2>/dev/null || true
  systemctl stop caddy 2>/dev/null || true
  fuser -k 80/tcp 2>/dev/null || true

  # 2) Open firewall for 80 during issuance (if ufw exists)
  if command -v ufw >/dev/null 2>&1; then ufw allow 80/tcp || true; fi

  # 3) Install acme.sh if needed & set CA
  if [[ ! -x "/root/.acme.sh/acme.sh" ]]; then
    curl https://get.acme.sh | sh -s email="admin@${domain}"
  fi
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  # 4) HTTP-01 standalone issuance on port 80
  set +e
  /root/.acme.sh/acme.sh --issue -d "${domain}" --standalone --keylength ec-256 \
    --fullchain-file "${cert_file}" --key-file "${key_file}"
  local rc=$?
  set -e

  # 5) Restore any web servers we stopped (best-effort)
  systemctl start nginx 2>/dev/null || true
  systemctl start apache2 2>/dev/null || true
  systemctl start caddy 2>/dev/null || true

  if [[ $rc -eq 0 && -s "${cert_file}" && -s "${key_file}" ]]; then
    ok "Let's Encrypt HTTP-01 certificate issued."
    chown "${SERVICE_USER}:${SERVICE_USER}" "${cert_file}" "${key_file}"
    echo "${cert_file}:${key_file}"
    return 0
  fi

  warn "HTTP-01 issuance failed (is port 80 reachable?). Falling back to self-signed."
  # Fallback: self-signed (1 year)
  openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
    -keyout "${key_file}" -out "${cert_file}" -days 365 -subj "/CN=${domain}"
  chown "${SERVICE_USER}:${SERVICE_USER}" "${cert_file}" "${key_file}"
  echo "${cert_file}:${key_file}"
}

# ========== [Section] systemd Unit ===========================================
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
  ok "systemd unit ready."
}

# ========== [Section] Service Start & Logrotate ===============================
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
  ok "Logrotate configured."
}

# ========== [Section] Manager CLI (checker-x) =================================
install_cli(){
  local target="/usr/local/bin/checker-x"
  info "Installing global manager: checker-x"
  cat > "${target}" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; CYAN='\033[1;36m'; NC='\033[0m'
info(){ echo -e "${CYAN}[INFO]${NC} $*"; } ; ok(){ echo -e "${GREEN}[OK]${NC}  $*"; } ; warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; } ; err(){ echo -e "${RED}[ERR]${NC}  $*"; } ; die(){ err "$*"; exit 1; }

SERVICE_NAME="traffic-x"; SERVICE_USER="trafficx"
SERVICE_HOME="/home/${SERVICE_USER}"; APP_DIR="${SERVICE_HOME}/Traffic-X"
LOG_FILE="/var/log/traffic-x.log"; CERT_DIR="/var/lib/Traffic-X/certs"
DB_PATH="/etc/x-ui/x-ui.db"; UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
REPO_HEAD_ZIP="https://github.com/Tyga-x/Traffic-X/archive/refs/heads/main.zip"

require_root(){ [[ $EUID -eq 0 ]] || die "Run as root (sudo)."); command -v systemctl >/dev/null || die "systemd required."; }
ensure_ubuntu(){ command -v lsb_release >/dev/null 2>&1 || { apt-get update -y && apt-get install -y lsb-release; }; }

fresh_cleanup(){ info "Cleaning previous ${SERVICE_NAME}..."; systemctl stop "${SERVICE_NAME}" 2>/dev/null || true; systemctl disable "${SERVICE_NAME}" 2>/dev/null || true; rm -f "${UNIT_FILE}" || true; systemctl daemon-reload || true; rm -rf "${APP_DIR}" || true; ok "Clean slate."; }
ensure_user(){ id -u "${SERVICE_USER}" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "${SERVICE_USER}"; mkdir -p "${SERVICE_HOME}"; chown -R "${SERVICE_USER}:${SERVICE_USER}" "${SERVICE_HOME}"; }
install_prereqs(){ info "Installing prerequisites..."; apt-get update -y; apt-get install -y python3 python3-venv python3-pip git unzip curl socat sqlite3 openssl rsync; ok "Prereqs ready."; }
fetch_app(){ local version="${1:-latest}" dl="$REPO_HEAD_ZIP"; [[ -n "${version}" && "${version}" != "latest" ]] && dl="https://github.com/Tyga-x/Traffic-X/archive/refs/tags/${version}.zip"; info "Downloading Traffic-X (${version})..."; local tmp="/tmp/Traffic-X.zip"; curl -fL "${dl}" -o "${tmp}"; mkdir -p "${APP_DIR}"; unzip -q "${tmp}" -d "${SERVICE_HOME}"; local extracted; extracted=$(find "${SERVICE_HOME}" -maxdepth 1 -type d -name "Traffic-X*" | head -n1); rsync -a "${extracted}/" "${APP_DIR}/"; rm -f "${tmp}"; chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"; [[ -d "${APP_DIR}/templates" ]] || die "Templates missing."; [[ -f "${APP_DIR}/app.py" ]] || die "app.py missing."; ok "Fetched to ${APP_DIR}"; }
setup_venv(){ info "Creating venv..."; sudo -u "${SERVICE_USER}" python3 -m venv "${APP_DIR}/venv"; sudo -u "${SERVICE_USER}" bash -lc "${APP_DIR}/venv/bin/pip install --upgrade pip"; sudo -u "${SERVICE_USER}" bash -lc "${APP_DIR}/venv/bin/pip install flask gunicorn psutil requests"; ok "venv ready."; }
prepare_paths(){ mkdir -p "${CERT_DIR}"; touch "${LOG_FILE}"; chown -R "${SERVICE_USER}:${SERVICE_USER}" "${CERT_DIR}" "${LOG_FILE}"; if [[ -f "${DB_PATH}" ]]; then chmod 644 "${DB_PATH}" || true; chown root:root "${DB_PATH}" || true; else warn "x-ui DB not found at ${DB_PATH}."; fi; }

# --- HTTP-01 issuance helper (inside checker-x) ---
issue_cert_http01_or_selfsigned(){
  local domain="$1"
  local cert_file="${CERT_DIR}/${domain}.cer"
  local key_file="${CERT_DIR}/${domain}.cer.key"

  info "Preparing HTTP-01 issuance on port 80 for ${domain}…"
  systemctl stop nginx 2>/dev/null || true
  systemctl stop apache2 2>/dev/null || true
  systemctl stop caddy 2>/dev/null || true
  fuser -k 80/tcp 2>/dev/null || true
  if command -v ufw >/dev/null 2>&1; then ufw allow 80/tcp || true; fi

  if [[ ! -x "/root/.acme.sh/acme.sh" ]]; then
    curl https://get.acme.sh | sh -s email="admin@${domain}"
  fi
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
  set +e
  /root/.acme.sh/acme.sh --issue -d "${domain}" --standalone --keylength ec-256 \
    --fullchain-file "${cert_file}" --key-file "${key_file}"
  local rc=$?
  set -e
  systemctl start nginx 2>/dev/null || true
  systemctl start apache2 2>/dev/null || true
  systemctl start caddy 2>/dev/null || true

  if [[ $rc -eq 0 && -s "${cert_file}" && -s "${key_file}" ]]; then
    chown "${SERVICE_USER}:${SERVICE_USER}" "${cert_file}" "${key_file}"
    ok "Let's Encrypt certificate issued."
    echo "${cert_file}:${key_file}"
    return 0
  fi
  warn "HTTP-01 issuance failed; falling back to self-signed."
  openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
    -keyout "${key_file}" -out "${cert_file}" -days 365 -subj "/CN=${domain}"
  chown "${SERVICE_USER}:${SERVICE_USER}" "${cert_file}" "${key_file}"
  echo "${cert_file}:${key_file}"
}

write_unit(){ local domain="$1" port="$2" cert_file="$3" key_file="$4"; info "Writing systemd unit..."; cat > "${UNIT_FILE}" <<EOF
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
systemctl daemon-reload; systemctl enable "${SERVICE_NAME}"; ok "Unit saved."; }
start_service(){ systemctl restart "${SERVICE_NAME}"; sleep 1; systemctl --no-pager -l status "${SERVICE_NAME}" | sed -n '1,20p' || true; ss -ltnp | grep -E ":$(systemctl show -p Environment ${SERVICE_NAME} | sed -n 's/.*PORT=\([0-9]*\).*/\1/p')" || true; }
install_logrotate(){ info "Configuring logrotate..."; cat > /etc/logrotate.d/traffic-x <<'ROT'
/var/log/traffic-x.log { weekly rotate 8 missingok notifempty compress delaycompress copytruncate }
ROT
ok "Logrotate set."; }

cmd_install(){
  echo -e "${BLUE}Traffic-X Installation${NC}"
  local DOMAIN="${TRAFFICX_DOMAIN-}"; local PORT="${TRAFFICX_PORT-}"; local VERSION="${TRAFFICX_VERSION-}"
  [[ -n "${DOMAIN}" ]] || read -r -p "$(echo -e "${CYAN}Enter domain (e.g. example.com): ${NC}")" DOMAIN
  [[ -n "${PORT}" ]] || { read -r -p "$(echo -e "${CYAN}Enter HTTPS port [default 5000]: ${NC}")" PORT; PORT=${PORT:-5000}; }
  [[ -n "${VERSION}" ]] || { read -r -p "$(echo -e "${CYAN}Version tag (e.g. v1.0.1) or blank for latest: ${NC}")" VERSION; VERSION=${VERSION:-latest}; }

  fresh_cleanup; ensure_user; install_prereqs; fetch_app "${VERSION}"; setup_venv; prepare_paths
  local pair; pair=$(issue_cert_http01_or_selfsigned "${DOMAIN}")
  local CERT_FILE="${pair%%:*}" KEY_FILE="${pair##*:}"
  write_unit "${DOMAIN}" "${PORT}" "${CERT_FILE}" "${KEY_FILE}"
  install_logrotate; start_service
  echo; ok "Installation complete!"
  echo -e "${GREEN}App URL (HTTPS):${NC} https://${DOMAIN}:${PORT}"
  echo -e "${GREEN}Certs:${NC} ${CERT_FILE}  ${KEY_FILE}"
  echo -e "${GREEN}Log:${NC}   ${LOG_FILE}"
}
cmd_uninstall(){ info "Uninstalling ${SERVICE_NAME}..."; systemctl stop "${SERVICE_NAME}" 2>/dev/null || true; systemctl disable "${SERVICE_NAME}" 2>/dev/null || true; rm -f "${UNIT_FILE}"; systemctl daemon-reload || true; rm -rf "${APP_DIR}"; ok "Uninstalled. Certs/log kept: ${CERT_DIR}, ${LOG_FILE}"; }
cmd_status(){ systemctl --no-pager -l status "${SERVICE_NAME}" || true; echo; ss -ltnp | grep -E '(:[0-9]+)' | grep "${SERVICE_NAME}" || true; }
cmd_start(){ systemctl start "${SERVICE_NAME}"; ok "Started."; }
cmd_stop(){ systemctl stop  "${SERVICE_NAME}"; ok "Stopped."; }
cmd_restart(){ systemctl restart "${SERVICE_NAME}"; ok "Restarted."; }
cmd_logs(){ tail -n 50 "${LOG_FILE}" || true; }
cmd_follow(){ tail -f "${LOG_FILE}"; }
cmd_change_port(){ local newp; read -r -p "$(echo -e "${CYAN}Enter new HTTPS port:${NC} ")" newp; [[ "${newp}" =~ ^[0-9]+$ ]] || die "Invalid port."; info "Switching port to ${newp}..."; sed -i "s/^Environment=PORT=.*/Environment=PORT=${newp}/" "${UNIT_FILE}"; systemctl daemon-reload; systemctl restart "${SERVICE_NAME}"; ok "Port changed to ${newp}."; }
cmd_reboot(){ read -r -p "$(echo -e "${YELLOW}Reboot the system now? [y/N] ${NC}")" ans; [[ "${ans,,}" == "y" ]] && { ok "Rebooting..."; reboot; } || warn "Reboot cancelled."; }

show_menu(){ clear; echo -e "${BLUE}=== Traffic-X Manager (checker-x) ===${NC}"; echo "1) Install / Reinstall (fresh)"; echo "2) Uninstall"; echo "3) Start"; echo "4) Stop"; echo "5) Restart"; echo "6) Status"; echo "7) Tail last 50 log lines"; echo "8) Follow logs"; echo "9) Change Port"; echo "r) Reboot system"; echo "0) Exit"; echo; }
main_menu(){ ensure_ubuntu; while true; do show_menu; read -r -p "Select: " c; case "$c" in 1) cmd_install ;; 2) cmd_uninstall ;; 3) cmd_start ;; 4) cmd_stop ;; 5) cmd_restart ;; 6) cmd_status ;; 7) cmd_logs ;; 8) cmd_follow ;; 9) cmd_change_port ;; r|R) cmd_reboot ;; 0) exit 0 ;; *) warn "Invalid option" ;; esac; echo -e "${YELLOW}Press Enter to continue...${NC}"; read -r || true; done; }

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
  reboot)       cmd_reboot ;;
  "" )          main_menu ;;
  * )           echo "Usage: checker-x [install|uninstall|start|stop|restart|status|logs|follow|change-port|reboot]"; exit 2 ;;
esac
SCRIPT
  chmod +x "${target}"
  ok "Installed global command: checker-x"
}

# ========== [Section] One-shot Installer Flow =================================
noninteractive_install(){
  local DOMAIN="${TRAFFICX_DOMAIN-}" PORT="${TRAFFICX_PORT-}" VERSION="${TRAFFICX_VERSION-}"
  [[ -n "${DOMAIN}" ]] || read -r -p "$(echo -e "${CYAN}Enter domain (e.g. example.com): ${NC}")" DOMAIN
  [[ -n "${PORT}" ]] || { read -r -p "$(echo -e "${CYAN}Enter HTTPS port [default 5000]: ${NC}")" PORT; PORT=${PORT:-5000}; }

  fresh_cleanup
  ensure_user
  install_prereqs
  fetch_app "${VERSION:-latest}"
  setup_venv
  prepare_paths
  local pair; pair=$(issue_cert_http01_or_selfsigned "${DOMAIN}")
  local CERT_FILE="${pair%%:*}" KEY_FILE="${pair##*:}"
  write_unit "${DOMAIN}" "${PORT}" "${CERT_FILE}" "${KEY_FILE}"
  install_logrotate
  start_service

  echo; ok "Installation complete!"
  echo -e "${GREEN}App URL (HTTPS):${NC} https://${DOMAIN}:${PORT}"
  echo -e "${GREEN}Certs:${NC} ${CERT_FILE}  ${KEY_FILE}"
  echo -e "${GREEN}Log:${NC}   ${LOG_FILE}"
}

# ========== [Section] Bootstrap Run ==========================================
require_root
ensure_ubuntu
install_cli        # make the checker-x menu tool available globally
noninteractive_install
