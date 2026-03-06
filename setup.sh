#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# SignFlow — Lightsail Ubuntu 24.04 Setup Script
# Repo   : https://github.com/mawegrzyn-ux/simpleForm
# Domain : wingvibes.com  (13.37.62.63)
# Auth0  : obscurekitty tenant · wingvibes application
#
# Run as the default ubuntu user (NOT root):
#   chmod +x setup.sh && ./setup.sh
#
# What this script does:
#   1.  System update + essential packages
#   2.  Swap file (prevents OOM on 1 GB instances during npm install)
#   3.  UFW firewall (SSH / HTTP / HTTPS only)
#   4.  fail2ban (SSH brute-force protection — Ubuntu 24.04 compatible)
#   5.  Unattended security updates
#   6.  Node.js 20 LTS
#   7.  PM2 process manager + log-rotate module
#   8.  GitHub deploy key generation + instructions to add to repo
#   9.  Clone repo from GitHub
#   10. Create .env file with secrets (prompts you)
#   11. npm install
#   12. Initialise data files if missing
#   13. Start app with PM2 + configure auto-start on reboot
#   14. Nginx reverse proxy
#   15. DNS verification before Certbot
#   16. Certbot SSL (Let's Encrypt) — automatic renewal included
#   17. Daily backup cron for data/ directory (7-day retention)
#   18. SSH hardening (disable password auth + root login)
#   19. Quick-deploy script for future updates
#   20. Final summary with Auth0 checklist
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}▸ $*${RESET}"; }
success() { echo -e "${GREEN}✔ $*${RESET}"; }
warn()    { echo -e "${YELLOW}⚠ $*${RESET}"; }
error()   { echo -e "${RED}✖ $*${RESET}"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}\n"; }

# ── Pre-flight ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] && error "Do not run as root. Run as the 'ubuntu' user: ./setup.sh"

# Confirm Ubuntu 24.04
OS_VERSION=$(lsb_release -rs 2>/dev/null || echo "unknown")
if [[ "${OS_VERSION}" != "24.04" ]]; then
  warn "This script is optimised for Ubuntu 24.04. Detected: ${OS_VERSION}. Continuing anyway..."
fi

section "SignFlow — Lightsail Ubuntu 24.04 Setup"
echo -e "Repo   : ${BOLD}https://github.com/mawegrzyn-ux/simpleForm${RESET}"
echo -e "Domain : ${BOLD}wingvibes.com${RESET} (13.37.62.63)"
echo -e "Auth0  : ${BOLD}obscurekitty${RESET} tenant · ${BOLD}wingvibes${RESET} application"
echo -e "User   : ${BOLD}$(whoami)${RESET} on ${BOLD}$(hostname)${RESET}"
echo ""

# ── Pre-filled known values ───────────────────────────────────────────────────
DOMAIN="wingvibes.com"
STATIC_IP="13.37.62.63"
AUTH0_TENANT_DOMAIN="obscurekitty"   # will be expanded to full domain below

# ── Prompt only for what we don't know ───────────────────────────────────────
echo -e "${BOLD}A few things needed before we start:${RESET}"
echo ""

# Auth0 — tenant domain format (could be .us.auth0.com or .eu.auth0.com etc.)
echo -e "${CYAN}Auth0 tenant:${RESET} obscurekitty"
read -rp "  Full Auth0 domain (e.g. obscurekitty.us.auth0.com): " AUTH0_DOMAIN
[[ -z "${AUTH0_DOMAIN}" ]] && error "Auth0 domain is required."

echo ""
echo -e "${CYAN}Auth0 application:${RESET} wingvibes"
echo -e "  Find Client ID + Secret in Auth0 Dashboard → Applications → wingvibes"
read -rp "  Client ID    : " AUTH0_CLIENT_ID
[[ -z "${AUTH0_CLIENT_ID}" ]] && error "Client ID is required."
read -rp "  Client Secret: " -s AUTH0_CLIENT_SECRET; echo ""
[[ -z "${AUTH0_CLIENT_SECRET}" ]] && error "Client Secret is required."

echo ""
read -rp "$(echo -e "${BOLD}hCaptcha secret key${RESET} (press Enter to skip for now): ")" HCAPTCHA_SECRET; echo ""
read -rp "$(echo -e "${BOLD}Email address${RESET} for Let's Encrypt certificate: ")" ADMIN_EMAIL
[[ -z "${ADMIN_EMAIL}" ]] && error "Email is required for SSL certificate."

# Derived values
AUTH0_CALLBACK_URL="https://${DOMAIN}/auth/callback"
SESSION_SECRET=$(openssl rand -hex 32 2>/dev/null || cat /proc/sys/kernel/random/uuid | tr -d '-')

echo ""
echo -e "${BOLD}Config summary:${RESET}"
echo -e "  Domain          : ${CYAN}${DOMAIN}${RESET} (${STATIC_IP})"
echo -e "  Auth0 domain    : ${CYAN}${AUTH0_DOMAIN}${RESET}"
echo -e "  Callback URL    : ${CYAN}${AUTH0_CALLBACK_URL}${RESET}"
echo -e "  Admin role      : ${CYAN}signflow-admin${RESET}"
echo -e "  SSL email       : ${CYAN}${ADMIN_EMAIL}${RESET}"
echo ""
read -rp "Looks good? Press Enter to continue (Ctrl+C to abort)..."

APP_DIR="/home/ubuntu/signflow"
BACKUP_DIR="/home/ubuntu/backups/signflow"
CLONE_URL="git@github-signflow:mawegrzyn-ux/simpleForm.git"
DEPLOY_KEY_PATH="/home/ubuntu/.ssh/signflow_deploy"

APP_DIR="/home/ubuntu/signflow"
BACKUP_DIR="/home/ubuntu/backups/signflow"
GITHUB_REPO="git@github.com:mawegrzyn-ux/simpleForm.git"
DEPLOY_KEY_PATH="/home/ubuntu/.ssh/signflow_deploy"

# ═══════════════════════════════════════════════════════════════════════════════
section "1 · System update & packages"
# ═══════════════════════════════════════════════════════════════════════════════
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
sudo apt-get install -y -qq \
  git curl wget gnupg2 ca-certificates \
  nginx certbot python3-certbot-nginx \
  ufw fail2ban \
  unattended-upgrades apt-listchanges \
  logrotate cron jq
success "Packages installed"

# ═══════════════════════════════════════════════════════════════════════════════
section "2 · Swap file (1 GB)"
# ═══════════════════════════════════════════════════════════════════════════════
if [[ ! -f /swapfile ]]; then
  sudo fallocate -l 1G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null
  # Tune swappiness for a server (default 60 is too aggressive)
  echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf > /dev/null
  sudo sysctl -p > /dev/null
  success "1 GB swap created and enabled"
else
  warn "Swap file already exists — skipping"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "3 · UFW firewall"
# ═══════════════════════════════════════════════════════════════════════════════
sudo ufw --force reset > /dev/null
sudo ufw default deny incoming > /dev/null
sudo ufw default allow outgoing > /dev/null
sudo ufw allow OpenSSH > /dev/null
sudo ufw allow 'Nginx Full' > /dev/null
sudo ufw --force enable > /dev/null
success "UFW enabled: SSH + HTTP + HTTPS allowed"

# ═══════════════════════════════════════════════════════════════════════════════
section "4 · fail2ban (Ubuntu 24.04 compatible)"
# ═══════════════════════════════════════════════════════════════════════════════
# Ubuntu 24.04 uses nftables by default and journald for SSH logs.
# The banaction must be nftables-based; backend must be systemd.
sudo tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
[DEFAULT]
bantime   = 3600
findtime  = 600
maxretry  = 5
backend   = systemd
banaction = nftables-multiport
banaction_allports = nftables-allports

[sshd]
enabled  = true
port     = ssh
filter   = sshd
maxretry = 5
EOF
sudo systemctl enable fail2ban --quiet
sudo systemctl restart fail2ban
success "fail2ban configured (SSH: 5 attempts → 1h ban, nftables backend)"

# ═══════════════════════════════════════════════════════════════════════════════
section "5 · Automatic security updates"
# ═══════════════════════════════════════════════════════════════════════════════
sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
success "Unattended security updates enabled"

# ═══════════════════════════════════════════════════════════════════════════════
section "6 · Node.js 20 LTS"
# ═══════════════════════════════════════════════════════════════════════════════
if ! command -v node &> /dev/null || [[ $(node -v | cut -d. -f1 | tr -d 'v') -lt 20 ]]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - > /dev/null 2>&1
  sudo apt-get install -y -qq nodejs
  success "Node.js $(node -v) installed"
else
  success "Node.js $(node -v) already present"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "7 · PM2 + log rotation"
# ═══════════════════════════════════════════════════════════════════════════════
sudo npm install -g pm2 --silent
pm2 install pm2-logrotate --silent 2>/dev/null || true
pm2 set pm2-logrotate:max_size 10M 2>/dev/null || true
pm2 set pm2-logrotate:retain 7 2>/dev/null || true
pm2 set pm2-logrotate:compress true 2>/dev/null || true
success "PM2 $(pm2 -v) + log rotation ready"

# ═══════════════════════════════════════════════════════════════════════════════
section "8 · GitHub deploy key"
# ═══════════════════════════════════════════════════════════════════════════════
mkdir -p ~/.ssh
chmod 700 ~/.ssh

if [[ ! -f "${DEPLOY_KEY_PATH}" ]]; then
  ssh-keygen -t ed25519 -C "signflow-deploy@$(hostname)" -f "${DEPLOY_KEY_PATH}" -N "" -q
  success "Deploy key generated: ${DEPLOY_KEY_PATH}"
else
  warn "Deploy key already exists at ${DEPLOY_KEY_PATH} — reusing"
fi

# Configure SSH to use this key for GitHub
cat >> ~/.ssh/config <<EOF

# SignFlow deploy key for GitHub
Host github-signflow
  HostName github.com
  User git
  IdentityFile ${DEPLOY_KEY_PATH}
  IdentitiesOnly yes
EOF

chmod 600 ~/.ssh/config 2>/dev/null || true

echo ""
echo -e "${BOLD}${YELLOW}ACTION REQUIRED — Add this deploy key to GitHub:${RESET}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "1. Go to: ${CYAN}https://github.com/mawegrzyn-ux/simpleForm/settings/keys${RESET}"
echo -e "2. Click ${BOLD}Add deploy key${RESET}"
echo -e "3. Title: ${BOLD}Lightsail $(hostname)${RESET}"
echo -e "4. Paste this public key:\n"
cat "${DEPLOY_KEY_PATH}.pub"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
read -rp "Press Enter once you have added the key to GitHub..."

# Verify connection
info "Verifying GitHub connection..."
ssh -o StrictHostKeyChecking=no -T git@github.com 2>&1 | grep -q "successfully authenticated" \
  && success "GitHub SSH connection verified" \
  || warn "Could not verify GitHub connection — continuing anyway"

# ═══════════════════════════════════════════════════════════════════════════════
section "9 · Clone repository"
# ═══════════════════════════════════════════════════════════════════════════════
# Use the deploy key host alias
CLONE_URL="git@github-signflow:mawegrzyn-ux/simpleForm.git"

if [[ -d "${APP_DIR}/.git" ]]; then
  warn "Repo already cloned — pulling latest changes"
  cd "${APP_DIR}" && git pull
else
  git clone "${CLONE_URL}" "${APP_DIR}"
  success "Repo cloned to ${APP_DIR}"
fi

cd "${APP_DIR}"

# ═══════════════════════════════════════════════════════════════════════════════
section "10 · Create .env file"
# ═══════════════════════════════════════════════════════════════════════════════
if [[ -f "${APP_DIR}/.env" ]]; then
  warn ".env already exists — not overwriting. Edit manually if needed: nano ${APP_DIR}/.env"
else
  cat > "${APP_DIR}/.env" <<EOF
# SignFlow secrets — DO NOT COMMIT THIS FILE

# Auth0
AUTH0_DOMAIN=${AUTH0_DOMAIN}
AUTH0_CLIENT_ID=${AUTH0_CLIENT_ID}
AUTH0_CLIENT_SECRET=${AUTH0_CLIENT_SECRET}
AUTH0_CALLBACK_URL=${AUTH0_CALLBACK_URL}
AUTH0_ADMIN_ROLE=signflow-admin
SESSION_SECRET=${SESSION_SECRET}

# hCaptcha (optional)
SF_HCAPTCHA_SECRET=${HCAPTCHA_SECRET:-}

# App
PORT=3000
NODE_ENV=production
EOF
  chmod 600 "${APP_DIR}/.env"
  success ".env created (chmod 600)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "11 · npm install"
# ═══════════════════════════════════════════════════════════════════════════════
cd "${APP_DIR}"
npm install --omit=dev
success "Dependencies installed"

# ═══════════════════════════════════════════════════════════════════════════════
section "12 · Initialise data files"
# ═══════════════════════════════════════════════════════════════════════════════
mkdir -p "${APP_DIR}/data" "${APP_DIR}/public/uploads"

if [[ ! -f "${APP_DIR}/data/subscribers.json" ]]; then
  echo '[]' > "${APP_DIR}/data/subscribers.json"
  success "data/subscribers.json created"
fi

if [[ ! -f "${APP_DIR}/data/config.json" ]]; then
  # Copy default if it exists in repo, otherwise create minimal one
  if [[ -f "${APP_DIR}/data/config.json.example" ]]; then
    cp "${APP_DIR}/data/config.json.example" "${APP_DIR}/data/config.json"
  else
    cat > "${APP_DIR}/data/config.json" <<'CONFJSON'
{
  "site": {
    "title": "Stay in the Loop",
    "favicon": "",
    "adminPassword": "changeme123",
    "cookieBannerText": "We use cookies to manage your subscription preferences and ensure GDPR compliance.",
    "privacyPolicyUrl": "/privacy",
    "unsubscribeEnabled": true,
    "captchaEnabled": false,
    "hcaptchaSiteKey": "",
    "hcaptchaSecretKey": ""
  },
  "design": {
    "googleFont": "Playfair Display",
    "bodyFont": "Lato",
    "primaryColor": "#1a1a2e",
    "accentColor": "#e94560",
    "backgroundColor": "#f8f5f0",
    "textColor": "#1a1a2e",
    "buttonText": "Subscribe Now",
    "buttonRadius": "4px",
    "containerWidth": "600px",
    "backgroundImage": "",
    "backgroundOverlay": 0.4,
    "logoUrl": "",
    "logoWidth": "180px"
  },
  "sections": [
    { "id": "hero",   "type": "hero",   "visible": true, "heading": "Don't Miss a Thing", "subheading": "Join our newsletter.", "imageUrl": "", "imagePosition": "above" },
    { "id": "form",   "type": "form",   "visible": true, "submitSuccessMessage": "🎉 You're in!", "submitErrorMessage": "Something went wrong." },
    { "id": "footer", "type": "footer", "visible": true, "text": "© 2025 · Unsubscribe anytime." }
  ],
  "fields": [
    { "id": "email",     "label": "Email Address", "type": "email", "required": true,  "placeholder": "you@example.com",   "system": true  },
    { "id": "firstName", "label": "First Name",    "type": "text",  "required": true,  "placeholder": "Your first name",   "system": false },
    { "id": "lastName",  "label": "Last Name",     "type": "text",  "required": false, "placeholder": "Your last name",    "system": false }
  ]
}
CONFJSON
  fi
  success "data/config.json created"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "13 · PM2 — start app & configure auto-start"
# ═══════════════════════════════════════════════════════════════════════════════
cd "${APP_DIR}"

# Stop existing instance if running
pm2 delete signflow 2>/dev/null || true

pm2 start server.js \
  --name signflow \
  --time \
  --max-memory-restart 300M \
  --restart-delay 3000

pm2 save

# Generate and run the startup command automatically
STARTUP_CMD=$(pm2 startup systemd -u ubuntu --hp /home/ubuntu 2>&1 | grep "sudo env" | head -1)
if [[ -n "${STARTUP_CMD}" ]]; then
  eval "sudo ${STARTUP_CMD#sudo }"
  success "PM2 auto-start on boot configured"
else
  warn "Could not auto-configure PM2 startup. Run manually: pm2 startup"
fi

success "SignFlow running via PM2"

# ═══════════════════════════════════════════════════════════════════════════════
section "14 · Nginx reverse proxy"
# ═══════════════════════════════════════════════════════════════════════════════
NGINX_CONF="/etc/nginx/sites-available/signflow"

if [[ -n "${DOMAIN}" ]]; then
  sudo tee "${NGINX_CONF}" > /dev/null <<EOF
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Allow embedding from external sites (for /embed route)
    location /embed {
        add_header X-Frame-Options "" always;
        add_header Content-Security-Policy "frame-ancestors *" always;
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    client_max_body_size 10M;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
else
  # No domain — listen on all interfaces, useful for IP-only access
  sudo tee "${NGINX_CONF}" > /dev/null <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    client_max_body_size 10M;

    location /embed {
        add_header X-Frame-Options "" always;
        add_header Content-Security-Policy "frame-ancestors *" always;
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF
fi

# Remove default site if it exists
sudo rm -f /etc/nginx/sites-enabled/default

# Enable signflow site
sudo ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/signflow

sudo nginx -t && sudo systemctl reload nginx
success "Nginx configured and reloaded"

# ═══════════════════════════════════════════════════════════════════════════════
section "15 · DNS verification"
# ═══════════════════════════════════════════════════════════════════════════════
info "Checking that ${DOMAIN} resolves to ${STATIC_IP}..."
RESOLVED_IP=$(dig +short "${DOMAIN}" A | tail -1 || true)
WWW_RESOLVED=$(dig +short "www.${DOMAIN}" A | tail -1 || true)

if [[ "${RESOLVED_IP}" == "${STATIC_IP}" ]]; then
  success "${DOMAIN} → ${RESOLVED_IP} ✔"
else
  warn "${DOMAIN} resolves to '${RESOLVED_IP}' (expected ${STATIC_IP})"
  warn "Certbot will fail if DNS hasn't propagated yet."
  read -rp "Continue anyway? (y/N): " DNS_CONT
  [[ "${DNS_CONT,,}" != "y" ]] && error "Aborting. Fix DNS first, then re-run from step 16."
fi

if [[ "${WWW_RESOLVED}" == "${STATIC_IP}" ]]; then
  success "www.${DOMAIN} → ${WWW_RESOLVED} ✔"
  CERTBOT_DOMAINS="${DOMAIN},www.${DOMAIN}"
else
  warn "www.${DOMAIN} does not resolve to ${STATIC_IP} (got '${WWW_RESOLVED}')"
  warn "Requesting certificate for ${DOMAIN} only (no www)."
  CERTBOT_DOMAINS="${DOMAIN}"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "16 · SSL with Let's Encrypt"
# ═══════════════════════════════════════════════════════════════════════════════
info "Requesting certificate for ${CERTBOT_DOMAINS}..."
sudo certbot --nginx \
  --non-interactive \
  --agree-tos \
  --email "${ADMIN_EMAIL}" \
  --domains "${CERTBOT_DOMAINS}" \
  --redirect \
  2>&1 | tail -8

# Verify auto-renewal timer (Ubuntu 24.04 uses systemd timer, not cron)
if sudo systemctl is-active certbot.timer &>/dev/null; then
  success "Certbot systemd auto-renewal timer already active"
else
  sudo systemctl enable --now certbot.timer
  success "Certbot auto-renewal timer enabled"
fi

success "SSL certificate installed for ${CERTBOT_DOMAINS}"

# ═══════════════════════════════════════════════════════════════════════════════
section "17 · Daily backup cron (7-day retention)"
# ═══════════════════════════════════════════════════════════════════════════════
mkdir -p "${BACKUP_DIR}"

BACKUP_SCRIPT="/home/ubuntu/signflow-backup.sh"
cat > "${BACKUP_SCRIPT}" <<EOF
#!/usr/bin/env bash
# SignFlow daily backup
BACKUP_DIR="${BACKUP_DIR}"
APP_DIR="${APP_DIR}"
DATE=\$(date +%Y%m%d_%H%M%S)

mkdir -p "\${BACKUP_DIR}"

# Backup data directory
tar -czf "\${BACKUP_DIR}/data-\${DATE}.tar.gz" -C "\${APP_DIR}" data/

# Backup uploads directory
tar -czf "\${BACKUP_DIR}/uploads-\${DATE}.tar.gz" -C "\${APP_DIR}" public/uploads/ 2>/dev/null || true

# Remove backups older than 7 days
find "\${BACKUP_DIR}" -name "*.tar.gz" -mtime +7 -delete

echo "[\$(date)] Backup complete: data-\${DATE}.tar.gz"
EOF
chmod +x "${BACKUP_SCRIPT}"

# Add cron job at 02:30 daily (avoid exact hour to reduce server load spikes)
CRON_JOB="30 2 * * * ${BACKUP_SCRIPT} >> /home/ubuntu/backup.log 2>&1"
(crontab -l 2>/dev/null | grep -v "signflow-backup"; echo "${CRON_JOB}") | crontab -

success "Daily backup cron set (02:30 UTC, 7-day retention → ${BACKUP_DIR})"

# ═══════════════════════════════════════════════════════════════════════════════
section "18 · SSH hardening"
# ═══════════════════════════════════════════════════════════════════════════════
# Only harden if we can confirm the ubuntu user has a key set up
if [[ -f "/home/ubuntu/.ssh/authorized_keys" && -s "/home/ubuntu/.ssh/authorized_keys" ]]; then
  sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sudo sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
  # Add if not present
  grep -q "^MaxAuthTries" /etc/ssh/sshd_config || echo "MaxAuthTries 3" | sudo tee -a /etc/ssh/sshd_config > /dev/null
  grep -q "^ClientAliveInterval" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" | sudo tee -a /etc/ssh/sshd_config > /dev/null

  sudo systemctl reload sshd
  success "SSH hardened: password auth disabled, root login disabled"
else
  warn "Skipping SSH hardening — no authorized_keys found."
  warn "Add your public key to ~/.ssh/authorized_keys first, then re-run the hardening block."
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "19 · Quick-deploy script (for future updates)"
# ═══════════════════════════════════════════════════════════════════════════════
cat > /home/ubuntu/deploy.sh <<EOF
#!/usr/bin/env bash
# Run this to pull latest code and restart SignFlow
set -e
cd ${APP_DIR}
echo "▸ Pulling latest from GitHub..."
git pull
echo "▸ Installing dependencies..."
npm install --omit=dev
echo "▸ Restarting app..."
pm2 restart signflow
pm2 save
echo "✔ Deploy complete — \$(date)"
EOF
chmod +x /home/ubuntu/deploy.sh
success "Quick-deploy script created: ~/deploy.sh"

# ═══════════════════════════════════════════════════════════════════════════════
section "20 · Setup Complete"
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${GREEN}Everything is running. Here's your summary:${RESET}"
echo ""
echo -e "  ${BOLD}Signup page  :${RESET} ${CYAN}https://${DOMAIN}/${RESET}"
echo -e "  ${BOLD}Admin panel  :${RESET} ${CYAN}https://${DOMAIN}/admin${RESET}"
echo -e "  ${BOLD}Auth login   :${RESET} ${CYAN}https://${DOMAIN}/auth/login${RESET}"
echo -e "  ${BOLD}Embed JS     :${RESET} ${CYAN}https://${DOMAIN}/embed.js${RESET}"
echo -e "  ${BOLD}SSL          :${RESET} ${GREEN}Enabled via Let's Encrypt${RESET}"
echo ""
echo -e "  ${BOLD}App directory:${RESET} ${APP_DIR}"
echo -e "  ${BOLD}Secrets      :${RESET} ${APP_DIR}/.env  (chmod 600)"
echo -e "  ${BOLD}Backups      :${RESET} ${BACKUP_DIR}  (daily 02:30 UTC, 7-day retention)"
echo -e "  ${BOLD}PM2 logs     :${RESET} pm2 logs signflow"
echo -e "  ${BOLD}Future deploy:${RESET} ~/deploy.sh"
echo ""
echo -e "${BOLD}${YELLOW}Final checklist:${RESET}"
echo -e "  ${YELLOW}□${RESET} Open ports 80 + 443 in Lightsail console → Networking (if not already open)"
echo ""
echo -e "${BOLD}${CYAN}Auth0 — 3 steps remaining (application 'wingvibes' already exists):${RESET}"
echo -e "  ${CYAN}1.${RESET} In Auth0 Dashboard → Applications → ${BOLD}wingvibes${RESET} → Settings:"
echo -e "     • Allowed Callback URLs : ${BOLD}${AUTH0_CALLBACK_URL}${RESET}"
echo -e "     • Allowed Logout URLs   : ${BOLD}https://${DOMAIN}${RESET}"
echo -e "     • Save Changes"
echo ""
echo -e "  ${CYAN}2.${RESET} Auth0 → User Management → Roles → ${BOLD}Create Role${RESET}"
echo -e "     Name: ${BOLD}signflow-admin${RESET}  →  assign it to your user"
echo ""
echo -e "  ${CYAN}3.${RESET} Auth0 → Actions → Flows → ${BOLD}Login${RESET} → Add Action → Build Custom:"
echo -e "     Name: ${BOLD}Add roles to token${RESET}"
echo -e "${YELLOW}     ┌─────────────────────────────────────────────────────────────┐"
echo -e "     │ exports.onExecutePostLogin = async (event, api) => {        │"
echo -e "     │   const ns = 'https://signflow/roles';                      │"
echo -e "     │   const roles = event.authorization?.roles || [];           │"
echo -e "     │   api.idToken.setCustomClaim(ns, roles);                    │"
echo -e "     │   api.accessToken.setCustomClaim(ns, roles);                │"
echo -e "     │ };                                                          │"
echo -e "     └─────────────────────────────────────────────────────────────┘${RESET}"
echo -e "     Deploy the action, then drag it into the Login flow."
echo ""
echo -e "  ${YELLOW}□${RESET} Then visit ${CYAN}https://${DOMAIN}/admin${RESET} — you should be redirected to Auth0 login"
echo -e "  ${YELLOW}□${RESET} Enable hCaptcha in admin → Settings once signed in"
echo -e "  ${YELLOW}□${RESET} Run ${CYAN}npm audit${RESET} in ${APP_DIR} periodically"
echo ""
echo -e "${GREEN}${BOLD}SignFlow is live on wingvibes.com 🚀${RESET}"
echo ""
