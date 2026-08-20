#!/usr/bin/env bash
# ==============================================================================
# ENTERPRISE SIEM & AI SECURITY PLATFORM AUTOMATED SETUP SCRIPT (setup.sh)
# ==============================================================================
# This script configures all system requirements, Linux kernel audit hooks,
# firewall prerequisites, Python dependencies, and systemd service orchestration.
# ==============================================================================

set -e

# ANSI Color Codes for Professional SOC Logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "=============================================================================="
echo "      ENTERPRISE SIEM & AI SECURITY MONITORING PLATFORM SETUP                "
echo "=============================================================================="
echo -e "${NC}"

# 1. Check Root Privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] ERROR: This installation script must be executed as root (sudo).${NC}"
    echo -e "${YELLOW}[*] Usage: sudo bash setup.sh${NC}"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "${GREEN}[+] Current Project Root: ${PROJECT_DIR}${NC}"

# 2. Update Linux Package Repositories & Install System Dependencies
echo -e "\n${BLUE}[1/7] Updating package index and installing system dependencies...${NC}"
apt-get update -y

PACKAGES=(
    python3
    python3-pip
    python3-dev
    python3-setuptools
    build-essential
    ufw
    iptables
    ip6tables
    conntrack
    auditd
    libaudit-dev
    net-tools
    iproute2
    psmisc
    curl
    procps
    rsyslog
)

for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] Installing ${pkg}...${NC}"
        apt-get install -y "$pkg"
    else
        echo -e "${GREEN}[OK] Package ${pkg} already installed.${NC}"
    fi
done

# 3. Install Python Dependencies
echo -e "\n${BLUE}[2/7] Installing Python AI & Security libraries...${NC}"
python3 -m pip install --upgrade pip setuptools wheel

PYTHON_DEPS=(
    "psutil>=5.9.0"
    "numpy>=1.23.0"
    "scipy>=1.9.0"
    "scikit-learn>=1.2.0"
    "joblib>=1.2.0"
    "requests>=2.28.0"
)

for dep in "${PYTHON_DEPS[@]}"; do
    echo -e "${YELLOW}[*] Installing Python dependency: ${dep}...${NC}"
    python3 -m pip install "$dep"
done

# 4. Create Project Log & Model Directories
echo -e "\n${BLUE}[3/7] Initializing project directory structure...${NC}"
mkdir -p "${PROJECT_DIR}/logs"
mkdir -p "${PROJECT_DIR}/models/numpy_ensemble"
mkdir -p "${PROJECT_DIR}/models/numpy_autoencoder"

touch "${PROJECT_DIR}/logs/activity_records.jsonl"
touch "${PROJECT_DIR}/logs/readable_activity.log"
touch "${PROJECT_DIR}/log.json"

chmod -R 750 "${PROJECT_DIR}/logs"
echo -e "${GREEN}[OK] Log and model directories verified.${NC}"

# 5. Configure Linux Kernel Auditd Rules for Sensitive Files
echo -e "\n${BLUE}[4/7] Configuring Linux Kernel auditd syscall monitoring...${NC}"
if command -v auditctl >/dev/null 2>&1; then
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
    
    # Add persistent audit rules for credential and sudoers integrity
    auditctl -w /etc/shadow -p rwa -k siem_shadow 2>/dev/null || true
    auditctl -w /etc/sudoers -p rwa -k siem_sudoers 2>/dev/null || true
    auditctl -w /etc/sudoers.d/ -p rwa -k siem_sudoers 2>/dev/null || true
    auditctl -w /var/log/auth.log -p rwa -k siem_auth 2>/dev/null || true
    echo -e "${GREEN}[OK] Kernel auditd watches active on /etc/shadow and /etc/sudoers.${NC}"
else
    echo -e "${YELLOW}[!] auditctl utility not found, skipping kernel audit rule injection.${NC}"
fi

# 6. Install Global Interactive Shell Audit Hook
echo -e "\n${BLUE}[5/7] Installing system-wide interactive shell audit hook...${NC}"
HOOK_PATH="/etc/profile.d/siem_audit.sh"
cat << 'EOF' > "$HOOK_PATH"
# SIEM Real-Time Interactive Shell Command Audit Hook
export PROMPT_COMMAND='logger -p auth.notice -t siem_audit "user=$USER tty=$(tty 2>/dev/null | sed "s#/dev/##") cmd=\"$(history 1 | sed "s/^[ ]*[0-9]*[ ]*//")\"" 2>/dev/null'
EOF
chmod 644 "$HOOK_PATH"

BASHRC_PATH="/etc/bash.bashrc"
if [ -f "$BASHRC_PATH" ]; then
    if ! grep -q "siem_audit" "$BASHRC_PATH"; then
        echo -e "\n# SIEM Interactive Shell Audit Hook\nexport PROMPT_COMMAND='logger -p auth.notice -t siem_audit \"user=\$USER tty=\$(tty 2>/dev/null | sed \"s#/dev/##\") cmd=\\\"\$(history 1 | sed \"s/^[ ]*[0-9]*[ ]*//\")\\\"\" 2>/dev/null'" >> "$BASHRC_PATH"
    fi
fi
echo -e "${GREEN}[OK] Shell audit hook installed in /etc/profile.d and /etc/bash.bashrc.${NC}"

# 7. Configure Linux File Descriptor Limits & Firewall Defaults
echo -e "\n${BLUE}[6/7] Optimizing system resource limits and UFW firewall...${NC}"
if command -v ufw >/dev/null 2>&1; then
    # Ensure SSH port 22 is always open before starting firewall
    ufw allow 22/tcp >/dev/null 2>&1 || true
    echo -e "${GREEN}[OK] UFW configured with safe SSH port 22 allow rule.${NC}"
fi

# 8. Create Systemd Service File (Optional Background Auto-Start)
echo -e "\n${BLUE}[7/7] Generating systemd service file (/etc/systemd/system/siem-monitor.service)...${NC}"
SERVICE_FILE="/etc/systemd/system/siem-monitor.service"
PYTHON_BIN=$(which python3)

cat << EOF > "$SERVICE_FILE"
[Unit]
Description=Enterprise SIEM & AI Security Monitoring Platform
After=network.target network-online.target systemd-journald.service auditd.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PYTHON_BIN} ${PROJECT_DIR}/main.py
Restart=always
RestartSec=3
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"
systemctl daemon-reload
echo -e "${GREEN}[OK] systemd service created: siem-monitor.service${NC}"

# ==============================================================================
# INSTALLATION COMPLETE SUMMARY
# ==============================================================================
echo -e "\n${GREEN}"
echo "=============================================================================="
echo "           SIEM & AI DEFENSE PLATFORM INSTALLED SUCCESSFULLY!                "
echo "=============================================================================="
echo -e "${NC}"
echo -e "You can run and manage the platform using either of the following methods:"
echo ""
echo -e "  ${CYAN}1. Interactive Terminal Console Mode:${NC}"
echo -e "     ${YELLOW}sudo python3 main.py${NC}"
echo ""
echo -e "  ${CYAN}2. Background Systemd Service Mode (Starts automatically on boot):${NC}"
echo -e "     ${YELLOW}sudo systemctl start siem-monitor${NC}"
echo -e "     ${YELLOW}sudo systemctl enable siem-monitor${NC}"
echo -e "     ${YELLOW}sudo systemctl status siem-monitor${NC}"
echo ""
echo -e "  ${CYAN}3. SOC Management & Audit CLI:${NC}"
echo -e "     ${YELLOW}python3 manage.py status${NC}           (System and active bans status)"
echo -e "     ${YELLOW}python3 manage.py monitor${NC}          (Interactive live SOC dashboard)"
echo -e "     ${YELLOW}python3 manage.py verify-integrity${NC} (HMAC-SHA256 log audit)"
echo ""
echo "=============================================================================="
