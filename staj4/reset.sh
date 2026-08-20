#!/usr/bin/env bash
# ==============================================================================
# UBUNTU ENVIRONMENT SAFE CLEANUP & RESET SCRIPT (reset.sh)
# ==============================================================================
# This script safely cleans active firewall bans, terminates lingering test
# processes, flushes IPTables/UFW, cleans temporary FIFO pipes, and resets the
# database without deleting any Python code, modules, or .joblib model files.
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "=============================================================================="
echo "          SAFE UBUNTU ENVIRONMENT CLEANUP & RESET SCRIPT                      "
echo "=============================================================================="
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] ERROR: This reset script must be executed as root (sudo).${NC}"
    echo -e "${YELLOW}[*] Usage: sudo bash reset.sh${NC}"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "${GREEN}[+] Project Directory Preserved: ${PROJECT_DIR}${NC}"

# 1. Stop SIEM Background Service & Lingering Test Processes
echo -e "\n${BLUE}[1/5] Stopping SIEM service and terminating test processes...${NC}"
systemctl stop siem-monitor 2>/dev/null || true
pkill -9 -f "python3 main.py" 2>/dev/null || true
pkill -9 -f "python3 manage.py" 2>/dev/null || true
pkill -9 -f "siem_test" 2>/dev/null || true
echo -e "${GREEN}[OK] All SIEM background processes stopped.${NC}"

# 2. Flush Firewall Bans & Reset UFW / IPTables (Preserves SSH Port 22)
echo -e "\n${BLUE}[2/5] Flushing firewall bans and resetting IPTables/UFW rules...${NC}"
# Flush custom SIEM chains and standard filter tables
iptables -F SIEM_BAN_CHAIN 2>/dev/null || true
iptables -F INPUT 2>/dev/null || true
iptables -P INPUT ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true

ip6tables -F SIEM_BAN_CHAIN_V6 2>/dev/null || true
ip6tables -F INPUT 2>/dev/null || true
ip6tables -P INPUT ACCEPT 2>/dev/null || true

if command -v ufw >/dev/null 2>&1; then
    # Ensure SSH port 22 is always open so you are never locked out
    ufw allow 22/tcp >/dev/null 2>&1 || true
    ufw reload >/dev/null 2>&1 || true
fi
echo -e "${GREEN}[OK] Firewall restrictions and IP bans completely cleared.${NC}"

# 3. Clean Temporary Test Files & Named Pipes
echo -e "\n${BLUE}[3/5] Cleaning temporary test pipes and socket files...${NC}"
rm -rf /tmp/siem_* /tmp/test* /tmp/backpipe 2>/dev/null || true
echo -e "${GREEN}[OK] Temporary /tmp artifacts removed.${NC}"

# 4. Reset Linux Kernel Audit Rules
echo -e "\n${BLUE}[4/5] Resetting Linux kernel auditd rules...${NC}"
if command -v auditctl >/dev/null 2>&1; then
    auditctl -D 2>/dev/null || true
    echo -e "${GREEN}[OK] Kernel auditd rules reset to default clean state.${NC}"
fi

# 5. Clean Database Runtime State (Preserves Models and Code)
echo -e "\n${BLUE}[5/5] Resetting SQLite events database and runtime logs...${NC}"
cd "$PROJECT_DIR"
rm -f security_events.db security_events.db-wal security_events.db-shm 2>/dev/null || true
rm -f log.json 2>/dev/null || true
touch log.json
echo -e "${GREEN}[OK] Database and runtime log queues reset.${NC}"

# ==============================================================================
# SUMMARY
# ==============================================================================
echo -e "\n${GREEN}"
echo "=============================================================================="
echo "       UBUNTU ENVIRONMENT CLEANED AND RESET TO PRISTINE STATE!                "
echo "=============================================================================="
echo -e "${NC}"
echo -e "[*] ${GREEN}Preserved:${NC} All Python files (*.py), .joblib AI models, and setup scripts."
echo -e "[*] ${GREEN}Cleared:${NC} All active IP bans, firewall drops, test processes, and SQLite databases."
echo ""
echo -e "You can now start a fresh monitoring session with:"
echo -e "  ${YELLOW}sudo python3 main.py${NC}"
echo "=============================================================================="
