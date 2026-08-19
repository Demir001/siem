# -*- coding: utf-8 -*-
"""
==============================================================================
SYSTEM AND SECURITY CONFIGURATION (config.py)
==============================================================================
"""

# 1. System Resource Thresholds
CPU_USAGE_THRESHOLD = 85.0              # Overall CPU usage alert threshold (%)
CPU_USAGE_BY_CORE_THRESHOLD = 95.0      # Per-core CPU overload threshold (%)
CPU_IOWAIT_THRESHOLD = 20.0             # CPU Disk I/O wait bottleneck threshold (%)

RAM_USAGE_THRESHOLD = 85.0              # RAM usage alert threshold (%)
DISK_USAGE_READ_THRESHOLD = 100         # Disk read speed alert threshold (MB/s)
DISK_USAGE_WRITE_THRESHOLD = 100        # Disk write speed alert threshold (MB/s)
INTERNET_BANDWITH_USAGE_THRESHOLD = 100 # Network bandwidth alert threshold (MB/s)
GPU_USAGE_THRESHOLD = 85.0              # GPU/TPU resource alert threshold (%)

# 2. File and Archive Settings
FILE_SIZE_THRESHOLD = 5                 # Maximum log file size before rotation (MB)
CHECK_INTERVAL_SECONDS = 2              # Hardware metric sampling interval (Seconds)
LINUX_APP_LOG_PATH = "app.log"          # Application log path

# 3. Monitored System Log Files (Multi-File Real-Time Tailing)
SYSTEM_LOG_PATHS = [
    "/var/log/auth.log",      # Debian/Ubuntu SSH & Authentication Logs
    "/var/log/syslog",        # Debian/Ubuntu System, Network & Kernel Logs
    "/var/log/secure",        # RHEL/CentOS/Rocky Linux Security Logs
    "/var/log/messages",      # RHEL/CentOS System Logs
    "/var/log/ufw.log",       # UFW Firewall Packet Drop Logs
    "/var/log/kern.log",      # Kernel & Hardware Logs
    "logs/auth.log",          # Local Test Auth Log
    "logs/syslog"             # Local Test Syslog Log
]

# 4. Session Inactivity Timeout (Auto-Kick)
IDLE_SESSION_TIMEOUT_SECONDS = 900      # 15 Minutes (900 seconds) idle session timeout

# 5. Cumulative Security Risk & Sliding Time Window
RISK_SCORE_THRESHOLD = 50               # Cumulative risk threshold required to trigger an automatic ban
TIME_WINDOW = 600                       # Sliding time window for risk calculation (10 Minutes / 600s)

# 6. Network Segmentation (Internal LAN vs. External WAN)
INTERNAL_SUBNETS = [
    "127.0.0.0/8",       # Localhost loopback
    "10.0.0.0/8",        # Class A Private Network
    "172.16.0.0/12",     # Class B Private Network
    "192.168.0.0/16",    # Class C Private Network
    "169.254.0.0/16",    # Link-Local Subnet
    "fc00::/7",          # IPv6 Unique Local Address (ULA)
    "fe80::/10"          # IPv6 Link-Local Subnet
]

PROTECTED_IPS = [
    "127.0.0.1", "::1", "localhost", "192.168.1.1", "10.0.0.1" # Whitelist to avoid self-lockout
]

# 7. Password Typo Tolerance Thresholds
EXTERNAL_MAX_TYPOS = 8                  # Maximum tolerated typos for external WAN IPs (8 attempts)
INTERNAL_MAX_TYPOS = 8                  # Maximum tolerated typos for internal LAN users (8 attempts)
TYPO_TIME_INTERVAL_SECONDS = 1.0        # Rapid burst threshold (<1.0s between attempts triggers brute-force alert)
AUTH_FAIL_BAN_DURATION_SECONDS = 300    # Maximum 5 Minutes (300 seconds) ban duration for failed login attempts

# 8. Tiered Ban Durations by Threat Level (Seconds)
BAN_DURATIONS_EXTERNAL = {
    "CRITICAL": 3600,                   # 60 Minutes (Reverse shell, C2, memory injection, rootkit)
    "HIGH": 1800,                       # 30 Minutes (Zero-day anomaly, SQLi, RCE, network probe)
    "MEDIUM": 300,                      # 5 Minutes (Password brute-force, protocol abuse - Max 5 mins)
    "LOW": 0                            # 0 Minutes (Tolerated typo, minor warning - No ban)
}

BAN_DURATIONS_INTERNAL = {
    "CRITICAL": 900,                    # 15 Minutes (Session termination & SSH port isolation)
    "HIGH": 300,                        # 5 Minutes (Temporary service rate-limiting)
    "MEDIUM": 300,                      # 5 Minutes (Temporary rate-limiting - Max 5 mins)
    "LOW": 0                            # 0 Minutes (Tolerated typo - No ban)
}

# 9. Email Alert Settings (Disabled by Default)
ENABLE_EMAIL_ALERTS = False              # Email alerts active/inactive
SMTP_ENABLED = False                     # Master SMTP switch
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your_email@gmail.com"
RECEIVER_EMAIL = "admin@example.com"
EMAIL_PASSWORD = "your_app_password"

# Backward compatibility aliases
SMTP_HOST = SMTP_SERVER
SMTP_MAIL_ADRESS = SENDER_EMAIL
SMTP_ALERT_MAIL = RECEIVER_EMAIL
SMTP_PASSWORD = EMAIL_PASSWORD

# 10. Advanced Multi-Backend Firewall & Kernel Enforcement
ENABLE_IPTABLES_FALLBACK = True           # Direct kernel-level IPTables drop (-I INPUT 1 -j DROP)
ENABLE_SESSION_KILL = True               # Terminate active TCP/SSH socket connections on ban
ENABLE_FIREWALL_SYNC_ON_STARTUP = True   # Re-synchronize active database bans into OS firewall on boot
SQLITE_BUSY_TIMEOUT_MS = 15000           # SQLite WAL busy timeout (15 seconds)
LOGROTATE_CHECK_INTERVAL_SECONDS = 2.0   # Inode and logrotate check frequency

# 11. Distributed Botnet & Subnet / CIDR Defense
ENABLE_SUBNET_SHIELD = True              # Enable /24 & /64 CIDR botnet aggregation
SUBNET_DISTINCT_IPS_THRESHOLD = 3        # Distinct IPs attacking from same /24 or /64 subnet
SUBNET_RISK_THRESHOLD = 75.0             # Cumulative risk score across subnet to trigger CIDR ban
SUBNET_BAN_DURATION_SECONDS = 7200       # 2 Hours ban for distributed botnet CIDR blocks

# 12. File Integrity Monitoring (FIM)
ENABLE_FIM = True                        # Enable real-time file integrity monitoring
FIM_CHECK_INTERVAL_SECONDS = 5.0         # Frequency of file checksum verification
FIM_MONITORED_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/ld.so.preload",
    "/root/.ssh/authorized_keys",
    "config.py"                          # Core configuration integrity watch
]

# 13. Honeypot Decoy Port Traps
ENABLE_HONEYPOT_TRAPS = True             # Enable decoy TCP port traps
HONEYPOT_PORTS = [23, 2323, 5555, 6379, 4444, 31337] # Decoy TCP ports to trap scanners (Avoids web dev ports 8080/8888)
HONEYPOT_BAN_DURATION_SECONDS = 86400    # 24 Hours ban for honeypot probe offenders

# 14. Cryptographic HMAC-SHA256 Log Integrity Chain
ENABLE_LOG_INTEGRITY_SEAL = True         # Cryptographically seal log lines with HMAC-SHA256
LOG_SECRET_KEY_PATH = ".log_secret.key"  # Secret HMAC key storage path

# 15. Outbound C2 & Reverse Shell Beaconing Guard
ENABLE_C2_DETECTION = True               # Enable active outbound socket inspection
C2_CHECK_INTERVAL_SECONDS = 3.0          # Sampling frequency for outbound sockets