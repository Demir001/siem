# -*- coding: utf-8 -*-
"""
==============================================================================
ENTERPRISE LOG MONITORING & THREAT DETECTION ENGINE (log_monitor.py)
==============================================================================
This module provides:
1. DUAL-STACK IPv4 / IPv6 EXTRACTION & PID ATTRIBUTION:
   - Accurately captures IPv4 and IPv6 attacks with multi-line PID session memory.
2. DISTRIBUTED BOTNET & SUBNET / CIDR DEFENSE SHIELD:
   - Correlates multi-IP attacks across /24 and /64 subnets to block botnets.
3. PAYLOAD CANONICALIZATION:
   - Decodes URL, Hex, Unicode, Base64, and shell slicing before AI/Rule matching.
4. SMART FALSE-POSITIVE WHITELIST SHIELD:
   - Filters known benign system operations (Systemd, Certbot, Logrotate, Prometheus).
5. LINUX LOGROTATE & INODE TRACKING:
   - Automatically tracks inode changes and file truncations without interruption.
6. SYSTEMD-JOURNALD STREAMING:
   - Reads directly from journald on modern Linux distributions lacking rsyslog.
7. ZERO-LATENCY BANNED IP FAST-PATH:
   - Drops traffic from already-banned IPs instantly to minimize CPU usage.
==============================================================================
"""

import os
import time
import threading
import re
import json
from collections import defaultdict, deque

import config
from modules.ban_manager import BanManager
from modules.user_session_tracker import UserSessionTracker
from modules.ai_security_engine import AISecurityEngine
from modules.canonicalizer import PayloadCanonicalizer
from modules.whitelist_shield import WhitelistShield
from modules.journal_reader import JournalReader
from modules.log_parser_utils import LogParserUtils, PIDAttributionCache
from modules.subnet_shield import SubnetShield

class LogMonitor:
    def __init__(self, callback=None, ban_manager=None, session_tracker=None, ai_engine=None):
        self.callback = callback
        self.ban_manager = ban_manager or BanManager()
        self.session_tracker = session_tracker or UserSessionTracker()
        self.ai_engine = ai_engine or AISecurityEngine()
        self.journal_reader = None
        self.pid_cache = PIDAttributionCache(ttl_seconds=120.0)
        self.subnet_shield = SubnetShield()
        
        # ----------------------------------------------------------------------
        # 106 CATEGORIZED NETWORK AND SECURITY THREAT SIGNATURES
        # ----------------------------------------------------------------------
        self.patterns = {
            # CATEGORY 1: SSH & REMOTE ACCESS SECURITY (12 RULES)
            "SSH_INVALID_USER": (re.compile(r"Invalid user (\w+)(?: from ([^\s:]+))?"), 25),
            "SSH_FAILED_PASS": (re.compile(r"Failed password for (?:invalid user )?(\w+)(?: from ([^\s:]+))?"), 15),
            "SSH_SUCCESS": (re.compile(r"Accepted (?:password|publickey) for (\w+)(?: from ([^\s:]+))?"), 0),
            "SSH_LOGOUT": (re.compile(r"Disconnected from (?:user (\w+) )?([^\s:]+)"), 0),
            "SSH_PREAUTH_SCAN": (re.compile(r"Did not receive identification string from ([^\s:]+)"), 20),
            "SSH_MAX_AUTH_EXCEEDED": (re.compile(r"error: maximum authentication attempts exceeded for (\w+)(?: from ([^\s:]+))?"), 35),
            "SSH_ROOT_LOGIN_ATTEMPT": (re.compile(r"Accepted (?:password|publickey) for root from ([^\s:]+)"), 50),
            "SSH_TUNNEL_ATTEMPT": (re.compile(r"refused local port forward.*from ([^\s:]+)"), 40),
            "SSH_DIRECT_TCPIP": (re.compile(r"connect_to .* port \d+: failed.*from ([^\s:]+)"), 30),
            "SSH_SFTP_REQUEST": (re.compile(r"subsystem request for sftp by user (\w+)(?: from ([^\s:]+))?"), 5),
            "SSH_HOST_KEY_CHANGED": (re.compile(r"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED.*from ([^\s:]+)"), 45),
            "SSH_CIPHER_MISMATCH": (re.compile(r"no matching cipher found.*from ([^\s:]+)"), 15),

            # CATEGORY 2: FIREWALL & ROUTING VIOLATIONS (12 RULES)
            "UFW_BLOCK_INBOUND": (re.compile(r"\[UFW BLOCK\] IN=(\w+) .* SRC=([^\s]+) DST=([^\s]+) .* PROTO=(\w+) DPT=(\d+)"), 10),
            "IPTABLES_DROP": (re.compile(r"\[IPTABLES DROP\] IN=(\w+) .* SRC=([^\s]+) DST=([^\s]+) .* PROTO=(\w+) DPT=(\d+)"), 10),
            "PFSENSE_BLOCK": (re.compile(r"filterlog.*block.*src ([^\s]+).*dst ([^\s]+)"), 10),
            "CISCO_ACL_DENY": (re.compile(r"%SEC-6-IPACCESSLOGP: list \w+ denied (\w+) ([^\s]+)"), 15),
            "MIKROTIK_DROP": (re.compile(r"firewall,info forward: in:\w+ out:\w+, src-mac .*, proto \w+, ([^\s]+)->([^\s]+)"), 10),
            "IP_SPOOFING_MARTIAN": (re.compile(r"IPv4: martian source ([^\s]+) from ([^\s]+)"), 60),
            "BROADCAST_STORM": (re.compile(r"received packet on \w+ with own address as source.*SRC=([^\s]+)"), 50),
            "UNAUTHORIZED_FORWARD": (re.compile(r"IP forwarding disabled.*SRC=([^\s]+)"), 30),
            "LAND_ATTACK_DETECTED": (re.compile(r"LAND attack: SRC=([^\s]+) equals DST"), 70),
            "TEARDROP_ATTACK": (re.compile(r"oversized Ethernet frame / fragmented packet from ([^\s]+)"), 65),
            "SMURF_ATTACK_PROBE": (re.compile(r"ICMP echo request to broadcast address from ([^\s]+)"), 55),
            "BGP_ROUTE_CHANGE": (re.compile(r"BGP-5-ADJCHANGE: neighbor ([^\s]+) Down"), 40),

            # CATEGORY 3: NETWORK PROTOCOL ANOMALIES & POISONING (12 RULES)
            "ARP_SPOOFING_DETECTED": (re.compile(r"arp: hardware address changed for ([^\s]+) from ([\da-fA-F:]+) to ([\da-fA-F:]+)"), 65),
            "DHCP_ROGUE_SERVER": (re.compile(r"dhcpd: DHCPNAK on ([^\s]+) from ([\da-fA-F:]+)"), 55),
            "DHCP_DISCOVER_FLOOD": (re.compile(r"DHCPDISCOVER from ([\da-fA-F:]+) via \w+: network \w+: no free leases"), 45),
            "DNS_AMPLIFICATION_QUERY": (re.compile(r"named.*query.*ANY.*from ([^\s]+)"), 40),
            "DNS_CACHE_POISONING": (re.compile(r"named.*lame server resolving.*from ([^\s]+)"), 50),
            "ICMP_UNREACHABLE_BURST": (re.compile(r"ICMP ([^\s]+) protocol (\d+) unreachable"), 20),
            "ICMP_REDIRECT_ATTACK": (re.compile(r"ICMP redirect received from ([^\s]+)"), 50),
            "IGMP_MEMBERSHIP_FLOOD": (re.compile(r"IGMP query flood detected from ([^\s]+)"), 40),
            "IPV6_RA_SPOOFING": (re.compile(r"ICMPv6-RA: Router Advertisement from unapproved link-local (\w+)"), 50),
            "NTP_MONLIST_AMPLIFICATION": (re.compile(r"ntpd.*monlist request from ([^\s]+)"), 45),
            "SSDP_AMPLIFICATION_FLOOD": (re.compile(r"SSDP M-SEARCH query flood from ([^\s]+)"), 40),
            "SNMP_BRUTE_FORCE": (re.compile(r"snmpd: Bad community name.*from ([^\s]+)"), 35),

            # CATEGORY 4: NETWORK SCANNING & RECON TOOLS (10 RULES)
            "NMAP_NULL_SCAN": (re.compile(r"\[UFW BLOCK\] .* SRC=([^\s]+) .* PROTO=TCP DPT=\d+ WINDOW=0"), 35),
            "NMAP_XMAS_SCAN": (re.compile(r"\[UFW BLOCK\] .* SRC=([^\s]+) .* PROTO=TCP.*FLAGS=FIN PSH URG"), 40),
            "NMAP_FIN_SCAN": (re.compile(r"\[UFW BLOCK\] .* SRC=([^\s]+) .* PROTO=TCP.*FLAGS=FIN"), 30),
            "SYN_FLOOD_PROBE": (re.compile(r"TCP: Possible SYN flooding on port (\d+).*Sending cookies"), 50),
            "MASSCAN_BANNER_GRAB": (re.compile(r"Masscan connection attempt from ([^\s]+)"), 40),
            "ZMAP_SWEEP_DETECTED": (re.compile(r"ZMap network scan probe detected from ([^\s]+)"), 40),
            "HPING3_PACKET_PROBE": (re.compile(r"custom TCP raw packet injection from ([^\s]+)"), 45),
            "TCP_ACK_SCAN": (re.compile(r"\[UFW BLOCK\] .* SRC=([^\s]+) .* PROTO=TCP.*FLAGS=ACK"), 25),
            "UDP_PORT_SWEEP": (re.compile(r"UDP port sweep from ([^\s]+) across multiple ports"), 35),
            "VULN_SCANNER_USERAGENT": (re.compile(r"(Nikto|sqlmap|Nmap|Gobuster|Dirbuster|Nuclei).*SRC=([^\s]+)"), 50),

            # CATEGORY 5: PACKET SNIFFING & PROMISCUOUS MODE (8 RULES)
            "NIC_PROMISCUOUS_ENTER": (re.compile(r"device (\w+) entered promiscuous mode"), 70),
            "NIC_PROMISCUOUS_LEAVE": (re.compile(r"device (\w+) left promiscuous mode"), 10),
            "BPF_FILTER_ATTACHED": (re.compile(r"BPF socket filter attached on interface (\w+)"), 50),
            "PCAP_CAPTURE_STARTED": (re.compile(r"pcap packet capture session started by UID (\d+)"), 45),
            "WIRESHARK_TCPDUMP_EXEC": (re.compile(r"process '(tcpdump|tshark|wireshark)' executed by (\w+)"), 40),
            "RAW_SOCKET_CREATED": (re.compile(r"user (\w+) opened raw network socket"), 45),
            "MAC_ADDRESS_CHANGED": (re.compile(r"interface (\w+): link MAC address changed to ([\da-fA-F:]+)"), 50),
            "PACKET_DROP_SPIKE": (re.compile(r"interface (\w+): excessive dropped packets count (\d+)"), 25),

            # CATEGORY 6: VPN & TUNNELING THREATS (10 RULES)
            "OPENVPN_AUTH_FAILED": (re.compile(r"openvpn.*TLS Auth Error: Auth Username/Password Failed.*peer ([^\s]+)"), 25),
            "WIREGUARD_HANDSHAKE_FAIL": (re.compile(r"wireguard: Handshake for peer \w+ did not complete after.*from ([^\s]+)"), 20),
            "IPSEC_IKE_AUTH_ERROR": (re.compile(r"pluto.*IKE SA authentication failed with ([^\s]+)"), 30),
            "L2TP_DISCONNECT_BURST": (re.compile(r"xl2tpd.*Connection terminated from ([^\s]+)"), 15),
            "SSH_SOCKS_PROXY_OPEN": (re.compile(r"SSH dynamic SOCKS proxy tunnel requested by (\w+) from ([^\s]+)"), 35),
            "DNS_TUNNELING_QUERY": (re.compile(r"DNS TXT query length > 200 bytes from ([^\s]+)"), 55),
            "ICMP_TUNNELING_PROBE": (re.compile(r"ICMP echo payload size > 1000 bytes from ([^\s]+)"), 55),
            "GRE_TUNNEL_CREATED": (re.compile(r"GRE tunnel interface \w+ created from ([^\s]+)"), 40),
            "VXLAN_ENCAP_WARNING": (re.compile(r"VXLAN invalid VNI received from ([^\s]+)"), 30),
            "TOR_EXIT_NODE_CONN": (re.compile(r"Tor exit node connection established from ([^\s]+)"), 50),

            # CATEGORY 7: FTP & MAIL SERVICE ATTACKS (10 RULES)
            "VSFTPD_FAILED_LOGIN": (re.compile(r"vsftpd.*FAIL LOGIN: Client \"([^\"]+)\""), 20),
            "PROFTPD_ANON_ATTEMPT": (re.compile(r"proftpd.*ANONYMOUS FTP login attempt from ([^\s]+)"), 25),
            "POSTFIX_SASL_FAILED": (re.compile(r"postfix/smtpd.*warning: .*\[([^\s\]]+)\]: SASL authentication failed"), 25),
            "DOVECOT_IMAP_BRUTE": (re.compile(r"dovecot: imap-login: Disconnected.*auth failed.*rip=([^\s,]+)"), 25),
            "SMTP_RELAY_ATTEMPT": (re.compile(r"postfix/smtpd.*relay access denied.*from \[([^\s\]]+)\]"), 40),
            "FTP_BOUNCE_ATTEMPT": (re.compile(r"FTP PORT command to non-client IP from ([^\s]+)"), 55),
            "POP3_AUTH_ERROR": (re.compile(r"dovecot: pop3-login: Aborted login.*rip=([^\s,]+)"), 20),
            "MAIL_SPAM_FLOOD": (re.compile(r"Postfix rate limit exceeded for client \[([^\s\]]+)\]"), 45),
            "RBL_BLACKLISTED_IP": (re.compile(r"blocked using RBL blacklist.*client \[([^\s\]]+)\]"), 35),
            "FTP_CMD_INJECTION": (re.compile(r"FTP command injection payload from ([^\s]+)"), 60),

            # CATEGORY 8: PRIVILEGE ESCALATION & REVERSE SHELLS (12 RULES)
            "SUDO_EXECUTION": (re.compile(r"(\w+) : TTY=.* ; COMMAND=(.*)"), 5),
            "SUDO_FAILED_PASSWORD": (re.compile(r"(\w+) : (\d+) incorrect password attempts"), 20),
            "SUDO_ROOT_SHELL": (re.compile(r"(\w+) : TTY=.* ; COMMAND=.*(?:/bin/bash|/bin/sh|/bin/zsh|su root|su -)"), 65),
            "SU_TO_ROOT_SUCCESS": (re.compile(r"successful su for root by (\w+)"), 40),
            "NETCAT_REVERSE_SHELL": (re.compile(r"process '(nc|ncat|netcat)' launched with '-e' by (\w+)"), 80),
            "SOCAT_TUNNEL_EXEC": (re.compile(r"socat EXEC:.*TCP:([^\s:]+)"), 75),
            "PYTHON_REVERSE_SHELL": (re.compile(r"python.*socket.*connect\(.*([^\s:]+)"), 80),
            "BASH_DEV_TCP_SHELL": (re.compile(r"bash -i >& /dev/tcp/([^\s/]+)/\d+"), 85),
            "TTY_ALLOCATION_GRANT": (re.compile(r"grantpt: allocated pty slave device for UID (\d+)"), 20),
            "SUID_BINARY_EXECUTION": (re.compile(r"SUID binary '(.*)' executed by non-root UID (\d+)"), 50),
            "SHADOW_FILE_ACCESS": (re.compile(r"unauthorized read attempt on /etc/shadow by (\w+)"), 75),
            "CRON_JOB_ADDED": (re.compile(r"CRON.*\((\w+)\) CMD \(.*([^\s:]+).*\)"), 45),

            # CATEGORY 9: KERNEL & HARDWARE ANOMALIES (10 RULES)
            "KERNEL_SEGFAULT": (re.compile(r"kernel: .* segfault at .* error \d+ in"), 40),
            "OOM_KILLER_TRIGGERED": (re.compile(r"kernel: Out of memory: Kill process (\d+) \((.*)\)"), 45),
            "NIC_LINK_DOWN": (re.compile(r"kernel: \w+: link down / carrier lost"), 30),
            "NIC_DRIVER_CRASH": (re.compile(r"kernel: \w+: driver reset failed / hardware error"), 50),
            "DMA_BUFFER_OVERFLOW": (re.compile(r"kernel: DMA buffer overflow on interface (\w+)"), 60),
            "RING_BUFFER_FULL": (re.compile(r"kernel: \w+: rx ring buffer full, dropping packets"), 35),
            "EBPF_PROGRAM_LOAD": (re.compile(r"bpf: loaded program TYPE_\w+ by UID (\d+)"), 40),
            "KERNEL_MODULE_INSERT": (re.compile(r"kernel: module '(\w+)' loaded into kernel by UID (\d+)"), 55),
            "SYSCTL_PARAM_CHANGED": (re.compile(r"sysctl: net\.ipv4\..* changed by (\w+)"), 35),
            "HARDWARE_INTERRUPT_FLOOD": (re.compile(r"kernel: do_IRQ: \d+\.\d+ No irq handler for vector"), 40),

            # CATEGORY 10: ACCOUNT MANAGEMENT ABUSE (10 RULES)
            "USER_CREATED": (re.compile(r"new user: name=(\w+), UID=(\d+)"), 30),
            "USER_DELETED": (re.compile(r"delete user '(\w+)'"), 35),
            "PASSWORD_CHANGED": (re.compile(r"password changed for (\w+)"), 20),
            "GROUP_SUDO_ADD": (re.compile(r"add '(\w+)' to group '(?:sudo|wheel|root)'"), 70),
            "SHADOW_FILE_MODIFIED": (re.compile(r"user management updated /etc/shadow for (\w+)"), 50),
            "PAM_AUTH_FAILURE": (re.compile(r"pam_unix\(.*:auth\): authentication failure; logname=.* rhost=([^\s]+)"), 20),
            "LOCKED_ACCOUNT_LOGIN": (re.compile(r"User (\w+) account is locked, login refused from ([^\s]+)"), 30),
            "GPASSWD_GROUP_CHANGE": (re.compile(r"gpasswd: user (\w+) added to group (\w+) by (\w+)"), 40),
            "EXPIRED_PASS_LOGIN": (re.compile(r"User (\w+) password has expired, login refused from ([^\s]+)"), 25),
            "MAX_SESSIONS_EXCEEDED": (re.compile(r"Too many active sessions for user (\w+) from ([^\s]+)"), 30)
        }

        self.failed_attempts = defaultdict(deque)
        self.ip_risk_score = defaultdict(float)

    def tail_file(self, file_path: str):
        """
        Continuous file tailing with inode and logrotate rotation detection.
        """
        try:
            current_inode = None
            if os.path.exists(file_path):
                current_inode = os.stat(file_path).st_ino

            with open(file_path, "r", encoding="utf-8", errors="ignore") as log:
                log.seek(0, 2)
                print(f"[+] Live Tailing Active (Logrotate Inode Tracking Active): {file_path}")
                
                while True:
                    line = log.readline()
                    if line:
                        self.parse_line(line, source_file=file_path)
                    else:
                        time.sleep(0.3)
                        
                        if os.path.exists(file_path):
                            try:
                                stat = os.stat(file_path)
                                if current_inode is not None and stat.st_ino != current_inode:
                                    print(f"[*] [LOGROTATE DETECTED] Inode changed for {file_path}. Reopening new file...")
                                    break
                                if log.tell() > stat.st_size:
                                    print(f"[*] [LOG TRUNCATED] File truncated for {file_path}. Resetting read position...")
                                    log.seek(0, 0)
                            except Exception:
                                pass
        except PermissionError:
            print(f"[-] Permission Denied for {file_path}. Try running with sudo.")
        except Exception as e:
            print(f"[-] Error tailing {file_path}: {e}")

        time.sleep(1)
        self.tail_file(file_path)

    def start(self):
        """
        Discovers system log files and launches journald streaming if available.
        """
        print(f"[+] 106-Rule, Subnet Shield & Dual-AI Log Monitor Initializing: {time.ctime()}")
        
        target_paths = getattr(config, "SYSTEM_LOG_PATHS", ["/var/log/auth.log", "/var/log/syslog", "logs/auth.log"])
        active_files = []

        for p in target_paths:
            if os.path.exists(p) and os.path.isfile(p):
                active_files.append(p)
            elif not os.path.isabs(p):
                os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
                if not os.path.exists(p):
                    with open(p, "w", encoding="utf-8") as f:
                        f.write(f"# Local log file created for {p}\n")
                active_files.append(p)

        if active_files:
            print(f"[+] Monitoring {len(active_files)} System Log File(s): {', '.join(active_files)}")
            for path in active_files:
                t = threading.Thread(target=self.tail_file, args=(path,), daemon=True)
                t.start()

        if JournalReader.is_available():
            self.journal_reader = JournalReader(callback=self.parse_line)
            t_j = threading.Thread(target=self.journal_reader.start_streaming, daemon=True)
            t_j.start()

        while True:
            time.sleep(1)

    def parse_line(self, line: str, source_file: str = "syslog"):
        """
        Parses a log line through Whitelist Shield, Canonicalizer, and Dual-AI Engine.
        """
        cleaned_line = line.strip()
        if not cleaned_line:
            return

        # 1. Payload Canonicalization (URL, Hex, Unicode, Base64 Deobfuscation)
        canonical_line = PayloadCanonicalizer.canonicalize(cleaned_line)

        # 2. False Positive Whitelist Shield Check
        if WhitelistShield.is_known_benign(cleaned_line) or WhitelistShield.is_known_benign(canonical_line):
            return

        # 3. Extract Authentic Event Timestamp
        log_event_time = LogParserUtils.parse_log_timestamp(cleaned_line)

        # 4. Process & PID Attribution Context
        pid = LogParserUtils.extract_pid(cleaned_line)

        # 5. Dual-Stack IP Extraction (IPv4 + IPv6)
        ip = LogParserUtils.extract_primary_ip(canonical_line)
        if ip == "LOCAL_SYSTEM" and pid:
            cached_ip, cached_user = self.pid_cache.resolve(pid)
            if cached_ip:
                ip = cached_ip

        user = "UNKNOWN"
        matched_rule = None
        base_score = 0
        ai_res = {"is_attack": False, "verdict": "BENIGN"}

        # 6. 106 Regex Rules Matching
        for event_type, (pattern, score) in self.patterns.items():
            match = pattern.search(canonical_line) or pattern.search(cleaned_line)
            if match:
                matched_rule = event_type
                base_score = score
                groups = match.groups()
                
                for g in groups:
                    if g:
                        g_str = str(g).strip("[](),: ")
                        if g_str in LogParserUtils.extract_all_ips(g_str):
                            if ip == "LOCAL_SYSTEM":
                                ip = g_str
                        elif not re.match(r"^\d+$", g_str) and user == "UNKNOWN":
                            user = g_str

                if pid:
                    self.pid_cache.record(pid, ip=ip if ip != "LOCAL_SYSTEM" else None, user=user if user != "UNKNOWN" else None)

                # Zero-Latency Banned IP Fast-Path
                if ip != "LOCAL_SYSTEM" and self.ban_manager.is_banned(ip):
                    return

                # A. Successful Authentication
                if event_type == "SSH_SUCCESS":
                    self.ban_manager.register_auth_success(ip=ip, username=user)
                    self.session_tracker.start_session(username=user, source_ip=ip, tty="pts/0")
                    self.ip_risk_score[ip] = 0.0
                    self.failed_attempts[ip].clear()
                    if self.callback:
                        self.callback("SSH_SUCCESS", ip, f"User '{user}' authenticated successfully from {ip}.")

                # B. Session Logout
                elif event_type == "SSH_LOGOUT":
                    self.session_tracker.end_session(username=user, source_ip=ip, tty="pts/0")

                # C. Command Execution
                elif event_type == "SUDO_EXECUTION" and len(groups) >= 2:
                    cmd = groups[1]
                    self.session_tracker.record_command(username=user, source_ip=ip, command=cmd, tty="pts/0")

                # D. Authentication Failure & Typo Handling (8 Attempts Tolerance)
                elif event_type in ["SSH_FAILED_PASS", "SSH_INVALID_USER"]:
                    is_malicious, failure_type, count = self.ban_manager.register_auth_failure(ip=ip, username=user)
                    if not is_malicious:
                        if self.callback:
                            self.callback("SSH_FAILED_PASS", ip,
                                          f"Password typo for user '{user}' from {ip} (Tolerated attempt {count}/8).")
                        log_data = {"user": user, "ip": ip, "event": "SSH_FAILED_PASS_TOLERATED", "timestamp": time.ctime(log_event_time), "source_file": source_file}
                        self.write_log_json(log_data)
                        return
                    else:
                        ban_reason = f"SSH Password Retry Limit Exceeded ({count}/8 Failed Attempts - {failure_type})"
                        if self.callback:
                            self.callback("RAPID_BRUTE_FORCE", ip,
                                          f"Auth failure threshold exceeded ({failure_type}) for user '{user}' from {ip} (Attempt {count}). 5-Minute Ban Applied.")
                        self.ban_manager.ban_ip(ip=ip, criticality="MEDIUM", reason=ban_reason, duration_override=300)
                        log_data = {"user": user, "ip": ip, "event": "SSH_BRUTE_FORCE_BANNED", "timestamp": time.ctime(log_event_time), "source_file": source_file}
                        self.write_log_json(log_data)
                        return
                break

        # Zero-Latency Banned IP Fast-Path
        if ip != "LOCAL_SYSTEM" and self.ban_manager.is_banned(ip):
            return

        # 7. Multi-Layer AI Security Analysis (Skipped for protected IPs and LOCAL_SYSTEM to prevent loops)
        if ip != "LOCAL_SYSTEM" and not self.ban_manager.is_protected_ip(ip):
            ai_res = self.ai_engine.analyze(canonical_line)
            
            if ai_res.get("is_attack"):
                ai_verdict = ai_res.get("verdict", "ATTACK")
                urgency = ai_res.get("urgency", "HIGH")
                
                ai_score = 40.0
                criticality = "HIGH"
                if urgency == "CRITICAL":
                    ai_score = 75.0
                    criticality = "CRITICAL"
                elif ai_verdict == "ZERO_DAY":
                    ai_score = 65.0
                    criticality = "HIGH"
                
                event_name = "AI_ZERO_DAY_ANOMALY" if ai_verdict == "ZERO_DAY" else "AI_ATTACK_DETECTED"
                self.threat_event(ip=ip, user=user, score=ai_score, event=event_name, ai_info=ai_res, criticality=criticality, event_time=log_event_time)
            elif matched_rule and base_score > 0:
                crit = "CRITICAL" if base_score >= 60 else ("HIGH" if base_score >= 35 else "MEDIUM")
                self.threat_event(ip=ip, user=user, score=base_score, event=matched_rule, ai_info=ai_res, criticality=crit, event_time=log_event_time)

        log_data = {"user": user, "ip": ip, "event": matched_rule or ai_res.get("verdict"), "timestamp": time.ctime(log_event_time), "source_file": source_file, "ai_analysis": ai_res}
        self.write_log_json(log_data)

    def write_log_json(self, log_dict):
        try:
            with open("log.json", "a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(log_dict, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def threat_event(self, ip, user, score, event, ai_info=None, criticality="MEDIUM", event_time=None):
        """
        Calculates cumulative threat risk and triggers individual IP and Subnet / CIDR bans.
        """
        if not ip or ip == "LOCAL_SYSTEM" or self.ban_manager.is_protected_ip(ip):
            return

        if self.ban_manager.is_banned(ip):
            return

        now = event_time or time.time()
        window = getattr(config, "TIME_WINDOW", 600)
        
        # 1. Subnet / CIDR Botnet Aggregator Evaluation
        should_ban_sub, subnet_cidr, sub_risk, distinct_ips = self.subnet_shield.record_threat(ip, score, event, now)
        if should_ban_sub and subnet_cidr and not self.ban_manager.is_banned(subnet_cidr):
            sub_reason = f"Distributed Botnet Detected: {distinct_ips} distinct attacking IPs across {subnet_cidr} (Subnet Risk: {sub_risk:.1f})"
            if self.callback:
                self.callback("DISTRIBUTED_BOTNET_SUB_BAN", subnet_cidr,
                              f"BOTNET ALERT! Subnet {subnet_cidr} banned ({distinct_ips} rotating IPs).")
            self.ban_manager.ban_ip(ip=subnet_cidr, criticality="CRITICAL", reason=sub_reason)
            self.subnet_shield.clear_subnet(subnet_cidr)
            return

        # 2. Individual IP Threat Risk Evaluation
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = deque() 

        while self.failed_attempts[ip] and (now - self.failed_attempts[ip][0]['time'] > window):
            old_event = self.failed_attempts[ip].popleft()
            self.ip_risk_score[ip] -= old_event['score']
            if self.ip_risk_score[ip] < 0:
                self.ip_risk_score[ip] = 0.0

        burst_multiplier = 1.0
        recent_burst = sum(1 for e in self.failed_attempts[ip] if now - e['time'] <= 10)
        if recent_burst >= 5:
            burst_multiplier = 1.5

        final_score = score * burst_multiplier

        self.failed_attempts[ip].append({'time': now, 'score': final_score, 'type': event})
        self.ip_risk_score[ip] += final_score            
        current_score = self.ip_risk_score[ip]
        total_attempts = len(self.failed_attempts[ip])

        if self.callback and score > 0:
            mitre_id = ai_info.get("mitre_id", "N/A") if isinstance(ai_info, dict) else "N/A"
            msg = f"THREAT({event}) | Target: {ip} | Risk: {current_score:.1f}/50 | MITRE: {mitre_id} | Level: {criticality}"
            self.callback(event, ip, msg)

        risk_threshold = getattr(config, "RISK_SCORE_THRESHOLD", 50)
        if current_score >= risk_threshold:
            if not self.ban_manager.is_banned(ip):
                reason_msg = f"Cumulative Risk Exceeded ({current_score:.1f}/{risk_threshold} - {total_attempts} Events - Triggered by {event})"
                
                if self.callback:
                    self.callback("ADVANCED_THREAT_DETECTED", ip,
                                  f"CRITICAL THREAT! IP: {ip} | Risk: {current_score:.1f} | Tiered {criticality} Ban Applied.")
                
                self.ban_manager.ban_ip(ip=ip, criticality=criticality, reason=reason_msg)

            self.failed_attempts[ip].clear()
            self.ip_risk_score[ip] = 0.0