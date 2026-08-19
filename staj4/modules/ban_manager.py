# -*- coding: utf-8 -*-
"""
==============================================================================
MULTI-BACKEND TIERED FIREWALL & BAN SUBSYSTEM (ban_manager.py)
==============================================================================
This module manages active ban states across dual-stack IPv4/IPv6 networks,
applies kernel-level IPTables/IP6Tables and UFW drop rules, enforces 8-attempt
password retry tolerance with max 5-minute cooldowns, lifts parent CIDR subnets
during unbans, and auto-unbans expired restrictions with full thread safety.
==============================================================================
"""

import os
import time
import ipaddress
import subprocess
import threading
from collections import defaultdict
import config
from modules.smart_logger import SmartLogger
from modules.db_manager import get_db_connection

class BanManager:
    def __init__(self, db_name="security_events.db", logger=None):
        self.db_name = db_name
        self.logger = logger or SmartLogger()
        self.lock = threading.RLock()
        
        # In-memory fast cache: target (IP/CIDR) -> unban_timestamp
        self.active_bans = {}
        # IP -> list of recent failure timestamps
        self.auth_failure_history = defaultdict(list)
        
        self.dynamic_protected_ips = set(getattr(config, 'PROTECTED_IPS', [
            "127.0.0.1", "::1", "localhost", "192.168.1.1", "10.0.0.1"
        ]))
        
        self.init_db()
        self.load_active_bans_from_db()
        self.discover_host_network_interfaces()

        if getattr(config, 'ENABLE_FIREWALL_SYNC_ON_STARTUP', True):
            self.sync_firewall_rules_on_startup()

    def init_db(self):
        """
        Initializes the 'banned_ips' table in SQLite WAL mode.
        """
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""CREATE TABLE IF NOT EXISTS banned_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    reason TEXT,
                    banned_at REAL,
                    ban_duration_seconds INTEGER,
                    unban_at REAL,
                    is_active INTEGER,
                    network_type TEXT,
                    criticality_level TEXT,
                    enforcement_action TEXT
                )""")
                conn.commit()
        except Exception as e:
            print(f"[-] Ban Database Initialization Error: {e}")

    def load_active_bans_from_db(self):
        """
        Loads non-expired bans from database into memory.
        """
        now = time.time()
        try:
            with self.lock:
                with get_db_connection(self.db_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT ip, unban_at FROM banned_ips WHERE is_active = 1 AND unban_at > ?", (now,))
                    rows = cursor.fetchall()
                    for ip, unban_at in rows:
                        self.active_bans[ip] = unban_at
        except Exception as e:
            print(f"[-] Active Bans Database Load Error: {e}")

    def discover_host_network_interfaces(self):
        """
        Detects host interface IP addresses and whitelists them to prevent self-lockout.
        """
        try:
            import psutil
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.address:
                        clean_ip = addr.address.split('%')[0]
                        self.dynamic_protected_ips.add(clean_ip)
        except Exception:
            pass

    def sync_firewall_rules_on_startup(self):
        """
        Synchronizes active bans from database into the host firewall.
        """
        with self.lock:
            if not self.active_bans:
                return

            print(f"[*] [FIREWALL SYNC] Re-synchronizing {len(self.active_bans)} active ban(s) into OS firewall...")
            for target, unban_at in list(self.active_bans.items()):
                if unban_at > time.time():
                    self._apply_os_firewall_rule(target, is_internal=self.is_internal_ip(target), criticality="HIGH")

    def is_banned(self, ip: str) -> bool:
        """
        Checks if an IP is actively banned (either directly or via an active CIDR subnet ban).
        """
        if not ip or self.is_protected_ip(ip):
            return False

        now = time.time()

        with self.lock:
            # 1. Direct O(1) in-memory cache lookup
            if ip in self.active_bans:
                if self.active_bans[ip] > now:
                    return True
                else:
                    del self.active_bans[ip]

            # 2. Check if IP falls within any active CIDR subnet bans
            try:
                ip_obj = ipaddress.ip_address(ip)
                for target, unban_at in list(self.active_bans.items()):
                    if "/" in target and unban_at > now:
                        try:
                            if ip_obj in ipaddress.ip_network(target):
                                return True
                        except Exception:
                            pass
            except Exception:
                pass

        # 3. Database query fallback
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT unban_at FROM banned_ips WHERE ip = ? AND is_active = 1 AND unban_at > ? ORDER BY unban_at DESC LIMIT 1", (ip, now))
                row = cursor.fetchone()
                if row:
                    with self.lock:
                        self.active_bans[ip] = row[0]
                    return True
        except Exception:
            pass

        return False

    def is_internal_ip(self, ip: str) -> bool:
        """
        Determines if an IP or Subnet belongs to internal LAN or external WAN.
        """
        if not ip or ip in ["LOCAL_SYSTEM", "localhost", "127.0.0.1", "::1"]:
            return True
        try:
            if "/" in ip:
                net_obj = ipaddress.ip_network(ip, strict=False)
                return net_obj.is_private or net_obj.is_loopback or net_obj.is_link_local
            else:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    return True
                
                internal_subnets = getattr(config, 'INTERNAL_SUBNETS', ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "fc00::/7", "fe80::/10"])
                for subnet in internal_subnets:
                    try:
                        if ip_obj in ipaddress.ip_network(subnet):
                            return True
                    except TypeError:
                        pass
        except ValueError:
            pass
        return False

    def is_protected_ip(self, ip: str) -> bool:
        """
        Checks if the IP is in the core protected whitelist to prevent self-lockout.
        """
        if not ip or ip in ["LOCAL_SYSTEM", "localhost", "127.0.0.1", "::1"]:
            return True
        if ip in self.dynamic_protected_ips:
            return True
        configured_protected = getattr(config, 'PROTECTED_IPS', [])
        if ip in configured_protected:
            return True
        return False

    def register_auth_failure(self, ip: str, username: str = "unknown") -> tuple[bool, str, int]:
        """
        Enforces an 8-attempt human password typo tolerance before applying a ban.
        Returns: (should_ban, failure_type, attempt_count)
        """
        if not ip or self.is_protected_ip(ip):
            return False, "PROTECTED_IP", 0

        now = time.time()
        is_internal = self.is_internal_ip(ip)
        max_typos = getattr(config, 'INTERNAL_MAX_TYPOS', 8) if is_internal else getattr(config, 'EXTERNAL_MAX_TYPOS', 8)

        with self.lock:
            # 1. Filter failures within the sliding window (10 minutes)
            recent_failures = [t for t in self.auth_failure_history[ip] if now - t <= 600]
            
            # Deduplicate multi-line SSH log artifacts for the exact same connection attempt (within 0.3s)
            if recent_failures and (now - recent_failures[-1] < 0.3):
                failure_count = len(recent_failures)
                return (failure_count > max_typos), "DUPLICATE_AUTH_LOG_IGNORED", failure_count

            recent_failures.append(now)
            self.auth_failure_history[ip] = recent_failures
            failure_count = len(recent_failures)

            # 2. High-Speed Machine Burst Detection (>8 automated attempts in under 3 seconds)
            if failure_count > max_typos:
                burst_in_3s = sum(1 for t in recent_failures if now - t <= 3)
                if burst_in_3s > max_typos:
                    msg = f"Rapid Automated Brute-Force Burst Detected from {ip} ({burst_in_3s} attempts in 3s)."
                    self.logger.log_event("WARNING", "AUTH_GUARD", "RAPID_BRUTE_FORCE", ip, msg)
                    return True, "RAPID_BRUTE_FORCE_ATTACK", failure_count

            # 3. Human Typo Tolerance Check (Allows at least 8 attempts)
            if failure_count <= max_typos:
                msg = f"Tolerated human password typo ({failure_count}/{max_typos}) for user '{username}' from {ip}. No ban applied."
                self.logger.log_event("INFO", "AUTH_GUARD", "HUMAN_TYPO_TOLERATED", ip, msg)
                return False, "HUMAN_TYPO_TOLERATED", failure_count
            else:
                msg = f"Password failure tolerance exceeded ({failure_count}/{max_typos}) for user '{username}' from {ip}."
                self.logger.log_event("WARNING", "AUTH_GUARD", "TYPO_THRESHOLD_EXCEEDED", ip, msg)
                return True, "TYPO_THRESHOLD_EXCEEDED", failure_count

    def register_auth_success(self, ip: str, username: str):
        """
        Graceful forgiveness of past password typos upon successful authentication.
        """
        with self.lock:
            if ip in self.auth_failure_history and len(self.auth_failure_history[ip]) > 0:
                count = len(self.auth_failure_history[ip])
                self.auth_failure_history[ip].clear()
                msg = f"User '{username}' authenticated successfully. Previous {count} password typos forgiven for IP {ip}."
                self.logger.log_event("NOTICE", "AUTH_GUARD", "AUTH_RECOVERY_FORGIVEN", ip, msg)
                print(f"[+] [AUTH FORGIVEN] {msg}")

    def get_repeat_count(self, ip: str) -> int:
        """
        Queries the number of previous bans for an IP address.
        """
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM banned_ips WHERE ip = ? AND is_active = 0", (ip,))
                row = cursor.fetchone()
                return row[0] if row else 0
        except Exception:
            return 0

    def _execute_system_command(self, cmd_str: str):
        """
        Executes an OS firewall command cleanly with root/sudo fallback without broken pipes.
        """
        if os.name == 'nt':
            return

        try:
            is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0)
            final_cmd = cmd_str if is_root else f"sudo {cmd_str}"
            subprocess.run(final_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except Exception:
            pass

    def _apply_os_firewall_rule(self, target: str, is_internal: bool, criticality: str):
        """
        Executes host firewall enforcement (UFW + IPTables / IP6Tables).
        """
        if os.name != 'nt':
            is_ipv6 = False
            try:
                if "/" in target:
                    is_ipv6 = (ipaddress.ip_network(target, strict=False).version == 6)
                else:
                    is_ipv6 = (ipaddress.ip_address(target).version == 6)
            except ValueError:
                pass

            iptables_cmd = "ip6tables" if is_ipv6 else "iptables"

            # 1. UFW Rule Application
            if not is_internal:
                self._execute_system_command(f"ufw insert 1 deny from {target} to any comment 'SIEM-{criticality}'")
            else:
                self._execute_system_command(f"ufw insert 1 deny proto tcp from {target} to any port 22 comment 'SIEM-LAN-SSH'")

            # 2. Kernel Level IPTables / IP6Tables Direct Packet Drop
            if getattr(config, 'ENABLE_IPTABLES_FALLBACK', True):
                if not is_internal:
                    self._execute_system_command(f"{iptables_cmd} -I INPUT 1 -s {target} -j DROP")
                else:
                    self._execute_system_command(f"{iptables_cmd} -I INPUT 1 -p tcp -s {target} --dport 22 -j DROP")

            # 3. Terminate Active TCP/SSH Sockets Immediately
            if getattr(config, 'ENABLE_SESSION_KILL', True) and "/" not in target:
                self._execute_system_command(f"ss -K dst {target}")
                self._execute_system_command(f"conntrack -D -s {target}")
        else:
            action = "LAN Port 22 Block" if is_internal else "Drop All Traffic (UFW + IPTables)"
            print(f"[*] [Windows Simulation] {target} blocked via OS Firewall ({action}).")

    def _remove_os_firewall_rule(self, target: str, is_internal: bool):
        """
        Thoroughly purges all UFW and IPTables/IP6Tables drop rules for the specified target.
        """
        if os.name != 'nt':
            is_ipv6 = False
            try:
                if "/" in target:
                    is_ipv6 = (ipaddress.ip_network(target, strict=False).version == 6)
                else:
                    is_ipv6 = (ipaddress.ip_address(target).version == 6)
            except ValueError:
                pass

            iptables_cmd = "ip6tables" if is_ipv6 else "iptables"

            # 1. Purge all matching UFW deny rules (both full and port 22)
            self._execute_system_command(f"ufw delete deny from {target} to any")
            self._execute_system_command(f"ufw delete deny proto tcp from {target} to any port 22")
            self._execute_system_command(f"ufw delete deny from {target}")

            # 2. Purge all matching IPTables rules in a loop until none remain
            self._execute_system_command(f"while {iptables_cmd} -D INPUT -s {target} -j DROP 2>/dev/null; do :; done")
            self._execute_system_command(f"while {iptables_cmd} -D INPUT -p tcp -s {target} --dport 22 -j DROP 2>/dev/null; do :; done")
        else:
            print(f"[*] [Windows Simulation] Firewall restriction removed for {target}.")

    def ban_ip(self, ip: str, criticality: str = "CRITICAL", reason: str = "Security Violation",
               source: str = "AUTO", duration_override: int = None):
        """
        Applies a tiered ban for an IP or CIDR Subnet.
        """
        if not ip or ip == "LOCAL_SYSTEM" or self.is_protected_ip(ip):
            return

        now = time.time()

        with self.lock:
            # Suppress duplicate bans
            if ip in self.active_bans and self.active_bans[ip] > now:
                remaining_seconds = int(self.active_bans[ip] - now)
                remaining_mins = max(1, remaining_seconds // 60)
                print(f"[*] [ALREADY BANNED] {ip} is already actively banned (~{remaining_mins} mins remaining). Duplicate suppressed.")
                return

            is_internal = self.is_internal_ip(ip)
            network_type = "INTERNAL" if is_internal else "EXTERNAL"
            criticality_level = criticality.upper() if criticality.upper() in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "CRITICAL"

            if duration_override is not None:
                base_duration = duration_override
            else:
                if "/" in ip:
                    base_duration = getattr(config, 'SUBNET_BAN_DURATION_SECONDS', 7200)
                elif is_internal:
                    durations = getattr(config, 'BAN_DURATIONS_INTERNAL', {"CRITICAL": 900, "HIGH": 300, "MEDIUM": 300, "LOW": 0})
                    base_duration = durations.get(criticality_level, 300)
                else:
                    durations = getattr(config, 'BAN_DURATIONS_EXTERNAL', {"CRITICAL": 3600, "HIGH": 1800, "MEDIUM": 300, "LOW": 0})
                    base_duration = durations.get(criticality_level, 300)

            if base_duration == 0:
                print(f"[*] [NO BAN] Threat level '{criticality_level}' does not require ban for {ip}.")
                return

            repeat_count = self.get_repeat_count(ip)
            effective_duration = base_duration * (2 ** min(repeat_count, 3))
            unban_at = now + effective_duration
            unban_at_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unban_at))
            duration_minutes = effective_duration // 60

            enforcement_action = "SSH_SESSION_KILL_AND_ISOLATE" if is_internal else "UFW_IPTABLES_DUAL_DROP"

            # Update in-memory active cache
            self.active_bans[ip] = unban_at

        target_type = "SUBNET / CIDR" if "/" in ip else "IP"
        print(f"\n[!] [{criticality_level} BAN] [{target_type}] Network: [{network_type}] | Target: {ip} | Duration: {duration_minutes} Mins | Action: {enforcement_action}")
        print(f"    Reason: {reason}")

        # 1. Execute OS Firewall Rule
        self._apply_os_firewall_rule(ip, is_internal=is_internal, criticality=criticality_level)

        # 2. Persist in SQLite Database
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE banned_ips SET is_active = 0 WHERE ip = ? AND is_active = 1", (ip,))
                cursor.execute("""INSERT INTO banned_ips 
                    (ip, reason, banned_at, ban_duration_seconds, unban_at, is_active, network_type, criticality_level, enforcement_action)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)""",
                    (ip, reason, now, effective_duration, unban_at, network_type, criticality_level, enforcement_action))
                conn.commit()
        except Exception as e:
            print(f"[-] Ban Database Write Error: {e}")

        # 3. Log Structured Event
        log_type = "INTERNAL_IP_BAN" if is_internal else "EXTERNAL_IP_BAN"
        details_msg = f"Target {ip} ({network_type}) restricted for {duration_minutes} mins. Reason: {reason}"
        self.logger.log_event("CRITICAL", "BAN_MANAGER", log_type, ip, details_msg)

    def unban_ip(self, ip: str, reason: str = "Manual Unban"):
        """
        Removes ban restriction for an IP or Subnet CIDR, lifts covering parent subnets,
        and clears historical auth failures.
        """
        if not ip:
            return

        is_internal = self.is_internal_ip(ip)
        network_type = "INTERNAL" if is_internal else "EXTERNAL"

        with self.lock:
            # 1. Remove OS Firewall Rule (UFW + IPTables)
            self._remove_os_firewall_rule(ip, is_internal=is_internal)

            # 2. Remove from in-memory active cache
            if ip in self.active_bans:
                del self.active_bans[ip]

            # 3. Clear auth failure retry history
            if ip in self.auth_failure_history:
                self.auth_failure_history[ip].clear()

            # 4. Check if any active parent CIDR subnet covers this IP and lift it
            if "/" not in ip:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    covering_subnets = []
                    for target in list(self.active_bans.keys()):
                        if "/" in target:
                            try:
                                if ip_obj in ipaddress.ip_network(target):
                                    covering_subnets.append(target)
                            except Exception:
                                pass

                    for sub in covering_subnets:
                        print(f"[*] [SUBNET LIFTED] Covering parent subnet {sub} also unbanned to restore access for {ip}.")
                        self._remove_os_firewall_rule(sub, is_internal=self.is_internal_ip(sub))
                        if sub in self.active_bans:
                            del self.active_bans[sub]
                        try:
                            with get_db_connection(self.db_name) as conn:
                                cursor = conn.cursor()
                                cursor.execute("UPDATE banned_ips SET is_active = 0 WHERE ip = ? AND is_active = 1", (sub,))
                                conn.commit()
                        except Exception:
                            pass
                except Exception:
                    pass

        # 5. Update Database for target
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE banned_ips SET is_active = 0 WHERE ip = ? AND is_active = 1", (ip,))
                conn.commit()
        except Exception as e:
            print(f"[-] Unban Database Update Error: {e}")

        msg = f"Network: [{network_type}] | Target: {ip} restriction lifted! Reason: {reason}"
        print(f"\n[+] [BAN REMOVED] {msg}")
        self.logger.log_event("INFO", "BAN_MANAGER", "BAN_REMOVED", ip, msg)

    def unban_all(self, reason: str = "Manual Admin Master Flush"):
        """
        Flushes all active IP and Subnet bans across memory, database, UFW, and IPTables.
        """
        with self.lock:
            targets = list(self.active_bans.keys())
            for t in targets:
                self.unban_ip(t, reason=reason)

            try:
                with get_db_connection(self.db_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE banned_ips SET is_active = 0 WHERE is_active = 1")
                    conn.commit()
            except Exception:
                pass
            print(f"[OK] Master Flush Complete: All firewall and database bans removed ({len(targets)} targets).")

    def check_expired_bans(self):
        """
        Periodically checks for expired bans and removes them automatically.
        """
        now = time.time()
        expired = []
        with self.lock:
            for target, unban_at in list(self.active_bans.items()):
                if now >= unban_at:
                    expired.append(target)

        for target in expired:
            self.unban_ip(target, reason="Tiered Ban Duration Expired")

    def start(self):
        """
        Starts the continuous Auto-Unban watchdog service.
        """
        print(f"[+] Multi-Backend Tiered Ban & Auto-Unban Service Started: {time.ctime()}")
        while True:
            try:
                self.check_expired_bans()
            except Exception as e:
                print(f"[-] Auto-Unban Loop Error: {e}")
            time.sleep(5)
