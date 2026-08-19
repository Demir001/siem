# -*- coding: utf-8 -*-
"""
==============================================================================
OUTBOUND C2 & REVERSE SHELL BEACONING GUARD (c2_detector.py)
==============================================================================
This module continuously monitors active outbound network sockets. It identifies
and terminates unauthorized reverse shells (e.g. bash /dev/tcp, netcat -e,
python socket), out-of-band C2 beaconing connections, and instantly drops the
destination C2 server on the host firewall.
==============================================================================
"""

import os
import time
import psutil
import ipaddress
import config
from modules.ban_manager import BanManager
from modules.smart_logger import SmartLogger

SUSPICIOUS_C2_BINARIES = {"nc", "ncat", "netcat", "socat", "bash", "sh", "zsh", "dash", "perl", "ruby", "lua"}
SAFE_STANDARD_PORTS = {80, 443, 53, 123, 22, 993, 995, 465, 587, 853}

class C2Detector:
    def __init__(self, ban_manager=None, callback=None, logger=None):
        self.ban_manager = ban_manager or BanManager()
        self.callback = callback
        self.logger = logger or SmartLogger()
        self.is_running = True

    def scan_outbound_sockets(self):
        """
        Samples all active outbound TCP sockets and detects reverse shells.
        """
        if not getattr(config, 'ENABLE_C2_DETECTION', True):
            return

        try:
            connections = psutil.net_connections(kind='inet')
        except Exception:
            return

        for conn in connections:
            if conn.status != psutil.CONN_ESTABLISHED:
                continue

            raddr = conn.raddr
            if not raddr:
                continue

            dst_ip = raddr.ip
            dst_port = raddr.port
            pid = conn.pid

            if not pid or self.ban_manager.is_internal_ip(dst_ip) or self.ban_manager.is_protected_ip(dst_ip):
                continue

            # Check if destination port is a suspicious non-standard port
            is_non_standard = dst_port not in SAFE_STANDARD_PORTS

            try:
                proc = psutil.Process(pid)
                p_name = proc.name().lower()
                cmdline = " ".join(proc.cmdline()).lower()

                is_suspicious_bin = any(b in p_name for b in SUSPICIOUS_C2_BINARIES)
                has_shell_flags = any(k in cmdline for k in ["/dev/tcp", "-e /bin", "pty.spawn", "socket.socket", "connect("])

                if (is_suspicious_bin and is_non_standard) or has_shell_flags:
                    reason_msg = f"Outbound Reverse Shell / C2 Connection to {dst_ip}:{dst_port} by PID {pid} ({p_name})"
                    print(f"\n[!] [C2 INTERCEPT ALERT] {reason_msg}")

                    self.logger.log_event(
                        "CRITICAL", "C2_GUARD", "C2_REVERSE_SHELL_INTERCEPT", dst_ip,
                        f"Active reverse shell terminated (PID: {pid} | Command: {cmdline[:60]}). C2 IP banned."
                    )

                    if self.callback:
                        self.callback("C2_REVERSE_SHELL_INTERCEPT", dst_ip, reason_msg)

                    # 1. Kill malicious process immediately
                    try:
                        proc.kill()
                        print(f"[*] [C2 PROCESS KILLED] Malicious process {p_name} (PID: {pid}) terminated.")
                    except Exception:
                        pass

                    # 2. Ban C2 destination IP on firewall
                    self.ban_manager.ban_ip(ip=dst_ip, criticality="CRITICAL", reason=reason_msg)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def start(self):
        """
        Starts the continuous C2 & Reverse Shell monitoring loop.
        """
        print(f"[+] Outbound C2 & Reverse Shell Beaconing Guard Active: {time.ctime()}")
        interval = getattr(config, 'C2_CHECK_INTERVAL_SECONDS', 3.0)
        while self.is_running:
            try:
                self.scan_outbound_sockets()
            except Exception as e:
                print(f"[-] C2 Scan Error: {e}")
            time.sleep(interval)
