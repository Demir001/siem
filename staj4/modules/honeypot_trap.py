# -*- coding: utf-8 -*-
"""
==============================================================================
HONEYPOT DECOY TRAPS & REAL-TIME PORT SCAN / SYN-SWEEP GUARD
(honeypot_trap.py)
==============================================================================
This module provides:
1. DECOY PORT LISTENERS (Connect Scans & Probe Traps):
   - Deceptive TCP listeners on high-risk unassigned trap ports (23, 2323, 5555, 6379, 4444, 31337).
2. KERNEL RAW SOCKET SYN-SWEEP & NMAP SCAN INTERCEPTOR:
   - Inspects incoming raw TCP packets (SYN, NULL, FIN, XMAS, ACK).
   - Detects rapid port sweeps (>=5 distinct ports in <3 seconds) and immediately
     drops the attacker IP on the firewall for 1 hour before scans can complete.
==============================================================================
"""

import os
import time
import socket
import struct
import threading
from collections import defaultdict, deque
import config
from modules.ban_manager import BanManager
from modules.smart_logger import SmartLogger

class HoneypotTrap:
    def __init__(self, ban_manager=None, callback=None, logger=None):
        self.ban_manager = ban_manager or BanManager()
        self.callback = callback
        self.logger = logger or SmartLogger()
        self.ports = getattr(config, 'HONEYPOT_PORTS', [23, 2323, 5555, 6379, 4444, 31337])
        self.listeners = []
        self.is_running = True
        
        # Sliding window for raw TCP SYN port sweeps: src_ip -> deque of (timestamp, dst_port)
        self.port_probes = defaultdict(deque)
        self.lock = threading.RLock()

    def _listen_port(self, port: int):
        """
        Listens on a decoy TCP port.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            sock.settimeout(2.0)
            print(f"[+] Honeypot Decoy Trap Active on TCP Port {port}")

            while self.is_running:
                try:
                    client_sock, client_addr = sock.accept()
                    attacker_ip = client_addr[0]
                    client_sock.close()

                    # Handle attacker
                    self._handle_honeypot_intercept(attacker_ip, port)
                except socket.timeout:
                    continue
                except Exception:
                    pass
        except OSError:
            # Port already in use by another service on this machine
            pass
        finally:
            sock.close()

    def _handle_honeypot_intercept(self, ip: str, port: int):
        """
        Enforces zero-tolerance ban upon honeypot trigger.
        """
        if self.ban_manager.is_protected_ip(ip):
            return

        ban_duration = getattr(config, 'HONEYPOT_BAN_DURATION_SECONDS', 86400)
        reason_msg = f"Zero-Tolerance Honeypot Intercept on Decoy Port {port}"

        print(f"\n[!] [HONEYPOT TRAP TRIGGERED] Scanner IP: {ip} probed decoy Port {port}!")
        
        self.logger.log_event(
            "CRITICAL", "HONEYPOT_TRAP", "HONEYPOT_PROBE_INTERCEPT", ip,
            f"Malicious scanner {ip} trapped on decoy port {port}. 24-Hour ban applied."
        )

        if self.callback:
            self.callback("HONEYPOT_PROBE_INTERCEPT", ip, f"Zero-Tolerance Honeypot Ban! IP {ip} trapped on Port {port}.")

        self.ban_manager.ban_ip(ip=ip, criticality="CRITICAL", reason=reason_msg, duration_override=ban_duration)

    def record_raw_probe(self, src_ip: str, dst_port: int) -> bool:
        """
        Records an incoming TCP probe packet into the port sweep detector.
        Returns True if a port scan burst is detected (>=5 distinct ports in <3s).
        """
        if not src_ip or self.ban_manager.is_protected_ip(src_ip) or self.ban_manager.is_banned(src_ip):
            return False

        now = time.time()
        with self.lock:
            history = self.port_probes[src_ip]
            while history and (now - history[0][0] > 3.0):
                history.popleft()

            history.append((now, dst_port))
            distinct_ports = {p for _, p in history}

            if len(distinct_ports) >= 5:
                history.clear()
                self._handle_port_scan_intercept(src_ip, len(distinct_ports))
                return True

        return False

    def _handle_port_scan_intercept(self, ip: str, scanned_port_count: int):
        """
        Enforces immediate 1-hour firewall ban on Nmap / Masscan port scan offenders.
        """
        if self.ban_manager.is_protected_ip(ip) or self.ban_manager.is_banned(ip):
            return

        ban_duration = 3600
        reason_msg = f"Nmap Port Scan Sweep Detected ({scanned_port_count}+ distinct ports probed in <3s)"

        print(f"\n[!] [PORT SCAN INTERCEPT ALERT] Host {ip} executed rapid Nmap port scan! Applying 1-Hour Firewall Ban...")

        self.logger.log_event(
            "CRITICAL", "PORT_SCAN_GUARD", "NMAP_PORT_SCAN_INTERCEPT", ip,
            f"Automated port sweep scan detected from {ip} ({scanned_port_count} ports in <3s). 1-Hour kernel ban enforced."
        )

        if self.callback:
            self.callback("NMAP_PORT_SCAN_INTERCEPT", ip, reason_msg)

        self.ban_manager.ban_ip(ip=ip, criticality="CRITICAL", reason=reason_msg, duration_override=ban_duration)

    def _start_raw_syn_sniffer(self):
        """
        Listens on raw TCP socket to catch Nmap SYN, NULL, FIN, XMAS scans at kernel speed.
        """
        if os.name == 'nt':
            return

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_sock.settimeout(2.0)
            print("[+] Kernel Raw Socket SYN / Nmap Port Scan Sniffer Active.")

            while self.is_running:
                try:
                    packet, addr = raw_sock.recvfrom(65535)
                    if len(packet) < 40:
                        continue

                    # IP Header (first 20 bytes)
                    ip_header = packet[0:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    ihl = (iph[0] & 0xF) * 4
                    src_ip = socket.inet_ntoa(iph[8])

                    if self.ban_manager.is_protected_ip(src_ip) or self.ban_manager.is_banned(src_ip):
                        continue

                    # TCP Header
                    tcp_header = packet[ihl:ihl+20]
                    if len(tcp_header) < 20:
                        continue

                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    dst_port = tcph[1]
                    flags = tcph[5]

                    # Detect TCP SYN, NULL, FIN, XMAS scan probes
                    syn_flag = bool(flags & 0x02)
                    ack_flag = bool(flags & 0x10)
                    fin_flag = bool(flags & 0x01)
                    rst_flag = bool(flags & 0x04)

                    is_probe = (syn_flag and not ack_flag) or (flags == 0) or (fin_flag and not ack_flag)
                    if is_probe and not rst_flag:
                        self.record_raw_probe(src_ip, dst_port)

                except socket.timeout:
                    continue
                except Exception:
                    pass
        except PermissionError:
            print("[*] Raw socket port scan sniffer requires root privileges (Honeypot TCP listeners active).")
        except Exception as e:
            print(f"[-] Raw Socket Sniffer Error: {e}")

    def start(self):
        """
        Spawns listener threads across all configured honeypot ports and raw socket sniffer.
        """
        if not getattr(config, 'ENABLE_HONEYPOT_TRAPS', True):
            print("[*] Honeypot Decoy Port Traps disabled in config.py.")
            return

        print(f"[+] Honeypot Decoy Trap Subsystem Initializing: {time.ctime()}")
        for p in self.ports:
            t = threading.Thread(target=self._listen_port, args=(p,), daemon=True, name=f"Honeypot_{p}")
            t.start()
            self.listeners.append(t)

        # Launch kernel raw socket port scan sniffer
        threading.Thread(target=self._start_raw_syn_sniffer, daemon=True, name="RawSynSniffer").start()

        while self.is_running:
            time.sleep(5)
