# -*- coding: utf-8 -*-
"""
==============================================================================
HONEYPOT DECOY PORT TRAP DEFENSE SUBSYSTEM (honeypot_trap.py)
==============================================================================
This module sets up lightweight, zero-overhead deceptive TCP listeners on
commonly probed unassigned attack ports (Telnet 23, ADB 5555, Redis 6379,
Web Alternate 8080/8888). Any entity initiating a connection to these trap
ports is instantly identified as an unauthorized scanner and banned on the
firewall for 24 hours before they can discover real services.
==============================================================================
"""

import os
import time
import socket
import threading
import config
from modules.ban_manager import BanManager
from modules.smart_logger import SmartLogger

class HoneypotTrap:
    def __init__(self, ban_manager=None, callback=None, logger=None):
        self.ban_manager = ban_manager or BanManager()
        self.callback = callback
        self.logger = logger or SmartLogger()
        self.ports = getattr(config, 'HONEYPOT_PORTS', [23, 2323, 5555, 6379, 8080, 8888])
        self.listeners = []
        self.is_running = True

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

    def start(self):
        """
        Spawns listener threads across all configured honeypot ports.
        """
        if not getattr(config, 'ENABLE_HONEYPOT_TRAPS', True):
            print("[*] Honeypot Decoy Port Traps disabled in config.py.")
            return

        print(f"[+] Honeypot Decoy Trap Subsystem Initializing: {time.ctime()}")
        for p in self.ports:
            t = threading.Thread(target=self._listen_port, args=(p,), daemon=True, name=f"Honeypot_{p}")
            t.start()
            self.listeners.append(t)

        while self.is_running:
            time.sleep(5)
