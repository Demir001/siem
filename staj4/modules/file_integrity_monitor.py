# -*- coding: utf-8 -*-
"""
==============================================================================
FILE INTEGRITY MONITORING & ANTI-TAMPER SUBSYSTEM (file_integrity_monitor.py)
==============================================================================
This module provides cryptographic SHA-256 and inode integrity monitoring for
mission-critical system configuration files, credential stores, and SSH keys
(/etc/passwd, /etc/shadow, /etc/sudoers, /etc/ld.so.preload, authorized_keys).
Any unauthorized modification, injection, or deletion triggers an immediate
CRITICAL security alert.
==============================================================================
"""

import os
import time
import hashlib
import config
from modules.smart_logger import SmartLogger

class FileIntegrityMonitor:
    def __init__(self, callback=None, logger=None):
        self.callback = callback
        self.logger = logger or SmartLogger()
        self.monitored_paths = getattr(config, 'FIM_MONITORED_PATHS', [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
            "/etc/crontab", "/etc/hosts", "/etc/ld.so.preload", "config.py"
        ])
        self.baselines = {}
        self.init_baselines()

    def calculate_file_hash(self, file_path: str) -> str:
        """
        Calculates SHA-256 checksum for the specified file.
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return None

        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    def init_baselines(self):
        """
        Captures cryptographic baseline checksums and metadata on startup.
        """
        for path in self.monitored_paths:
            if os.path.exists(path) and os.path.isfile(path):
                f_hash = self.calculate_file_hash(path)
                stat = os.stat(path)
                self.baselines[path] = {
                    "hash": f_hash,
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                    "exists": True
                }
            else:
                self.baselines[path] = {
                    "hash": None,
                    "size": 0,
                    "mtime": 0,
                    "exists": False
                }

    def scan_integrity(self):
        """
        Scans all monitored targets against stored baselines.
        """
        if not getattr(config, 'ENABLE_FIM', True):
            return

        for path in self.monitored_paths:
            prev = self.baselines.get(path, {"exists": False, "hash": None})
            exists_now = os.path.exists(path) and os.path.isfile(path)

            # 1. File Newly Created (e.g. rootkit /etc/ld.so.preload or backdoor key)
            if not prev["exists"] and exists_now:
                new_hash = self.calculate_file_hash(path)
                stat = os.stat(path)
                self.baselines[path] = {"hash": new_hash, "size": stat.st_size, "mtime": stat.st_mtime, "exists": True}
                
                msg = f"CRITICAL TAMPER ALERT! Monitored file '{path}' was newly created! (SHA256: {new_hash[:16]}...)"
                print(f"[!] [FIM CREATED] {msg}")
                self.logger.log_event("CRITICAL", "FILE_INTEGRITY", "FILE_INTEGRITY_CREATED", path, msg)
                if self.callback:
                    self.callback("FILE_INTEGRITY_VIOLATION", path, msg)

            # 2. File Deleted (e.g. log / config wiped)
            elif prev["exists"] and not exists_now:
                self.baselines[path] = {"hash": None, "size": 0, "mtime": 0, "exists": False}
                
                msg = f"CRITICAL TAMPER ALERT! Monitored file '{path}' was DELETED from disk!"
                print(f"[!] [FIM DELETED] {msg}")
                self.logger.log_event("CRITICAL", "FILE_INTEGRITY", "FILE_INTEGRITY_DELETED", path, msg)
                if self.callback:
                    self.callback("FILE_INTEGRITY_VIOLATION", path, msg)

            # 3. File Content Modified / Tampered
            elif prev["exists"] and exists_now:
                stat = os.stat(path)
                if stat.st_mtime != prev["mtime"] or stat.st_size != prev["size"]:
                    curr_hash = self.calculate_file_hash(path)
                    if curr_hash and curr_hash != prev["hash"]:
                        old_h = prev["hash"] or "UNKNOWN"
                        self.baselines[path] = {"hash": curr_hash, "size": stat.st_size, "mtime": stat.st_mtime, "exists": True}
                        
                        msg = f"CRITICAL TAMPER ALERT! Unauthorized mutation in '{path}'! (Old: {old_h[:12]}... -> New: {curr_hash[:12]}...)"
                        print(f"[!] [FIM MODIFIED] {msg}")
                        self.logger.log_event("CRITICAL", "FILE_INTEGRITY", "FILE_INTEGRITY_MODIFIED", path, msg)
                        if self.callback:
                            self.callback("FILE_INTEGRITY_VIOLATION", path, msg)

    def start(self):
        """
        Starts the continuous File Integrity Monitoring loop.
        """
        print(f"[+] File Integrity Monitor (FIM) Active (Monitoring {len(self.monitored_paths)} targets): {time.ctime()}")
        interval = getattr(config, 'FIM_CHECK_INTERVAL_SECONDS', 5.0)
        while True:
            try:
                self.scan_integrity()
            except Exception as e:
                print(f"[-] FIM Scan Error: {e}")
            time.sleep(interval)
