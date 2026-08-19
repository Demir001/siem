# -*- coding: utf-8 -*-
"""
==============================================================================
RAM MONITORING SUBSYSTEM (ram_monitor.py)
==============================================================================
This module monitors system memory (RAM) utilization and identifies top
memory-consuming processes when utilization exceeds safety thresholds.
==============================================================================
"""

import psutil
import time
import config

class RamMonitor:
    def __init__(self, callback=None):
        self.callback = callback

    def get_top_process_ram(self):
        """
        Finds the process name consuming the highest memory percentage.
        """
        try:
            procs = []
            for p in psutil.process_iter(['name', 'memory_percent']):
                try:
                    info = p.info
                    procs.append((info.get('name') or "Unknown", info.get('memory_percent') or 0.0))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            if procs:
                procs.sort(key=lambda x: x[1], reverse=True)
                return procs[0][0]
            return "Unknown"
        except Exception:
            return "Unknown"

    def check_ram_usage(self):
        """
        Samples RAM utilization and triggers alerts if threshold is exceeded.
        """
        ram_usage = psutil.virtual_memory().percent
        threshold = getattr(config, 'RAM_USAGE_THRESHOLD', 85.0)

        if ram_usage > threshold:
            top_process = self.get_top_process_ram()
            msg = f"High RAM Usage Detected! Utilization: {ram_usage:.1f}% | Top Process: {top_process}"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("HIGH_RAM_USAGE", "RAM", msg)

        return ram_usage

    def start(self):
        """
        Starts the continuous RAM monitoring loop.
        """
        print(f"[+] RAM Monitoring Service Started: {time.ctime()}")
        while True:
            try:
                self.check_ram_usage()
            except Exception as e:
                print(f"[-] RAM Monitoring Error: {e}")
            time.sleep(getattr(config, 'CHECK_INTERVAL_SECONDS', 2))
