# -*- coding: utf-8 -*-
"""
==============================================================================
DISK I/O MONITORING SUBSYSTEM (disk_monitor.py)
==============================================================================
This module samples disk read and write throughput in real-time and raises
alerts when I/O speeds exceed configurable bandwidth thresholds.
==============================================================================
"""

import psutil
import time
import config

class DiskMonitor:
    def __init__(self, callback=None):
        self.callback = callback
        self.last_counters = psutil.disk_io_counters()
        self.last_time = time.time()

    def Get_Disk_Speed(self):
        """
        Samples disk read and write throughput non-blockingly (MB/s).
        """
        now = time.time()
        curr_counters = psutil.disk_io_counters()
        if not curr_counters or not self.last_counters:
            self.last_counters = curr_counters
            self.last_time = now
            return

        dt = now - self.last_time
        if dt <= 0.1:
            return

        read_bytes = max(0, curr_counters.read_bytes - self.last_counters.read_bytes)
        write_bytes = max(0, curr_counters.write_bytes - self.last_counters.write_bytes)

        self.last_counters = curr_counters
        self.last_time = now

        read_mb = (read_bytes / (1024 * 1024)) / dt
        write_mb = (write_bytes / (1024 * 1024)) / dt

        read_threshold = getattr(config, 'DISK_USAGE_READ_THRESHOLD', 100)
        if read_mb > read_threshold:
            msg = f"High Disk Read Speed Detected! Speed: {read_mb:.2f} MB/s"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("HIGH_DISK_READ", "DISK", msg)

        write_threshold = getattr(config, 'DISK_USAGE_WRITE_THRESHOLD', 100)
        if write_mb > write_threshold:
            msg = f"High Disk Write Speed Detected! Speed: {write_mb:.2f} MB/s"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("HIGH_DISK_WRITE", "DISK", msg)

    def start(self):
        """
        Starts the continuous Disk I/O monitoring loop.
        """
        print(f"[+] Disk Monitoring Service Started: {time.ctime()}")
        while True:
            try:
                self.Get_Disk_Speed()
            except Exception as e:
                print(f"[-] Disk Monitoring Error: {e}")
            time.sleep(getattr(config, 'CHECK_INTERVAL_SECONDS', 2))
