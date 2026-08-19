# -*- coding: utf-8 -*-
"""
==============================================================================
NETWORK BANDWIDTH MONITORING SUBSYSTEM (network_monitor.py)
==============================================================================
This module samples network interface throughput (Upload / Download MB/s)
and generates alerts when bandwidth spikes exceed configured thresholds.
==============================================================================
"""

import psutil
import time
import config

class NetworkMonitor:
    def __init__(self, callback=None):
        self.callback = callback
        self.last_counters = psutil.net_io_counters()
        self.last_time = time.time()

    def Get_Network_Speed(self):
        """
        Samples network upload and download throughput non-blockingly (MB/s).
        """
        now = time.time()
        curr_counters = psutil.net_io_counters()
        if not curr_counters or not self.last_counters:
            self.last_counters = curr_counters
            self.last_time = now
            return

        dt = now - self.last_time
        if dt <= 0.1:
            return

        sent_bytes = max(0, curr_counters.bytes_sent - self.last_counters.bytes_sent)
        recv_bytes = max(0, curr_counters.bytes_recv - self.last_counters.bytes_recv)

        self.last_counters = curr_counters
        self.last_time = now

        sent_mb = (sent_bytes / (1024 * 1024)) / dt
        recv_mb = (recv_bytes / (1024 * 1024)) / dt

        threshold = getattr(config, 'INTERNET_BANDWITH_USAGE_THRESHOLD', 100)

        if sent_mb > threshold:
            msg = f"High Network Upload Bandwidth Detected! Speed: {sent_mb:.2f} MB/s"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("HIGH_NET_UPLOAD", "NETWORK", msg)

        if recv_mb > threshold:
            msg = f"High Network Download Bandwidth Detected! Speed: {recv_mb:.2f} MB/s"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("HIGH_NET_DOWNLOAD", "NETWORK", msg)

    def start(self):
        """
        Starts the continuous Network monitoring loop.
        """
        print(f"[+] Network Monitoring Service Started: {time.ctime()}")
        while True:
            try:
                self.Get_Network_Speed()
            except Exception as e:
                print(f"[-] Network Monitoring Error: {e}")
            time.sleep(getattr(config, 'CHECK_INTERVAL_SECONDS', 2))
