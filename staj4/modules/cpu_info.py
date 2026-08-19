# -*- coding: utf-8 -*-
"""
==============================================================================
CPU MONITORING & MANAGEMENT SUBSYSTEM (cpu_info.py)
==============================================================================
This module monitors overall CPU utilization, per-core workload spikes,
frequency fluctuations, and IOWait bottleneck metrics.
==============================================================================
"""

import psutil
import time
import config

class CPU_Manager:
    def __init__(self, callback=None):
        self.callback = callback

    def get_top_process_cpu(self):
        """
        Identifies the process consuming the highest percentage of CPU.
        """
        try:
            procs = []
            for p in psutil.process_iter(['name', 'cpu_percent']):
                try:
                    info = p.info
                    procs.append((info.get('name') or "Unknown", info.get('cpu_percent') or 0.0))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            if procs:
                procs.sort(key=lambda x: x[1], reverse=True)
                return procs[0][0]
            return "Unknown"
        except Exception:
            return "Unknown"

    def get_cpu_iowait(self):
        """
        Calculates the percentage of time the CPU spent waiting for disk I/O.
        """
        try:
            cpu_t = psutil.cpu_times_percent(interval=None)
            return getattr(cpu_t, 'iowait', 0.0)
        except Exception:
            return 0.0

    def Get_CPU_INFO(self):
        """
        Samples CPU metrics and triggers threshold alerts.
        """
        cpu_per_core = psutil.cpu_percent(interval=1.0, percpu=True)
        cpu_usage = sum(cpu_per_core) / len(cpu_per_core) if cpu_per_core else 0.0
        core_threshold = getattr(config, 'CPU_USAGE_BY_CORE_THRESHOLD', 95.0)

        # 1. Per-Core Overload Check
        for i in range(len(cpu_per_core)):
            if cpu_per_core[i] > core_threshold:
                msg = f"CPU Core {i} Overloaded! Utilization: {cpu_per_core[i]:.1f}%"
                print(f"[!] {msg}")
                if self.callback:
                    self.callback("CPU_CORE_OVERLOAD", f"Core_{i}", msg)

        # 2. Overall CPU Threshold Check
        cpu_threshold = getattr(config, 'CPU_USAGE_THRESHOLD', 85.0)
        if cpu_usage > cpu_threshold:
            top_process = self.get_top_process_cpu()
            msg = f"High Overall CPU Usage! Utilization: {cpu_usage:.1f}% | Top Process: {top_process}"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("HIGH_CPU_USAGE", "CPU", msg)

        # 3. CPU IOWait Bottleneck Check
        cpu_iowait = self.get_cpu_iowait()
        iowait_threshold = getattr(config, 'CPU_IOWAIT_THRESHOLD', 20.0)
        if cpu_iowait > iowait_threshold:
            msg = f"CPU IOWait Bottleneck Detected! IOWait: {cpu_iowait:.1f}%"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("CPU_IOWAIT_BOTTLENECK", "CPU", msg)

    def start(self):
        """
        Starts the CPU Monitoring loop.
        """
        print(f"[+] CPU Monitoring Service Started: {time.ctime()}")
        while True:
            try:
                self.Get_CPU_INFO()
            except Exception as e:
                print(f"[-] CPU Monitoring Error: {e}")
            time.sleep(getattr(config, 'CHECK_INTERVAL_SECONDS', 2))