# -*- coding: utf-8 -*-
"""
==============================================================================
GPU / ACCELERATOR RESOURCE MONITORING (gpu_control.py)
==============================================================================
This module monitors GPU utilization and memory consumption for systems
equipped with dedicated graphics processing units.
==============================================================================
"""

import time
import config

try:
    import GPUtil
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

class Gpu_Controller:
    def __init__(self, callback=None):
        self.callback = callback

    def Get_GPU_INFO(self):
        """
        Samples GPU load and memory metrics.
        """
        if not GPU_AVAILABLE:
            return

        try:
            gpus = GPUtil.getGPUs()
            threshold = getattr(config, 'GPU_USAGE_THRESHOLD', 85.0)

            for gpu in gpus:
                load_percent = gpu.load * 100
                if load_percent > threshold:
                    msg = f"High GPU Load Detected ({gpu.name})! Utilization: {load_percent:.1f}%"
                    print(f"[!] {msg}")
                    if self.callback:
                        self.callback("HIGH_GPU_LOAD", gpu.name, msg)
        except Exception:
            pass

    def start(self):
        """
        Starts the GPU monitoring loop.
        """
        if GPU_AVAILABLE:
            print(f"[+] GPU Monitoring Service Started: {time.ctime()}")
            while True:
                try:
                    self.Get_GPU_INFO()
                except Exception as e:
                    print(f"[-] GPU Monitoring Error: {e}")
                time.sleep(getattr(config, 'CHECK_INTERVAL_SECONDS', 2))
        else:
            print("[*] GPU Hardware / GPUtil Driver not present. GPU monitor idle.")
            while True:
                time.sleep(3600)