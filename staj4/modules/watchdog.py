# -*- coding: utf-8 -*-
"""
==============================================================================
SELF-HEALING WATCHDOG & THREAD SUPERVISOR (watchdog.py)
==============================================================================
This module continuously monitors all registered background SIEM worker threads.
If any thread crashes or dies due to an unexpected system exception, the supervisor
automatically resurrects it (Self-Healing) to guarantee zero monitoring downtime.
==============================================================================
"""

import time
import threading
from modules.smart_logger import SmartLogger

class ThreadSupervisor:
    def __init__(self, logger=None):
        self.logger = logger or SmartLogger()
        self.services = {}
        self.is_running = True

    def register_service(self, name: str, target, args=()):
        """
        Registers a service target under active supervisor monitoring.
        """
        thread = threading.Thread(target=target, args=args, name=name, daemon=True)
        self.services[name] = {
            "target": target,
            "args": args,
            "thread": thread,
            "restart_count": 0,
            "last_start": time.time()
        }
        thread.start()
        print(f"[+] Watchdog: Registered & Started [{name}] (Thread ID: {thread.ident})")

    def supervise_loop(self):
        """
        Periodically inspects thread health and automatically restarts failed workers.
        """
        print("[+] Self-Healing Watchdog & Thread Supervisor Active.")
        
        while self.is_running:
            time.sleep(5)
            now = time.time()

            for name, info in list(self.services.items()):
                t = info["thread"]
                if not t.is_alive():
                    info["restart_count"] += 1
                    print(f"\n[!] [WATCHDOG ALERT] Service [{name}] DIED! Initiating Auto-Recovery (Restart #{info['restart_count']})...")
                    
                    self.logger.log_event(
                        "WARNING", "WATCHDOG", "SERVICE_RESTART", "LOCAL",
                        f"Thread [{name}] terminated unexpectedly. Auto-resurrecting service (Restart #{info['restart_count']})."
                    )

                    new_thread = threading.Thread(target=info["target"], args=info["args"], name=name, daemon=True)
                    info["thread"] = new_thread
                    info["last_start"] = now
                    new_thread.start()
                    print(f"[OK] [WATCHDOG HEALED] Service [{name}] successfully resurrected (New Thread ID: {new_thread.ident}).\n")

    def get_service_status(self) -> dict:
        """
        Returns the health status of all supervised services.
        """
        status = {}
        for name, info in self.services.items():
            status[name] = {
                "alive": info["thread"].is_alive(),
                "restart_count": info["restart_count"],
                "uptime_seconds": int(time.time() - info["last_start"])
            }
        return status
