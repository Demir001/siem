# -*- coding: utf-8 -*-
"""
==============================================================================
ENTERPRISE SECURITY & SYSTEM MONITORING ENGINE (main.py)
==============================================================================
This module orchestrates all 12 monitoring & defense subsystems:
1. Multi-Layer Dual-AI Threat & Zero-Day Anomaly Detection Engine
2. Multi-Backend Tiered Ban Manager (UFW + IPTables Kernel Drop)
3. 15-Minute Multi-Session & Hostile TTY Auto-Kick Tracker
4. 106-Rule High-Speed Log Parser & Logrotate Inode Watcher
5. Distributed Botnet Subnet / CIDR Defense Shield
6. File Integrity Monitoring (FIM - SHA256 Anti-Tamper Baseline)
7. Honeypot Decoy Port Traps (Telnet 23, ADB 5555, Redis 6379, etc.)
8. Outbound C2 & Reverse Shell Beaconing Guard
9. Hardware Telemetry Monitors (CPU, RAM, Disk, Network, GPU)
10. Automated Log Size Watcher & ZIP Compressor
11. Cryptographic HMAC-SHA256 Log Blockchain Sealer
12. Self-Healing Watchdog & Thread Supervisor (Auto-Resurrection)
==============================================================================
"""

import os
import time
import threading
import config

# Optimize Linux file descriptor limits (prevents EMFILE / 'Too many open files' error)
if os.name != 'nt':
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_limit = min(65536, hard)
        if soft < target_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard))
    except Exception:
        pass

# Subsystem Imports
from modules.smart_logger import SmartLogger
from modules.ban_manager import BanManager
from modules.ai_security_engine import AISecurityEngine
from modules.user_session_tracker import UserSessionTracker
from modules.log_monitor import LogMonitor
from modules.file_integrity_monitor import FileIntegrityMonitor
from modules.honeypot_trap import HoneypotTrap
from modules.c2_detector import C2Detector
from modules.cpu_info import CPU_Manager
from modules.ram_monitor import RamMonitor
from modules.disk_monitor import DiskMonitor
from modules.network_monitor import NetworkMonitor
from modules.gpu_control import Gpu_Controller
from modules.file_control_zip import FileManager
from modules.db_manager import DataBaseManager
from modules.alert import Alert
from modules.watchdog import ThreadSupervisor

# Global Core Instances
logger = SmartLogger()
ban_man = BanManager(logger=logger)
ai_engine = AISecurityEngine()
session_tracker = UserSessionTracker(logger=logger, ai_engine=ai_engine, ban_manager=ban_man)
db_man = DataBaseManager(database_name="security_events.db")
alert_service = Alert()
supervisor = ThreadSupervisor(logger=logger)

def alert_handler(event_type, target, message):
    """
    Central Alert Handler for SIEM events.
    """
    level = "INFO"
    if any(k in event_type for k in ["ADVANCED_THREAT", "AI_ATTACK", "AI_ZERO_DAY", "ROOT", "SPOOFING", "BAN", "KICKED", "FILE_INTEGRITY", "HONEYPOT", "C2_"]):
        level = "CRITICAL"
    elif any(k in event_type for k in ["HIGH_", "OVERLOAD", "IDLE"]):
        level = "WARNING"
    elif any(k in event_type for k in ["ATTEMPT", "BLOCK"]):
        level = "ALERT"

    logger.log_event(level=level, module="SIEM_MONITOR", event_type=event_type, target=target, details=message)
    status_tag = logger.determine_operation_status(level, event_type)
    print(f"[{level}] [{status_tag}] [{event_type}] Target: {target} | {message}")

    if level in ["ALERT", "CRITICAL"] and alert_service.is_enabled():
        try:
            alert_service.send_alert(f"Subject: SIEM ALERT [{level}] - {event_type}\n\n{message}")
        except Exception:
            pass

if __name__ == "__main__":
    print("=================================================================")
    print("  ENTERPRISE SIEM & DEFENSE PLATFORM INITIALIZING (12 ENGINES)   ")
    print("=================================================================")

    # A. Initialize Database and Smart Logger
    db_man.start()
    logger.log_event("INFO", "SYSTEM", "SYSTEM_START", "LOCAL", "SIEM Monitoring & Defense Platform Initialized.")

    # B. Load Multi-Layer AI Security Models into Memory
    ai_engine.load_all_models()

    # C. Instantiate All Monitoring & Defense Subsystems
    log_mon = LogMonitor(callback=alert_handler, ban_manager=ban_man, session_tracker=session_tracker, ai_engine=ai_engine)
    fim_mon = FileIntegrityMonitor(callback=alert_handler, logger=logger)
    honeypot = HoneypotTrap(ban_manager=ban_man, callback=alert_handler, logger=logger)
    c2_guard = C2Detector(ban_manager=ban_man, callback=alert_handler, logger=logger)
    cpu_mon = CPU_Manager(callback=alert_handler)
    ram_mon = RamMonitor(callback=alert_handler)
    disk_mon = DiskMonitor(callback=alert_handler)
    net_mon = NetworkMonitor(callback=alert_handler)
    gpu_mon = Gpu_Controller(callback=alert_handler)
    file_man = FileManager(file_path=config.LINUX_APP_LOG_PATH)

    # D. Register All 12 Subsystems Under Self-Healing Watchdog
    supervisor.register_service("SessionTracker", session_tracker.start)
    supervisor.register_service("BanManager", ban_man.start)
    supervisor.register_service("LogMonitor", log_mon.start)
    supervisor.register_service("FileIntegrityMonitor", fim_mon.start)
    supervisor.register_service("HoneypotTrap", honeypot.start)
    supervisor.register_service("C2Detector", c2_guard.start)
    supervisor.register_service("CpuMonitor", cpu_mon.start)
    supervisor.register_service("RamMonitor", ram_mon.start)
    supervisor.register_service("DiskMonitor", disk_mon.start)
    supervisor.register_service("NetworkMonitor", net_mon.start)
    supervisor.register_service("GpuMonitor", gpu_mon.start)
    supervisor.register_service("FileManager", file_man.start)

    # Launch Watchdog Supervisor Loop in Background
    threading.Thread(target=supervisor.supervise_loop, daemon=True).start()

    print("\n[+] All 12 Defense & Monitoring Engines, AI Core, and Self-Healing Watchdog Active!")
    print("[+] Activity logs cryptographically sealed to 'logs/activity_records.jsonl'.")
    print("[+] Use 'python manage.py monitor' or 'status' to inspect live SIEM status.\n")
    print("[+] Press Ctrl+C to terminate the monitoring engine...\n")

    # E. Keep Main Thread Alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.log_event("INFO", "SYSTEM", "SYSTEM_STOP", "LOCAL", "SIEM Monitoring Service Terminated by User.")
        print("\n[*] Monitoring Service Terminated by User Request.")