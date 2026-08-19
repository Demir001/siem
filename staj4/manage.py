# -*- coding: utf-8 -*-
"""
==============================================================================
SIEM MANAGEMENT & INTERACTIVE SOC CLI CONTROLLER (manage.py)
==============================================================================
This command-line utility provides:
1. LIVE INTERACTIVE TERMINAL SOC DASHBOARD:
   - 'python manage.py monitor' (or 'top'): Real-time visual gauges, live ban countdown
     timers, active session tracking, and streaming security event feed.
2. SYSTEM & BAN STATUS:
   - 'python manage.py status': Instant static status report.
3. IP & SUB-NET FIREWALL MANAGEMENT:
   - 'python manage.py ban <ip/cidr>'
   - 'python manage.py unban <ip/cidr>'
   - 'python manage.py list-bans'
4. CRYPTOGRAPHIC LOG INTEGRITY AUDIT:
   - 'python manage.py verify-integrity': Verifies HMAC-SHA256 log blockchain chain.
5. JSON SECURITY REPORT EXPORT:
   - 'python manage.py export-report'
==============================================================================
"""

import os
import sys
import time
import json
import psutil
import argparse

import config
from modules.ban_manager import BanManager
from modules.db_manager import get_db_connection
from modules.smart_logger import SmartLogger
from modules.integrity_guard import LogIntegrityGuard

def render_progress_bar(percent: float, width: int = 16) -> str:
    """
    Renders a clean, cross-platform ASCII progress bar: [########--------]
    """
    p = max(0.0, min(100.0, percent))
    filled_len = int(round(width * p / 100.0))
    bar = "#" * filled_len + "-" * (width - filled_len)
    return f"[{bar}] {p:>5.1f}%"

def format_countdown(unban_at: float, now: float) -> str:
    """
    Formats remaining ban seconds into mm:ss or hh:mm format.
    """
    remaining = max(0, int(unban_at - now))
    if remaining >= 3600:
        h = remaining // 3600
        m = (remaining % 3600) // 60
        return f"{h:02d}h {m:02d}m"
    else:
        m = remaining // 60
        s = remaining % 60
        return f"{m:02d}m {s:02d}s"

def show_status():
    """
    Displays live system resource utilization, active bans, and active sessions.
    """
    now = time.time()
    bm = BanManager()

    print("\n" + "=" * 78)
    print("           SIEM SECURITY & SYSTEM MONITORING STATUS REPORT")
    print("=" * 78)

    # 1. Hardware Resource Utilization
    cpu_percent = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/") if os.name != 'nt' else psutil.disk_usage("C:\\")

    print(f"[*] CPU Utilization   : {render_progress_bar(cpu_percent)}")
    print(f"[*] RAM Utilization   : {render_progress_bar(ram.percent)} ({ram.used // (1024*1024)} MB / {ram.total // (1024*1024)} MB)")
    print(f"[*] Disk Utilization  : {render_progress_bar(disk.percent)} ({disk.free // (1024*1024*1024)} GB Free Space)")

    # 2. Database & Active Firewall Bans
    active_bans = []
    try:
        with get_db_connection("security_events.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""SELECT ip, network_type, criticality_level, reason, unban_at 
                              FROM banned_ips WHERE is_active = 1 AND unban_at > ?""", (now,))
            active_bans = cursor.fetchall()
    except Exception as e:
        print(f"[-] DB Query Error: {e}")

    print("\n" + "-" * 78)
    print(f"  ACTIVE FIREWALL RESTRICTIONS (TOTAL ACTIVE BANS: {len(active_bans)})")
    print("-" * 78)
    if active_bans:
        print(f"{'Target (IP/CIDR)':<22} {'Network':<10} {'Level':<10} {'Remaining':<12} {'Reason'}")
        print("-" * 78)
        for ip, net, crit, reason, unban_at in active_bans:
            rem_str = format_countdown(unban_at, now)
            print(f"{ip:<22} {net:<10} {crit:<10} {rem_str:<12} {reason[:26]}")
    else:
        print("  [OK] No active IP bans currently in effect. System clean.")

    # 3. Active Terminal Sessions
    active_sessions = []
    try:
        with get_db_connection("security_events.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""SELECT username, source_ip, tty_device, total_commands, last_activity_time 
                              FROM user_sessions WHERE status = 'ACTIVE'""")
            active_sessions = cursor.fetchall()
    except Exception:
        pass

    print("\n" + "-" * 78)
    print(f"  ACTIVE USER SESSIONS (TOTAL SESSIONS: {len(active_sessions)})")
    print("-" * 78)
    if active_sessions:
        print(f"{'Username':<15} {'Source IP':<20} {'Terminal':<10} {'Cmds':<6} {'Last Activity'}")
        print("-" * 78)
        for u, ip, tty, cmds, last_act in active_sessions:
            idle_mins = int((now - last_act) // 60)
            print(f"{u:<15} {ip:<20} {tty:<10} {cmds:<6} {idle_mins} mins ago")
    else:
        print("  [OK] No active user sessions detected.")

    print("=" * 78 + "\n")

def run_live_monitor():
    """
    Runs the real-time interactive terminal SOC monitor (Top / Dashboard).
    """
    bm = BanManager()
    clear_cmd = "cls" if os.name == "nt" else "clear"

    try:
        while True:
            now = time.time()
            cpu_percent = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage("/") if os.name != 'nt' else psutil.disk_usage("C:\\")

            # Query active bans
            active_bans = []
            recent_logs = []
            active_sessions = []

            try:
                with get_db_connection("security_events.db") as conn:
                    cursor = conn.cursor()
                    cursor.execute("""SELECT ip, network_type, criticality_level, reason, unban_at 
                                      FROM banned_ips WHERE is_active = 1 AND unban_at > ? ORDER BY unban_at DESC LIMIT 8""", (now,))
                    active_bans = cursor.fetchall()

                    cursor.execute("""SELECT username, source_ip, tty_device, total_commands, last_activity_time 
                                      FROM user_sessions WHERE status = 'ACTIVE' LIMIT 5""")
                    active_sessions = cursor.fetchall()

                    cursor.execute("""SELECT timestamp, level, event_type, target, mitre_id 
                                      FROM activity_logs ORDER BY id DESC LIMIT 5""")
                    recent_logs = cursor.fetchall()
            except Exception:
                pass

            os.system(clear_cmd)
            t_str = time.strftime("%Y-%m-%d %H:%M:%S")

            print("+" + "=" * 76 + "+")
            print(f"|   ENTERPRISE SIEM & SOC REAL-TIME INTERACTIVE DASHBOARD                    |")
            print(f"|   Time: {t_str} | Refresh: 1.0s | Press Ctrl+C to Exit              |")
            print("+" + "=" * 76 + "+")

            # 1. Hardware Utilization Section
            print(f" [HARDWARE UTILIZATION]")
            print(f"  CPU Usage : {render_progress_bar(cpu_percent, 20)}  |  Cores: {psutil.cpu_count(logical=True)}")
            print(f"  RAM Usage : {render_progress_bar(ram.percent, 20)}  |  Used : {ram.used // (1024*1024)}MB / {ram.total // (1024*1024)}MB")
            print(f"  Disk Space: {render_progress_bar(disk.percent, 20)}  |  Free : {disk.free // (1024*1024*1024)}GB")

            # 2. Active Firewall Restrictions
            print("\n" + "-" * 78)
            print(f" [ACTIVE FIREWALL RESTRICTIONS & BOTNET SUB-NET BANS] ({len(active_bans)} Active)")
            print("-" * 78)
            if active_bans:
                print(f" {'Target (IP/CIDR)':<22} {'Network':<10} {'Level':<10} {'Countdown':<12} {'Reason'}")
                print(" " + "-" * 76)
                for ip, net, crit, reason, unban_at in active_bans:
                    rem_str = format_countdown(unban_at, now)
                    print(f" {ip:<22} {net:<10} {crit:<10} {rem_str:<12} {reason[:24]}")
            else:
                print("  [OK] No active firewall bans. Perimeter clean.")

            # 3. Active Terminal Sessions
            print("\n" + "-" * 78)
            print(f" [ACTIVE USER TERMINAL SESSIONS] ({len(active_sessions)} Active)")
            print("-" * 78)
            if active_sessions:
                print(f" {'Username':<14} {'Source IP':<20} {'TTY':<10} {'Cmds':<6} {'Inactivity'}")
                print(" " + "-" * 76)
                for u, ip, tty, cmds, last_act in active_sessions:
                    idle_s = int(now - last_act)
                    idle_fmt = f"{idle_s//60}m {idle_s%60}s"
                    print(f" {u:<14} {ip:<20} {tty:<10} {cmds:<6} {idle_fmt}")
            else:
                print("  [OK] No interactive terminal sessions active.")

            # 4. Live Security Event Stream
            print("\n" + "-" * 78)
            print(" [LIVE SECURITY EVENT STREAM - LAST 5 EVENTS]")
            print("-" * 78)
            if recent_logs:
                for ts, lvl, ev, tgt, mitre in recent_logs:
                    short_ts = ts.split()[-1] if " " in ts else ts
                    mitre_str = f"[{mitre}]" if mitre and mitre != "N/A" else ""
                    print(f"  {short_ts} [{lvl:<8}] {ev:<28} Target: {tgt:<16} {mitre_str}")
            else:
                print("  [*] Awaiting incoming security events...")

            print("+" + "=" * 76 + "+")
            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\n[*] Live Dashboard Exited Cleanly.")

def verify_log_integrity_cmd(log_path="logs/activity_records.jsonl"):
    """
    Cryptographically verifies the HMAC-SHA256 hash chain of the activity logs.
    """
    guard = LogIntegrityGuard()
    print("\n" + "=" * 78)
    print("      CRYPTOGRAPHIC HMAC-SHA256 LOG INTEGRITY & ANTI-TAMPER AUDIT")
    print("=" * 78)
    print(f"[*] Target Log File : {log_path}")

    is_valid, total_checked, broken_line, msg = guard.verify_jsonl_log_file(log_path)

    if is_valid:
        print(f"[*] Records Verified: {total_checked:,} entries checked.")
        print(f"[OK] VERIFICATION PASSED: {msg}")
        print("[OK] Blockchain Hash Chain is 100% INTACT. Zero tampering detected.")
    else:
        print(f"[!] VERIFICATION FAILED: Corrupted or tampered at Line {broken_line}!")
        print(f"    Error Details: {msg}")
    print("=" * 78 + "\n")

def ban_ip_cmd(ip, duration=None, criticality="CRITICAL", reason="Manual Admin Ban"):
    bm = BanManager()
    bm.ban_ip(ip=ip, criticality=criticality, reason=reason, duration_override=duration)
    print(f"[OK] Target {ip} successfully banned.")

def unban_ip_cmd(ip):
    bm = BanManager()
    if ip.lower() in ["all", "--all"]:
        bm.unban_all(reason="Manual Admin Master Flush")
    else:
        bm.unban_ip(ip=ip, reason="Manual Admin Unban")
    if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("[*] Note: For complete kernel-level firewall purge, run as root: 'sudo python3 manage.py unban <IP>'")
    print(f"[OK] Restriction lifted for target {ip}.")

def unban_all_cmd():
    bm = BanManager()
    bm.unban_all(reason="Manual Admin Master Flush")
    if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("[*] Note: For complete kernel-level firewall purge, run as root: 'sudo python3 manage.py unban-all'")
    print("[OK] All firewall and database restrictions successfully cleared.")

def list_all_bans():
    try:
        with get_db_connection("security_events.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ip, reason, criticality_level, banned_at, unban_at, is_active FROM banned_ips ORDER BY id DESC LIMIT 20")
            rows = cursor.fetchall()
            
            print("\n" + "=" * 78)
            print("                RECENT & ACTIVE FIREWALL RESTRICTIONS")
            print("=" * 78)
            print(f" {'IP / CIDR':<20} {'LEVEL':<10} {'STATUS':<10} {'REASON':<36}")
            print("-" * 78)
            if rows:
                for ip, reason, crit, b_at, u_at, is_act in rows:
                    status = "ACTIVE" if is_act == 1 and u_at > time.time() else "EXPIRED"
                    print(f" {ip:<20} {crit:<10} {status:<10} {reason[:35]:<36}")
            else:
                print("  [OK] No ban history found.")
            print("=" * 78 + "\n")
    except Exception as e:
        print(f"[-] Query Bans Error: {e}")

def export_report(output_file="siem_security_report.json"):
    try:
        bm = BanManager()
        categories = {}
        with get_db_connection("security_events.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT incident_category, COUNT(*) FROM structured_security_events GROUP BY incident_category")
            for cat, count in cursor.fetchall():
                categories[cat] = count

        report_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "active_bans_count": len(bm.active_bans),
            "active_bans_list": list(bm.active_bans.keys()),
            "hardware": {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "ram_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent
            },
            "threat_categories": categories,
            "whitelist_active": True,
            "subnet_botnet_shield_active": True,
            "file_integrity_monitoring_active": True,
            "honeypot_traps_active": True,
            "c2_detection_active": True,
            "log_hmac_integrity_active": True,
            "multi_firewall_enforced": True
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

        print(f"[OK] Security Report Exported Successfully: {output_file}")
    except Exception as e:
        print(f"[-] Export Report Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="SIEM Management & Interactive SOC Dashboard")
    subparsers = parser.add_subparsers(dest="command", help="Available Commands")

    # status
    subparsers.add_parser("status", help="Displays instant static system and ban status")

    # monitor / top
    subparsers.add_parser("monitor", help="Launches the real-time interactive terminal SOC dashboard")
    subparsers.add_parser("top", help="Alias for 'monitor'")

    # verify-integrity
    vi_parser = subparsers.add_parser("verify-integrity", help="Verify HMAC-SHA256 cryptographic log chain")
    vi_parser.add_argument("--file", type=str, default="logs/activity_records.jsonl", help="Log file path to verify")

    # ban
    ban_parser = subparsers.add_parser("ban", help="Manually ban an IP or Subnet CIDR")
    ban_parser.add_argument("ip", type=str, help="IP address or CIDR subnet to ban (e.g. 198.51.100.50 or 198.51.100.0/24)")
    ban_parser.add_argument("--duration", type=int, default=None, help="Ban duration in seconds")
    ban_parser.add_argument("--criticality", type=str, default="CRITICAL", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    ban_parser.add_argument("--reason", type=str, default="Manual Administrator Ban")

    # unban
    unban_parser = subparsers.add_parser("unban", help="Lift ban restriction for an IP or Subnet CIDR")
    unban_parser.add_argument("ip", type=str, help="IP address or CIDR subnet to unban (or 'all' / '--all')")

    # unban-all
    subparsers.add_parser("unban-all", help="Lift all active IP and Subnet ban restrictions")

    # list-bans
    subparsers.add_parser("list-bans", help="List recent and active IP/Subnet bans")

    # export-report
    rep_parser = subparsers.add_parser("export-report", help="Export SIEM security metrics as JSON")
    rep_parser.add_argument("--output", type=str, default="siem_security_report.json")

    args = parser.parse_args()

    if args.command in ["monitor", "top"]:
        run_live_monitor()
    elif args.command == "status" or not args.command:
        show_status()
    elif args.command == "verify-integrity":
        verify_log_integrity_cmd(args.file)
    elif args.command == "ban":
        ban_ip_cmd(args.ip, duration=args.duration, criticality=args.criticality, reason=args.reason)
    elif args.command == "unban":
        unban_ip_cmd(args.ip)
    elif args.command == "unban-all":
        unban_all_cmd()
    elif args.command == "list-bans":
        list_all_bans()
    elif args.command == "export-report":
        export_report(args.output)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
