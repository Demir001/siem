# -*- coding: utf-8 -*-
"""
==============================================================================
SMART ACTIVITY & SECURITY EVENT LOGGER (smart_logger.py)
==============================================================================
This module translates raw technical logs, AI threat detections, typo tolerance
events, and multi-backend ban events into structured English summaries.
Every record is cryptographically sealed with an HMAC-SHA256 blockchain chain
and categorized with [SAFE OPERATION] or [MALICIOUS OPERATION] tags.
==============================================================================
"""

import os
import time
import json
import sqlite3
import config
from modules.db_manager import get_db_connection
from modules.integrity_guard import LogIntegrityGuard

class SmartLogger:
    def __init__(self, log_dir="logs", db_name="security_events.db"):
        self.log_dir = log_dir
        self.db_name = db_name
        
        os.makedirs(self.log_dir, exist_ok=True)
        
        self.readable_log_path = os.path.join(self.log_dir, "readable_activity.log")
        self.jsonl_log_path = os.path.join(self.log_dir, "activity_records.jsonl")

        self.integrity_guard = LogIntegrityGuard()
        self.init_db()

    def init_db(self):
        """
        Initializes the 'activity_logs' table in SQLite WAL mode.
        """
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    level TEXT,
                    status TEXT,
                    module TEXT,
                    event_type TEXT,
                    target TEXT,
                    summary TEXT,
                    raw_details TEXT,
                    mitre_id TEXT,
                    ai_verdict TEXT
                )""")
                conn.commit()
        except Exception as e:
            print(f"[-] Log Database Initialization Error: {e}")

    def determine_operation_status(self, level, event_type, ai_info=None) -> str:
        """
        Classifies whether an operation is SAFE, MALICIOUS, or SUSPICIOUS.
        """
        if ai_info and isinstance(ai_info, dict) and ai_info.get("is_attack"):
            if ai_info.get("verdict") == "ZERO_DAY":
                return "MALICIOUS ZERO-DAY"
            return "MALICIOUS ATTACK"

        malicious_events = [
            "AI_ATTACK_DETECTED", "ADVANCED_THREAT_DETECTED", "DESTRUCTIVE_MUTATION",
            "REVERSE_SHELL_ATTEMPT", "SENSITIVE_FILE_READ", "ARP_SPOOFING_DETECTED",
            "NIC_PROMISCUOUS_ENTER", "SUDO_ROOT_SHELL", "DICTIONARY_PROBE",
            "RAPID_BRUTE_FORCE", "EXTERNAL_IP_BAN", "INTERNAL_IP_BAN", "UNVERIFIED_SCRIPT_PIPE",
            "FILE_INTEGRITY_VIOLATION", "HONEYPOT_PROBE_INTERCEPT", "C2_REVERSE_SHELL_INTERCEPT"
        ]
        
        if event_type in malicious_events or level.upper() in ["CRITICAL", "ALERT"]:
            return "MALICIOUS OPERATION"
        elif level.upper() == "WARNING" or "TYPO_THRESHOLD_EXCEEDED" in event_type or "IDLE_SESSION" in event_type:
            return "SUSPICIOUS / WARNING"
        else:
            return "SAFE OPERATION"

    def synthesize_summary(self, event_type, target, details, ai_info=None):
        """
        Synthesizes technical events into clean human-readable English summaries.
        """
        if ai_info and isinstance(ai_info, dict) and ai_info.get("is_attack"):
            verdict = ai_info.get("verdict", "ATTACK")
            conf = ai_info.get("confidence", 90.0)
            mitre = ai_info.get("mitre_id", "N/A")
            cat = ai_info.get("incident_category", "EXPLOIT")
            title = ai_info.get("incident_title", "Attack Vector")
            return f"AI [{verdict}] ({conf:.1f}% Confidence) | {title} (MITRE {mitre} - {cat}) detected from {target}."

        if event_type == "HUMAN_TYPO_TOLERATED":
            return f"Human password typo tolerated for target {target}. (Safe Operation - No ban applied)."
        elif event_type == "AUTH_RECOVERY_FORGIVEN":
            return f"Legitimate authentication succeeded for {target}. Past typo failures forgiven."
        elif event_type == "DICTIONARY_PROBE":
            return f"Automated dictionary scanning attack targeting privileged accounts from {target}."
        elif event_type == "RAPID_BRUTE_FORCE":
            return f"High-velocity automated brute-force attack burst detected from {target}."
        elif event_type == "EXTERNAL_IP_BAN":
            return f"EXTERNAL WAN IP {target} dropped on firewall due to security violations."
        elif event_type == "INTERNAL_IP_BAN":
            return f"INTERNAL LAN IP {target} SSH isolated due to security violations."
        elif event_type == "FILE_INTEGRITY_VIOLATION" or "FILE_INTEGRITY" in event_type:
            return f"Critical System File Integrity Breach detected on '{target}'."
        elif event_type == "HONEYPOT_PROBE_INTERCEPT":
            return f"Malicious scanner {target} intercepted on deceptive honeypot trap."
        elif event_type == "C2_REVERSE_SHELL_INTERCEPT":
            return f"Outbound Reverse Shell / C2 beacon connection to {target} killed."
        elif event_type == "IDLE_SESSION_KICKED":
            return f"User session for {target} terminated due to 15-minute inactivity timeout."
        elif event_type == "SSH_SUCCESS":
            return f"User authenticated successfully from {target}."
        elif event_type == "SSH_LOGOUT":
            return f"User logged out from {target}."
        elif event_type == "DESTRUCTIVE_MUTATION":
            return f"Destructive system file wipe command intercepted from {target}."
        elif event_type == "REVERSE_SHELL_ATTEMPT":
            return f"Outbound reverse shell network connection attempt intercepted from {target}."
        elif event_type == "SENSITIVE_FILE_READ":
            return f"Unauthorized credential file read (/etc/shadow) intercepted from {target}."
        else:
            return str(details)[:180]

    def log_event(self, level, module, event_type, target, details, ai_info=None):
        """
        Logs event across human-readable text, cryptographically sealed JSONL, and SQLite database.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        status_tag = self.determine_operation_status(level, event_type, ai_info)
        summary = self.synthesize_summary(event_type, target, details, ai_info)
        
        mitre_id = "N/A"
        ai_verdict = "N/A"
        if ai_info and isinstance(ai_info, dict):
            mitre_id = ai_info.get("mitre_id", "N/A")
            ai_verdict = ai_info.get("verdict", "N/A")

        # 1. Human-Readable Log File Output
        readable_entry = (
            f"[{timestamp}] [{level.upper():<8}] [{status_tag}] [{module}] [{event_type}]\n"
            f"  Target: {target} | MITRE: {mitre_id} | AI Verdict: {ai_verdict}\n"
            f"  Summary: {summary}\n"
            f"  Details: {details}\n"
            f"{'-'*75}\n"
        )
        try:
            with open(self.readable_log_path, "a", encoding="utf-8") as f:
                f.write(readable_entry)
        except Exception as e:
            print(f"[-] Readable Log Write Error: {e}")

        # 2. Cryptographically Sealed JSONL Log File Output (HMAC-SHA256 Chain)
        jsonl_data = {
            "timestamp": timestamp,
            "level": level,
            "status": status_tag,
            "module": module,
            "event_type": event_type,
            "target": str(target),
            "summary": summary,
            "details": str(details),
            "mitre_id": mitre_id,
            "ai_verdict": ai_verdict
        }

        if getattr(config, 'ENABLE_LOG_INTEGRITY_SEAL', True):
            jsonl_data = self.integrity_guard.seal_jsonl_record(jsonl_data)

        try:
            with open(self.jsonl_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(jsonl_data, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[-] JSONL Log Write Error: {e}")

        # 3. Persist to SQLite Database (WAL Mode)
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""INSERT INTO activity_logs 
                    (timestamp, level, status, module, event_type, target, summary, raw_details, mitre_id, ai_verdict)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (timestamp, level, status_tag, module, event_type, str(target), summary, str(details), mitre_id, ai_verdict))
                conn.commit()
        except Exception as e:
            print(f"[-] Activity Log DB Write Error: {e}")
