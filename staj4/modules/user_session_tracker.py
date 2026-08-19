# -*- coding: utf-8 -*-
"""
==============================================================================
MULTI-SESSION, IDLE INACTIVITY & COMMAND TRACKING ENGINE
(user_session_tracker.py)
==============================================================================
This module provides:
1. MULTI-SESSION & IDLE TIMEOUT AUTO-KICK (15-Minute Threshold):
   - Monitors active terminal sessions and cleanly terminates idle sessions.
2. LOW-NOISE COMMAND BUFFERING:
   - Aggregates routine developer commands into periodic summaries to reduce noise.
3. HOSTILE INTRUSION INTERCEPT:
   - Detects destructive commands, reverse shells, or privilege escalation and
     immediately terminates the user's terminal session while applying an IP ban.
4. THREAD-SAFE SQLITE CONCURRENCY (WAL Mode & Busy Timeout).
5. ZOMBIE & STALE SESSION CLEANUP:
   - Automatically resolves stale sessions on boot or upon new login on the same TTY.
==============================================================================
"""

import os
import time
import sqlite3
import config
from modules.smart_logger import SmartLogger
from modules.ai_security_engine import AISecurityEngine
from modules.ban_manager import BanManager
from modules.db_manager import get_db_connection

class UserSessionTracker:
    def __init__(self, db_name="security_events.db", logger=None, ai_engine=None, ban_manager=None):
        self.db_name = db_name
        self.logger = logger or SmartLogger()
        self.ai_engine = ai_engine or AISecurityEngine()
        self.ban_manager = ban_manager or BanManager(logger=self.logger)
        
        self.active_sessions = {}
        self.init_db()
        self.cleanup_stale_sessions_on_boot()

    def init_db(self):
        """
        Initializes user session and activity log tables in WAL mode.
        """
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id TEXT PRIMARY KEY,
                    username TEXT,
                    source_ip TEXT,
                    tty_device TEXT,
                    login_time REAL,
                    logout_time REAL,
                    last_activity_time REAL,
                    total_commands INTEGER,
                    status TEXT
                )""")
                
                cursor.execute("""CREATE TABLE IF NOT EXISTS session_activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    username TEXT,
                    source_ip TEXT,
                    timestamp TEXT,
                    command TEXT,
                    category TEXT,
                    risk_score INTEGER,
                    summary TEXT,
                    mitre_id TEXT,
                    criticality TEXT
                )""")
                conn.commit()
        except Exception as e:
            print(f"[-] Session Database Initialization Error: {e}")

    def cleanup_stale_sessions_on_boot(self):
        """
        Marks unclosed sessions from previous reboots or crashes as CLOSED.
        """
        now = time.time()
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE user_sessions SET status = 'SYSTEM_REBOOT_CLOSED', logout_time = ? WHERE status = 'ACTIVE'", (now,))
                conn.commit()
        except Exception:
            pass

    def start_session(self, username, source_ip, tty="pts/0"):
        """
        Registers and logs a new active user terminal session.
        """
        now = time.time()
        session_id = f"SESS_{username}_{source_ip}_{tty.replace('/', '_')}_{int(now)}"
        session_key = (username, source_ip, tty)
        
        session_data = {
            "session_id": session_id,
            "username": username,
            "source_ip": source_ip,
            "tty": tty,
            "login_time": now,
            "last_activity_time": now,
            "routine_buffer": [],
            "command_count": 0,
            "cumulative_risk": 0
        }
        
        self.active_sessions[session_key] = session_data

        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                # Mark previous active sessions on this TTY as superseded
                cursor.execute("""UPDATE user_sessions SET status = 'SUPERSEDED', logout_time = ? 
                                  WHERE username = ? AND tty_device = ? AND status = 'ACTIVE'""", (now, username, tty))
                cursor.execute("""INSERT INTO user_sessions 
                    (session_id, username, source_ip, tty_device, login_time, logout_time, last_activity_time, total_commands, status)
                    VALUES (?, ?, ?, ?, ?, 0, ?, 0, 'ACTIVE')""",
                    (session_id, username, source_ip, tty, now, now))
                conn.commit()
        except Exception as e:
            print(f"[-] Session Database Write Error: {e}")

        msg = f"User '{username}' logged in successfully. (IP: {source_ip} | Terminal: {tty})"
        self.logger.log_event("NOTICE", "SESSION_TRACKER", "USER_LOGIN", source_ip, msg)
        print(f"[+] [SESSION STARTED] {msg}")

    def record_command(self, username, source_ip, command, tty="pts/0"):
        """
        Analyzes command execution in user session and terminates hostile sessions.
        """
        session_key = (username, source_ip, tty)
        now = time.time()
        
        if session_key not in self.active_sessions:
            self.start_session(username, source_ip, tty)
            
        session = self.active_sessions[session_key]
        session["last_activity_time"] = now
        session["command_count"] += 1

        # 1. Analyze command context & AI classification
        category, risk_score, is_anomaly, summary, ai_res, criticality = self.analyze_command_context(username, command)

        # 2. Buffer low-risk routine commands
        if not is_anomaly and risk_score == 0:
            session["routine_buffer"].append(command)
            if len(session["routine_buffer"]) >= 10:
                self.flush_routine_buffer(session)
            return

        # 3. Log suspicious/hostile command event
        session["cumulative_risk"] += risk_score
        mitre_id = ai_res.get("mitre_id", "N/A")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""INSERT INTO session_activity_logs 
                    (session_id, username, source_ip, timestamp, command, category, risk_score, summary, mitre_id, criticality)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (session["session_id"], username, source_ip, timestamp, command, category, risk_score, summary, mitre_id, criticality))
                
                cursor.execute("UPDATE user_sessions SET total_commands = ?, last_activity_time = ? WHERE session_id = ?",
                    (session["command_count"], now, session["session_id"]))
                conn.commit()
        except Exception as e:
            print(f"[-] Command Logging Error: {e}")

        level = "CRITICAL" if criticality == "CRITICAL" else ("WARNING" if criticality == "HIGH" else "NOTICE")
        log_msg = f"Session [{session['session_id']}]: User '{username}' executed '{command}'. (Summary: {summary})"
        self.logger.log_event(level, "USER_ACTIVITY", f"COMMAND_{category}", source_ip, log_msg, ai_info=ai_res)

        # Immediate hostile action intercept & session kill
        if risk_score >= 70 or session["cumulative_risk"] >= 50:
            if not self.ban_manager.is_banned(source_ip) and not self.ban_manager.is_protected_ip(source_ip):
                ban_reason = f"Session Hostile Activity: '{command}' ({criticality} Level - Risk: {session['cumulative_risk']})"
                self.ban_manager.ban_ip(ip=source_ip, criticality=criticality, reason=ban_reason)
                session["cumulative_risk"] = 0
                
                if os.name != 'nt':
                    try:
                        clean_tty = tty.replace("/dev/", "")
                        is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0)
                        kill_cmd = f"pkill -9 -t {clean_tty}" if is_root else f"sudo -n pkill -9 -t {clean_tty}"
                        subprocess.run(kill_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                    except Exception:
                        pass

    def analyze_command_context(self, username, command):
        cmd = command.strip()
        cmd_lower = cmd.lower()
        
        # 1. SIEM internal operations & maintenance commands (Bypasses AI to eliminate recursive loops)
        if any(w in cmd_lower for w in ["ufw ", "iptables ", "ip6tables ", "pkill ", "ss -k", "conntrack -d", "main.py", "manage.py"]):
            return "ROUTINE_COMMAND", 0, False, "System Administration / SIEM Maintenance", {}, "LOW"

        ai_res = self.ai_engine.analyze(cmd)
        
        if any(w in cmd_lower for w in ["rm -rf /", "shred", "mkfs", "dd if=/dev/zero", "dd if=/dev/urandom of=/dev/sda"]):
            return "DESTRUCTIVE_MUTATION", 90, True, "Dangerous Destructive System Data Wipe Attempt", ai_res, "CRITICAL"

        if ("curl" in cmd_lower or "wget" in cmd_lower) and ("| bash" in cmd_lower or "| sh" in cmd_lower or "| perl" in cmd_lower):
            return "UNVERIFIED_SCRIPT_PIPE", 80, True, "Unverified Remote Web Script Piped Directly into Shell", ai_res, "HIGH"

        if "cat /etc/shadow" in cmd_lower or "cat /etc/sudoers" in cmd_lower:
            return "SENSITIVE_FILE_READ", 75, True, "Unauthorized Sensitive Credential/Privilege File Read", ai_res, "CRITICAL"
            
        if any(w in cmd_lower for w in ["sudo su", "su -", "pkexec", "doas", "chmod +s /bin/bash", "chmod 4755"]):
            return "PRIVILEGE_ESCALATION", 70, True, "Privilege Elevation / SUID Backdoor Spawned", ai_res, "HIGH"

        if any(w in cmd_lower for w in ["nc -e", "ncat -e", "/dev/tcp/", "socat exec", "mkfifo /tmp/f"]):
            return "REVERSE_SHELL_ATTEMPT", 85, True, "Outbound Reverse Shell Connection Attempt", ai_res, "CRITICAL"

        if ("python" in cmd_lower or "perl" in cmd_lower or "php" in cmd_lower) and "-c " in cmd_lower and any(k in cmd_lower for k in ["socket", "pty", "subprocess", "exec", "b64decode"]):
            return "INLINE_INTERPRETER_EXEC", 60, True, "Inline Command-Line Code String Injection Execution", ai_res, "HIGH"

        if ai_res.get("is_attack"):
            verdict = ai_res.get("verdict", "ATTACK")
            title = ai_res.get("incident_title", "Cyber Threat Detected")
            cat = ai_res.get("incident_category", "AI_ANOMALY")
            urgency = ai_res.get("urgency", "HIGH")
            score = 75 if urgency == "CRITICAL" else 60
            return f"AI_{cat}", score, True, f"AI {verdict}: {title}", ai_res, urgency

        return "ROUTINE_COMMAND", 0, False, "Routine Normal User / Developer Activity", ai_res, "LOW"

    def flush_routine_buffer(self, session):
        if not session["routine_buffer"]:
            return
            
        count = len(session["routine_buffer"])
        sample_cmds = ", ".join(session["routine_buffer"][:3])
        session["routine_buffer"].clear()

        summary_msg = f"Session [{session['session_id']}]: User '{session['username']}' executed {count} routine commands. (Samples: {sample_cmds}...)"
        self.logger.log_event("INFO", "SESSION_SUMMARY", "ROUTINE_ACTIVITY", session["source_ip"], summary_msg)

    def end_session(self, username, source_ip, tty="pts/0"):
        session_key = (username, source_ip, tty)
        now = time.time()
        
        if session_key in self.active_sessions:
            session = self.active_sessions[session_key]
            self.flush_routine_buffer(session)
            
            try:
                with get_db_connection(self.db_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE user_sessions SET logout_time = ?, status = 'ENDED' WHERE session_id = ?",
                        (now, session["session_id"]))
                    conn.commit()
            except Exception as e:
                print(f"[-] Session Close Error: {e}")

            msg = f"User '{username}' logged out. (IP: {source_ip} | Terminal: {tty})"
            self.logger.log_event("NOTICE", "SESSION_TRACKER", "USER_LOGOUT", source_ip, msg)
            print(f"[*] [SESSION CLOSED] {msg}")
            
            del self.active_sessions[session_key]

    def check_idle_session_timeouts(self):
        now = time.time()
        timeout_seconds = getattr(config, 'IDLE_SESSION_TIMEOUT_SECONDS', 900)
        
        sessions_to_kick = []
        for session_key, session in list(self.active_sessions.items()):
            idle_time = now - session["last_activity_time"]
            if idle_time >= timeout_seconds:
                sessions_to_kick.append((session_key, session, idle_time))

        for session_key, session, idle_time in sessions_to_kick:
            username = session["username"]
            source_ip = session["source_ip"]
            tty = session["tty"]
            idle_minutes = int(idle_time // 60)

            print(f"\n[!] [KICKED DUE TO INACTIVITY] User: {username} | Terminal: {tty} | Idle Duration: {idle_minutes} Minutes")

            try:
                if os.name != 'nt':
                    clean_tty = tty.replace("/dev/", "")
                    is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0)
                    kill_cmd = f"pkill -9 -t {clean_tty}" if is_root else f"sudo -n pkill -9 -t {clean_tty}"
                    subprocess.run(kill_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                else:
                    print(f"[*] [Windows Simulation] Session for user '{username}' on terminal {tty} terminated.")
            except Exception as e:
                print(f"[-] Session Termination Error ({tty}): {e}")

            try:
                with get_db_connection(self.db_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE user_sessions SET logout_time = ?, status = 'INACTIVE_TIMEOUT_KICKED' WHERE session_id = ?",
                        (now, session["session_id"]))
                    conn.commit()
            except Exception as e:
                print(f"[-] Session Timeout Database Update Error: {e}")

            kick_msg = f"User '{username}' automatically kicked out after {idle_minutes} minutes of inactivity (idle session timeout)."
            self.logger.log_event("WARNING", "SESSION_TRACKER", "IDLE_SESSION_KICKED", source_ip, kick_msg)

            del self.active_sessions[session_key]

    def start(self):
        print(f"[+] Session Inactivity Tracking Service Started (15-Min Threshold): {time.ctime()}")
        while True:
            try:
                self.check_idle_session_timeouts()
            except Exception as e:
                print(f"[-] Session Tracking Loop Error: {e}")
            time.sleep(10)
