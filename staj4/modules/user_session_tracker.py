# -*- coding: utf-8 -*-
"""
==============================================================================
MULTI-SESSION, IDLE INACTIVITY & ACTIVE COMMAND TRACKING ENGINE
(user_session_tracker.py)
==============================================================================
This module provides:
1. REAL-TIME NON-SUDO & SUDO TERMINAL PROCESS INTERCEPT:
   - Continuously samples active processes on terminal TTYs to analyze regular
     user keystrokes and shell commands without requiring 'sudo'.
2. MULTI-SESSION & IDLE TIMEOUT AUTO-KICK (15-Minute Threshold):
   - Monitors active terminal sessions and cleanly terminates idle sessions.
3. LOW-NOISE COMMAND BUFFERING:
   - Aggregates routine developer commands into periodic summaries to reduce noise.
4. HOSTILE INTRUSION INTERCEPT:
   - Detects destructive commands, reverse shells, or privilege escalation and
     immediately terminates the user's terminal session while applying an IP ban.
5. THREAD-SAFE SQLITE CONCURRENCY (WAL Mode & Busy Timeout).
6. ZOMBIE & STALE SESSION CLEANUP:
   - Automatically resolves stale sessions on boot or upon new login on the same TTY.
==============================================================================
"""

import os
import time
import psutil
import subprocess
import threading
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
        self.seen_process_pids = set()
        self.is_running = True
        self.lock = threading.RLock()
        
        self.init_db()
        self.cleanup_stale_sessions_on_boot()
        self._install_linux_shell_audit_hook()

    def _install_linux_shell_audit_hook(self):
        """
        Installs system-wide non-sudo and sudo interactive shell audit hook in /etc/profile.d and /etc/bash.bashrc.
        Ensures non-sudo commands (e.g. non-root 'cat /etc/shadow') are logged to journald/syslog immediately.
        """
        if os.name != 'nt':
            try:
                is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0)
                if is_root:
                    hook_content = (
                        '# SIEM Real-Time Interactive Shell Command Audit Hook\n'
                        'export PROMPT_COMMAND=\'logger -p auth.notice -t siem_audit "user=$USER tty=$(tty 2>/dev/null | sed "s#/dev/##") cmd=\\"$(history 1 | sed "s/^[ ]*[0-9]*[ ]*//")\\""\' 2>/dev/null\n'
                    )
                    # 1. Write to /etc/profile.d/siem_audit.sh
                    hook_path = "/etc/profile.d/siem_audit.sh"
                    with open(hook_path, "w", encoding="utf-8") as f:
                        f.write(hook_content)
                    os.chmod(hook_path, 0o644)

                    # 2. Append to /etc/bash.bashrc so interactive subshells always load it
                    bashrc_path = "/etc/bash.bashrc"
                    if os.path.exists(bashrc_path):
                        with open(bashrc_path, "r", encoding="utf-8", errors="ignore") as f:
                            current_rc = f.read()
                        if "siem_audit" not in current_rc:
                            with open(bashrc_path, "a", encoding="utf-8") as f:
                                f.write("\n" + hook_content + "\n")

                    # 3. Kernel Auditd watches on sensitive files if auditctl exists
                    subprocess.run("auditctl -w /etc/shadow -p r -k siem_shadow 2>/dev/null", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run("auditctl -w /etc/sudoers -p r -k siem_sudoers 2>/dev/null", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

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
        Preserves authentic remote IP when user escalates privileges via sudo su.
        """
        now = time.time()
        actual_ip = source_ip

        with self.lock:
            # If source_ip is LOCAL_SYSTEM, preserve existing authentic remote client IP on this TTY
            if source_ip in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                for (u, s_ip, t), sess in list(self.active_sessions.items()):
                    if t == tty and s_ip not in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                        actual_ip = s_ip
                        break

            session_id = f"SESS_{username}_{actual_ip}_{tty.replace('/', '_')}_{int(now * 1000)}"
            session_key = (username, actual_ip, tty)

            # Close/replace existing session on this TTY device
            for key in list(self.active_sessions.keys()):
                if key[2] == tty and key != session_key:
                    del self.active_sessions[key]
                    
            session_data = {
                "session_id": session_id,
                "username": username,
                "source_ip": actual_ip,
                "tty": tty,
                "login_time": now,
                "last_activity_time": now,
                "command_count": 0,
                "cumulative_risk": 0,
                "routine_buffer": []
            }
            self.active_sessions[session_key] = session_data

        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""INSERT INTO user_sessions 
                    (session_id, username, source_ip, tty_device, login_time, last_activity_time, total_commands, status)
                    VALUES (?, ?, ?, ?, ?, ?, 0, 'ACTIVE')""",
                    (session_id, username, actual_ip, tty, now, now))
                conn.commit()
        except Exception as e:
            print(f"[-] Session Database Write Error: {e}")

        msg = f"User '{username}' logged in successfully. (IP: {actual_ip} | Terminal: {tty})"
        self.logger.log_event("NOTICE", "SESSION_TRACKER", "USER_LOGIN", actual_ip, msg)
        print(f"[+] [SESSION STARTED] {msg}")

    def record_command(self, username, source_ip, command, tty="pts/0"):
        """
        Analyzes command execution in user session and terminates hostile sessions.
        """
        now = time.time()
        
        with self.lock:
            # 1. Resolve authentic remote client IP from active session on matching TTY
            actual_ip = source_ip
            actual_user = username
            actual_key = (username, source_ip, tty)

            if source_ip in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                clean_tty = tty.replace("/dev/", "")
                # A. First check matching TTY in active_sessions
                for (u, s_ip, t), sess in self.active_sessions.items():
                    clean_t = t.replace("/dev/", "")
                    if (clean_t == clean_tty or clean_tty in clean_t or clean_t in clean_tty) and s_ip not in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                        actual_ip = s_ip
                        actual_user = u
                        actual_key = (u, s_ip, t)
                        break
                
                # B. If not found by TTY, query psutil.users() live from Linux utmp!
                if actual_ip in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                    try:
                        for u in psutil.users():
                            u_term = (u.terminal or "").replace("/dev/", "")
                            u_host = u.host or ""
                            if (u_term == clean_tty or u.name == username) and u_host and u_host not in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                                actual_ip = u_host
                                actual_user = u.name
                                actual_key = (actual_user, actual_ip, tty)
                                break
                    except Exception:
                        pass

                # C. If still not found, check matching username in active_sessions
                if actual_ip in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                    for (u, s_ip, t), sess in self.active_sessions.items():
                        if u == username and s_ip not in ["LOCAL_SYSTEM", "127.0.0.1", "localhost", "::1"]:
                            actual_ip = s_ip
                            actual_user = u
                            actual_key = (u, s_ip, t)
                            break

            if actual_key not in self.active_sessions:
                self.start_session(actual_user, actual_ip, tty)
                actual_key = (actual_user, actual_ip, tty)
                
            session = self.active_sessions[actual_key]
            session["last_activity_time"] = now
            session["command_count"] += 1

            # 2. Analyze command context & AI classification
            category, risk_score, is_anomaly, summary, ai_res, criticality = self.analyze_command_context(actual_user, command)

            # 3. Buffer low-risk routine commands
            if not is_anomaly and risk_score == 0:
                session["routine_buffer"].append(command)
                if len(session["routine_buffer"]) >= 10:
                    self.flush_routine_buffer(session)
                return

            # 4. Log suspicious/hostile command event
            session["cumulative_risk"] += risk_score
            mitre_id = ai_res.get("mitre_id", "N/A")
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            try:
                with get_db_connection(self.db_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""INSERT INTO session_activity_logs 
                        (session_id, username, source_ip, timestamp, command, category, risk_score, summary, mitre_id, criticality)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (session["session_id"], actual_user, actual_ip, timestamp, command, category, risk_score, summary, mitre_id, criticality))
                    
                    cursor.execute("UPDATE user_sessions SET total_commands = ?, last_activity_time = ? WHERE session_id = ?",
                        (session["command_count"], now, session["session_id"]))
                    conn.commit()
            except Exception as e:
                print(f"[-] Command Logging Error: {e}")

            level = "CRITICAL" if criticality == "CRITICAL" else ("WARNING" if criticality == "HIGH" else "NOTICE")
            log_msg = f"Session [{session['session_id']}]: User '{actual_user}' executed '{command}'. (Summary: {summary})"
            self.logger.log_event(level, "USER_ACTIVITY", f"COMMAND_{category}", actual_ip, log_msg, ai_info=ai_res)

            # Immediate hostile action intercept & session kill
            if risk_score >= 70 or session["cumulative_risk"] >= 50:
                # 1. Terminate hostile interactive terminal session and wipe screen buffer immediately
                if os.name != 'nt':
                    try:
                        clean_tty = tty.replace("/dev/", "")
                        # Instantly wipe screen and scrollback buffer to prevent attacker viewing leaked output
                        try:
                            with open(f"/dev/{clean_tty}", "w") as tty_out:
                                tty_out.write("\033[2J\033[H\033[3J\r\n\r\n[!] ACCESS DENIED: SECURITY VIOLATION INTERCEPTED. TERMINAL KILLED.\r\n\r\n")
                                tty_out.flush()
                        except Exception:
                            pass

                        is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0)
                        kill_cmd = f"pkill -9 -t {clean_tty}" if is_root else f"sudo -n pkill -9 -t {clean_tty}"
                        subprocess.run(kill_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                    except Exception:
                        pass

                # 2. Ban IP on firewall if not protected
                if not self.ban_manager.is_banned(actual_ip) and not self.ban_manager.is_protected_ip(actual_ip):
                    ban_reason = f"Session Hostile Activity: '{command}' ({criticality} Level - Risk: {session['cumulative_risk']})"
                    self.ban_manager.ban_ip(ip=actual_ip, criticality=criticality, reason=ban_reason)
                
                session["cumulative_risk"] = 0

    def analyze_command_context(self, username, command):
        """
        Contextually inspects commands across Regex rules, AI Engine, and MITRE ATT&CK vectors.
        """
        from modules.canonicalizer import PayloadCanonicalizer
        cmd = PayloadCanonicalizer.canonicalize(command).strip()
        cmd_lower = cmd.lower()
        
        # 1. SIEM internal operations & maintenance commands (Bypasses AI to eliminate recursive loops)
        if any(w in cmd_lower for w in ["ufw ", "iptables ", "ip6tables ", "pkill ", "ss -k", "conntrack -d", "main.py", "manage.py"]):
            return "ROUTINE_COMMAND", 0, False, "System Administration / SIEM Maintenance", {}, "LOW"

        ai_res = self.ai_engine.analyze(cmd)
        
        # 2. High-Severity Deterministic Hostile Signatures
        if any(w in cmd_lower for w in ["rm -rf /", "shred", "mkfs", "dd if=/dev/zero", "dd if=/dev/urandom of=/dev/sda"]):
            return "DESTRUCTIVE_MUTATION", 90, True, "Dangerous Destructive System Data Wipe Attempt", ai_res, "CRITICAL"

        if ("curl" in cmd_lower or "wget" in cmd_lower) and ("| bash" in cmd_lower or "| sh" in cmd_lower or "| perl" in cmd_lower):
            return "UNVERIFIED_SCRIPT_PIPE", 80, True, "Unverified Remote Web Script Piped Directly into Shell", ai_res, "HIGH"

        is_shadow_read = any(s in cmd_lower for s in ["/etc/shadow", "etc/shadow", "s?ad*w", "sha\\"]) and any(b in cmd_lower for b in ["cat", "head", "tail", "less", "more", "awk", "sed", "nl", "xxd", "hexdump", "strings", "grep", "cut", "python", "perl", "open(", "find", "c?t"])
        if is_shadow_read:
            return "SENSITIVE_FILE_READ", 75, True, "Unauthorized Sensitive Credential File Read (/etc/shadow)", ai_res, "CRITICAL"
            
        if any(w in cmd_lower for w in ["chmod +s /bin/bash", "chmod 4755", "chmod u+s /bin", "pkexec /bin/sh", "--checkpoint-action=exec", "checkpoint-action", "apt::update::pre-invoke", "nopasswd", "sudoers.d"]):
            return "PRIVILEGE_ESCALATION", 75, True, "Privilege Elevation / GTFOBins Backdoor Manipulation", ai_res, "CRITICAL"

        if any(w in cmd_lower for w in ["nc -e", "ncat -e", "/dev/tcp/", "socat exec", "mkfifo", "mknod"]):
            return "REVERSE_SHELL_ATTEMPT", 85, True, "Outbound Reverse Shell Connection Attempt", ai_res, "CRITICAL"

        if ("python" in cmd_lower or "perl" in cmd_lower or "php" in cmd_lower) and "-c " in cmd_lower and any(k in cmd_lower for k in ["socket", "pty", "subprocess", "exec", "b64decode", "zlib"]):
            return "INLINE_INTERPRETER_EXEC", 75, True, "Inline Command-Line Code String Injection Execution", ai_res, "CRITICAL"

        # 3. AI Security Engine Anomaly / Attack Classification
        if ai_res.get("is_attack"):
            verdict = ai_res.get("verdict", "ATTACK")
            title = ai_res.get("incident_title", "Cyber Threat Detected")
            cat = ai_res.get("incident_category", "AI_ANOMALY")
            urgency = ai_res.get("urgency", "HIGH")
            score = 75 if urgency == "CRITICAL" else 60
            return f"AI_{cat}", score, True, f"AI {verdict}: {title}", ai_res, urgency

        return "ROUTINE_COMMAND", 0, False, "Routine Normal User / Developer Activity", ai_res, "LOW"

    def sync_active_os_sessions(self):
        """
        Queries the OS for all active interactive terminal sessions (pts/0, pts/1, pts/2...)
        and maps them dynamically to authentic client IP addresses.
        """
        try:
            for u in psutil.users():
                term = u.terminal or "pts/0"
                host = u.host or "LOCAL_SYSTEM"
                username = u.name or "unknown"
                clean_term = term.replace("/dev/", "")
                
                with self.lock:
                    session_key = (username, host, clean_term)
                    if session_key not in self.active_sessions:
                        self.start_session(username, host, clean_term)
        except Exception:
            pass

    def sample_active_terminal_processes(self):
        """
        Samples active processes executing across terminal TTYs to catch non-sudo commands.
        Dynamically resolves parent SSH socket connections when sessions are unknown.
        """
        self.sync_active_os_sessions()

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    pid = proc.info.get('pid')
                    if not pid or pid in self.seen_process_pids:
                        continue

                    cmdline_list = proc.info.get('cmdline')
                    if not cmdline_list:
                        continue

                    p_name = (proc.info.get('name') or '').lower()
                    if p_name in ["sshd", "systemd", "login", "init", "ps", "sleep", "journalctl", "main.py"]:
                        continue

                    cmdline_str = " ".join(cmdline_list).strip()
                    if not cmdline_str:
                        continue

                    # Filter out interactive user login shells (unless running inline scripts via -c / -e)
                    cmd_tokens = [t.lower() for t in cmdline_list]
                    base_binary = os.path.basename(cmdline_list[0]).lower().lstrip("-")
                    if any(base_binary.startswith(s) for s in ["bash", "sh", "zsh", "dash", "csh", "tcsh", "fish", "login"]):
                        if not any(flag in cmd_tokens for flag in ["-c", "-e", "-i>&", "/dev/tcp"]):
                            continue

                    # Extract TTY device dynamically or inherit from parent process tree
                    tty = None
                    try:
                        if hasattr(proc, 'terminal'):
                            tty = proc.terminal()
                    except Exception:
                        pass

                    if not tty:
                        try:
                            parent_proc = proc.parent()
                            for _ in range(4):
                                if not parent_proc:
                                    break
                                if hasattr(parent_proc, 'terminal') and parent_proc.terminal():
                                    tty = parent_proc.terminal()
                                    break
                                parent_proc = parent_proc.parent()
                        except Exception:
                            pass

                    clean_tty = (tty or "pts/0").replace("/dev/", "")

                    # 1. Match against known active sessions on this TTY
                    matched_session = None
                    with self.lock:
                        for (username, source_ip, session_tty), session in list(self.active_sessions.items()):
                            clean_session_tty = session_tty.replace("/dev/", "")
                            if clean_tty == clean_session_tty or clean_tty in clean_session_tty or clean_session_tty in clean_tty:
                                matched_session = (username, source_ip, session_tty)
                                break

                    # 2. If session is not pre-registered, resolve authentic remote client IP from SSH process tree
                    if not matched_session:
                        user_name = proc.info.get('username') or 'unknown'
                        source_ip = 'LOCAL_SYSTEM'
                        try:
                            curr_proc = proc
                            for _ in range(5):
                                if not curr_proc:
                                    break
                                parent = curr_proc.parent()
                                if parent and "sshd" in parent.name().lower():
                                    for conn in parent.connections(kind='inet'):
                                        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                                            source_ip = conn.raddr.ip
                                            break
                                    break
                                curr_proc = parent
                        except Exception:
                            pass
                        matched_session = (user_name, source_ip, clean_tty)

                    # 3. Process & analyze non-sudo command
                    target_user, target_ip, target_tty = matched_session
                    self.seen_process_pids.add(pid)
                    if len(self.seen_process_pids) > 10000:
                        self.seen_process_pids.clear()

                    self.record_command(username=target_user, source_ip=target_ip, command=cmdline_str, tty=target_tty)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass

    def flush_routine_buffer(self, session):
        """
        Flushes and summarizes buffered routine commands into a single log entry.
        """
        if not session["routine_buffer"]:
            return
            
        count = len(session["routine_buffer"])
        sample_cmds = ", ".join(session["routine_buffer"][:3])
        session["routine_buffer"].clear()

        summary_msg = f"Session [{session['session_id']}]: User '{session['username']}' executed {count} routine commands. (Samples: {sample_cmds}...)"
        self.logger.log_event("INFO", "SESSION_SUMMARY", "ROUTINE_ACTIVITY", session["source_ip"], summary_msg)

    def end_session(self, username, source_ip, tty="pts/0"):
        """
        Closes user session and flushes pending routine command buffers.
        """
        session_key = (username, source_ip, tty)
        now = time.time()
        
        with self.lock:
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
        """
        Kicks sessions exceeding IDLE_SESSION_TIMEOUT_SECONDS of inactivity.
        """
        now = time.time()
        timeout_seconds = getattr(config, 'IDLE_SESSION_TIMEOUT_SECONDS', 900)
        
        sessions_to_kick = []
        with self.lock:
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

            with self.lock:
                if session_key in self.active_sessions:
                    del self.active_sessions[session_key]

    def start(self):
        """
        Starts the continuous terminal process sampling and session timeout service.
        """
        print(f"[+] Terminal Process & Session Activity Tracker Active: {time.ctime()}")
        last_timeout_check = 0
        while self.is_running:
            try:
                # 1. High-speed process sampling (captures non-sudo terminal commands)
                self.sample_active_terminal_processes()

                # 2. Periodic idle timeout check (every 10 seconds)
                now = time.time()
                if now - last_timeout_check >= 10:
                    self.check_idle_session_timeouts()
                    last_timeout_check = now
            except Exception as e:
                print(f"[-] Session Tracking Loop Error: {e}")
            time.sleep(0.05)
