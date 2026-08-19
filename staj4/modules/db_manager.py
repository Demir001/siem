# -*- coding: utf-8 -*-
"""
==============================================================================
THREAD-SAFE DATABASE MANAGEMENT SUBSYSTEM (db_manager.py)
==============================================================================
This module manages SQLite connections using WAL (Write-Ahead Logging) mode,
15-second busy timeout retry mechanisms, and thread-safe connection pooling
to completely prevent database locking errors during high-concurrency event logging.
==============================================================================
"""

import os
import time
import sqlite3
import config

def get_db_connection(db_name="security_events.db", timeout=15.0):
    """
    Returns a thread-safe, WAL-enabled SQLite connection.
    """
    busy_timeout_ms = getattr(config, 'SQLITE_BUSY_TIMEOUT_MS', 15000)
    conn = sqlite3.connect(db_name, timeout=timeout, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms};")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception:
        pass
    return conn

class DataBaseManager:
    def __init__(self, database_name="security_events.db"):
        self.database_name = database_name
        self.init_tables()

    def init_tables(self):
        """
        Initializes required event logging tables in WAL mode.
        """
        try:
            with get_db_connection(self.database_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""CREATE TABLE IF NOT EXISTS log_db (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    user TEXT,
                    event TEXT,
                    time TEXT,
                    country TEXT
                )""")
                conn.commit()
        except Exception as e:
            print(f"[-] Database Initialization Error ({self.database_name}): {e}")

    def insert_data(self, ip, user, event):
        """
        Inserts event records enriched with GeoIP data (Thread-Safe).
        """
        country = "Unknown"
        try:
            if os.path.exists("GeoLite2-City.mmdb"):
                import geoip2.database
                reader = geoip2.database.Reader("GeoLite2-City.mmdb")
                response = reader.city(ip) if ip and ip != "None" else None
                if response and response.country:
                    country = response.country.name
        except Exception:
            country = "Unknown"

        data = (str(ip), str(user), str(event), time.ctime(), country)
        
        for attempt in range(3):
            try:
                with get_db_connection(self.database_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO log_db (ip, user, event, time, country) VALUES (?, ?, ?, ?, ?)", data)
                    conn.commit()
                break
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower() and attempt < 2:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                print(f"[-] Database Write Error: {e}")
                break
            except Exception as e:
                print(f"[-] Database Write Error: {e}")
                break

    def delete_data(self, record_id):
        """
        Deletes a record by ID (Thread-Safe).
        """
        try:
            with get_db_connection(self.database_name) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM log_db WHERE id = ?", (record_id,))
                conn.commit()
        except Exception as e:
            print(f"[-] Database Delete Error: {e}")

    def get_recent_logs(self, limit=50):
        """
        Retrieves the latest N log records (Thread-Safe).
        """
        try:
            with get_db_connection(self.database_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM log_db ORDER BY id DESC LIMIT ?", (limit,))
                return cursor.fetchall()
        except Exception as e:
            print(f"[-] Log Query Error: {e}")
            return []

    def get_logs_by_ip(self, ip):
        """
        Retrieves all log records for a specific IP (Thread-Safe).
        """
        try:
            with get_db_connection(self.database_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM log_db WHERE ip = ? ORDER BY id DESC", (ip,))
                return cursor.fetchall()
        except Exception as e:
            print(f"[-] IP Log Query Error: {e}")
            return []

    def purge_expired_records(self, retention_days=30):
        """
        Purges historical logs and closed user sessions older than retention_days (Default: 30 Days).
        Runs a WAL checkpoint to reclaim disk space.
        """
        cutoff_time = time.time() - (retention_days * 86400)
        cutoff_date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cutoff_time))
        try:
            with get_db_connection(self.database_name) as conn:
                cursor = conn.cursor()
                cursor.execute("CREATE TABLE IF NOT EXISTS activity_logs (id INTEGER PRIMARY KEY, timestamp TEXT)")
                cursor.execute("CREATE TABLE IF NOT EXISTS session_activity_logs (id INTEGER PRIMARY KEY, timestamp TEXT)")
                cursor.execute("CREATE TABLE IF NOT EXISTS user_sessions (session_id TEXT PRIMARY KEY, logout_time REAL)")
                cursor.execute("CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, expires_at REAL)")
                
                cursor.execute("DELETE FROM activity_logs WHERE timestamp < ?", (cutoff_date_str,))
                cursor.execute("DELETE FROM session_activity_logs WHERE timestamp < ?", (cutoff_date_str,))
                cursor.execute("DELETE FROM user_sessions WHERE logout_time > 0 AND logout_time < ?", (cutoff_time,))
                cursor.execute("DELETE FROM banned_ips WHERE is_active = 0 AND unban_at > 0 AND unban_at < ?", (time.time() - 86400,))
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except Exception as e:
            print(f"[-] Database Retention Purge Error: {e}")

    def start(self):
        """
        Starts the Database Manager and cleans expired historical records.
        """
        try:
            self.init_tables()
            self.purge_expired_records(retention_days=getattr(config, 'LOG_RETENTION_DAYS', 30))
            print(f"[+] Database Connection Established (WAL Mode Active | {self.database_name}): {time.ctime()}")
        except Exception as e:
            print(f"[-] Database Connection Error: {e}")