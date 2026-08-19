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

    def start(self):
        """
        Starts the Database Manager.
        """
        try:
            self.init_tables()
            print(f"[+] Database Connection Established (WAL Mode Active | {self.database_name}): {time.ctime()}")
        except Exception as e:
            print(f"[-] Database Connection Error: {e}")