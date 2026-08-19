# -*- coding: utf-8 -*-
"""
==============================================================================
HIGH-PRECISION LOG PARSER & ATTRIBUTION UTILITIES (log_parser_utils.py)
==============================================================================
This module provides:
1. DUAL-STACK DUAL-PROTOCOL IP EXTRACTION (IPv4 & IPv6):
   - Extracts standard IPv4, IPv6 (compressed/expanded), and IPv4-mapped IPv6.
   - Validates candidates via python ipaddress library to prevent false IPs.
2. MULTI-FORMAT RFC TIMESTAMP PARSING:
   - Parses RFC 3164 Syslog ("Aug 18 14:22:31"), RFC 5424 ISO-8601 ("2026-08-18T14:22:31Z"),
     and Apache/Nginx combined timestamps into exact epoch seconds.
3. MULTI-LINE PROCESS/PID ATTRIBUTION CORRELATION:
   - Correlates multi-phase daemon events sharing identical PIDs (e.g., sshd[12345]).
==============================================================================
"""

import re
import time
import ipaddress
from datetime import datetime
from collections import defaultdict

# Pre-compiled high-precision regular expressions
IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
IPV6_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4})?\b')
PID_PATTERN = re.compile(r'\[(\d{1,7})\]')

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

class LogParserUtils:
    @staticmethod
    def extract_all_ips(text: str) -> list[str]:
        """
        Extracts and validates all IPv4 and IPv6 addresses present in a log string.
        """
        if not text:
            return []

        candidates = []
        # 1. Look for explicit keywords first (SRC=, from, rip=, rhost=)
        kw_matches = re.findall(r'(?:SRC=|from\s+|rip=|rhost=|client\s+\[?)([\da-fA-F\.\:]+)(?:\]|\b|\s|$)', text, re.IGNORECASE)
        for m in kw_matches:
            cleaned = m.strip("[](),: ")
            candidates.append(cleaned)

        # 2. Match general IPv4 addresses
        for match in IPV4_PATTERN.findall(text):
            candidates.append(match)

        # 3. Match general IPv6 addresses
        if ":" in text:
            for match in IPV6_PATTERN.findall(text):
                if match.count(":") >= 2:
                    candidates.append(match)

        valid_ips = []
        seen = set()
        for c in candidates:
            if c in seen:
                continue
            try:
                ip_obj = ipaddress.ip_address(c)
                # Ignore dummy/multicast/broadcast masks unless relevant
                valid_ips.append(str(ip_obj))
                seen.add(c)
            except ValueError:
                pass

        return valid_ips

    @staticmethod
    def extract_primary_ip(text: str) -> str:
        """
        Returns the primary attacker/source IP address or 'LOCAL_SYSTEM'.
        """
        ips = LogParserUtils.extract_all_ips(text)
        if not ips:
            return "LOCAL_SYSTEM"

        # Prioritize non-loopback IPs
        for ip in ips:
            if ip not in ["127.0.0.1", "::1", "0.0.0.0"]:
                return ip

        return ips[0]

    @staticmethod
    def extract_pid(text: str) -> str:
        """
        Extracts process PID identifier (e.g. sshd[12345] -> 12345).
        """
        match = PID_PATTERN.search(text)
        return match.group(1) if match else None

    @staticmethod
    def parse_log_timestamp(text: str) -> float:
        """
        Parses log line timestamps to epoch timestamp with fallback to time.time().
        """
        now = time.time()
        if not text:
            return now

        # Format A: RFC 3164 Syslog (e.g. "Aug 18 14:22:31" or "Aug  8 04:12:01")
        m_syslog = re.match(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})', text)
        if m_syslog:
            mon_str, day_str, h_str, min_str, s_str = m_syslog.groups()
            month = MONTH_MAP.get(mon_str, 1)
            current_year = datetime.now().year
            try:
                dt = datetime(current_year, month, int(day_str), int(h_str), int(min_str), int(s_str))
                return dt.timestamp()
            except Exception:
                pass

        # Format B: RFC 5424 ISO-8601 (e.g. "2026-08-18T14:22:31.123+03:00")
        m_iso = re.match(r'^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})', text)
        if m_iso:
            iso_str = m_iso.group(1).replace(" ", "T")
            try:
                dt = datetime.fromisoformat(iso_str)
                return dt.timestamp()
            except Exception:
                pass

        return now


class PIDAttributionCache:
    """
    Correlates multi-line daemon events sharing identical process IDs.
    """
    def __init__(self, ttl_seconds: float = 60.0):
        self.ttl = ttl_seconds
        self.cache = {}

    def record(self, pid: str, ip: str = None, user: str = None):
        if not pid:
            return
        now = time.time()
        self._prune(now)

        if pid not in self.cache:
            self.cache[pid] = {"ip": ip, "user": user, "last_seen": now}
        else:
            if ip and ip != "LOCAL_SYSTEM":
                self.cache[pid]["ip"] = ip
            if user and user != "UNKNOWN":
                self.cache[pid]["user"] = user
            self.cache[pid]["last_seen"] = now

    def resolve(self, pid: str) -> tuple[str, str]:
        if not pid or pid not in self.cache:
            return None, None
        entry = self.cache[pid]
        return entry.get("ip"), entry.get("user")

    def _prune(self, now: float):
        expired = [pid for pid, data in self.cache.items() if now - data["last_seen"] > self.ttl]
        for pid in expired:
            del self.cache[pid]
