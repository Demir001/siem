# -*- coding: utf-8 -*-
"""
==============================================================================
DISTRIBUTED BOTNET & SUBNET / CIDR DEFENSE SHIELD (subnet_shield.py)
==============================================================================
This module correlates attacks across entire subnet blocks (/24 for IPv4 and
/64 for IPv6) to detect and block distributed, slow-roll botnet attacks where
multiple rotating IPs from the same network segment coordinate attacks.
==============================================================================
"""

import time
import ipaddress
from collections import defaultdict, deque
import config

class SubnetShield:
    def __init__(self, logger=None):
        self.logger = logger
        # subnet_cidr -> deque of {'time': ts, 'ip': ip, 'score': score, 'event': event}
        self.subnet_history = defaultdict(deque)

    @staticmethod
    def get_subnet_prefix(ip: str) -> str:
        """
        Calculates the canonical /24 (IPv4) or /64 (IPv6) network prefix.
        Returns None for local loopback and configured internal LAN subnets.
        """
        if not ip or ip in ["LOCAL_SYSTEM", "localhost", "127.0.0.1", "::1"]:
            return None

        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_loopback:
                return None

            # Skip configured internal LAN subnets
            internal_subnets = getattr(config, 'INTERNAL_SUBNETS', ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "fc00::/7", "fe80::/10"])
            for subnet_str in internal_subnets:
                try:
                    if ip_obj in ipaddress.ip_network(subnet_str):
                        return None
                except TypeError:
                    pass

            if ip_obj.version == 4:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                return str(net)
            elif ip_obj.version == 6:
                net = ipaddress.ip_network(f"{ip}/64", strict=False)
                return str(net)
        except (ValueError, TypeError):
            pass

        return None

    def record_threat(self, ip: str, score: float, event: str, event_time: float = None) -> tuple[bool, str, float, int]:
        """
        Records an attack event within the subnet sliding window and determines
        whether the entire CIDR block should be banned.
        Returns: (should_ban_subnet, subnet_cidr, cumulative_risk, distinct_ip_count)
        """
        if not getattr(config, 'ENABLE_SUBNET_SHIELD', True):
            return False, None, 0.0, 0

        subnet = self.get_subnet_prefix(ip)
        if not subnet:
            return False, None, 0.0, 0

        now = event_time or time.time()
        window = getattr(config, 'TIME_WINDOW', 600)
        history = self.subnet_history[subnet]

        # 1. Evict entries outside the sliding window
        while history and (now - history[0]['time'] > window):
            history.popleft()

        # 2. Append new threat record
        history.append({
            'time': now,
            'ip': ip,
            'score': score,
            'event': event
        })

        # 3. Calculate subnet metrics
        distinct_ips = {e['ip'] for e in history}
        distinct_count = len(distinct_ips)
        total_risk = sum(e['score'] for e in history)

        distinct_threshold = getattr(config, 'SUBNET_DISTINCT_IPS_THRESHOLD', 3)
        risk_threshold = getattr(config, 'SUBNET_RISK_THRESHOLD', 75.0)

        # 4. Check if distributed botnet threshold is breached
        if distinct_count >= distinct_threshold or total_risk >= risk_threshold:
            return True, subnet, total_risk, distinct_count

        return False, subnet, total_risk, distinct_count

    def clear_subnet(self, subnet: str):
        """
        Clears subnet history after an enforced CIDR ban.
        """
        if subnet in self.subnet_history:
            self.subnet_history[subnet].clear()
