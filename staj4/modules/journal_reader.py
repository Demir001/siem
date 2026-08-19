# -*- coding: utf-8 -*-
"""
==============================================================================
SYSTEMD-JOURNALD STREAMING LOG READER (journal_reader.py)
==============================================================================
This module streams real-time journal events directly from systemd-journald
via 'journalctl -f' on modern Linux systems lacking /var/log/syslog or rsyslog.
==============================================================================
"""

import os
import time
import subprocess
import shutil

class JournalReader:
    def __init__(self, callback=None):
        self.callback = callback
        self.process = None
        self.is_running = False

    @staticmethod
    def is_available() -> bool:
        """
        Checks whether 'journalctl' is available in the host environment.
        """
        if os.name == 'nt':
            return False
        return shutil.which("journalctl") is not None

    def start_streaming(self):
        """
        Streams events in real time using 'journalctl -f -n 0 -o short-iso'.
        """
        if not self.is_available():
            return

        print("[+] Starting Live Systemd-Journald Streaming (Journalctl Subprocess)...")
        self.is_running = True

        cmd = ["journalctl", "-f", "-n", "0", "-o", "short-iso"]
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                bufsize=1
            )

            for line in iter(self.process.stdout.readline, ''):
                if not self.is_running:
                    break
                cleaned = line.strip()
                if cleaned and self.callback:
                    self.callback(cleaned, source_file="systemd-journald")

        except Exception as e:
            print(f"[-] Journald Reader Stream Error: {e}")
        finally:
            self.stop()

    def stop(self):
        """
        Stops the journal reader process cleanly.
        """
        self.is_running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None
