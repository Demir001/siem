# -*- coding: utf-8 -*-
"""
==============================================================================
EMAIL ALERT NOTIFICATION SERVICE (alert.py)
==============================================================================
This module dispatches high-priority email alerts asynchronously via SMTP.
==============================================================================
"""

import smtplib
import threading
import config

class Alert:
    def __init__(self):
        self.smtp_server = getattr(config, 'SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = getattr(config, 'SMTP_PORT', 587)
        self.sender_email = getattr(config, 'SENDER_EMAIL', 'your_email@gmail.com')
        self.receiver_email = getattr(config, 'RECEIVER_EMAIL', 'admin@example.com')
        self.email_password = getattr(config, 'EMAIL_PASSWORD', 'your_password')

    def is_enabled(self) -> bool:
        """
        Checks whether SMTP alerts are enabled in config.py.
        """
        return getattr(config, 'ENABLE_EMAIL_ALERTS', False) and getattr(config, 'SMTP_ENABLED', False)

    def _async_send_worker(self, message: str):
        """
        Transmits email alert asynchronously with a 5-second connection timeout.
        """
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=5.0) as server:
                server.starttls()
                server.login(self.sender_email, self.email_password)
                server.sendmail(self.sender_email, self.receiver_email, message)
                print(f"[+] Alert Email Dispatched to {self.receiver_email}")
        except Exception as e:
            print(f"[-] Email Dispatch Error: {e}")

    def send_alert(self, message: str):
        """
        Spawns a non-blocking background thread to dispatch the email alert.
        """
        if not self.is_enabled():
            return

        threading.Thread(target=self._async_send_worker, args=(message,), daemon=True).start()