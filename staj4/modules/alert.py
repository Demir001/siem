# -*- coding: utf-8 -*-
"""
==============================================================================
EMAIL ALERT NOTIFICATION SERVICE (alert.py)
==============================================================================
This module dispatches high-priority email alerts via SMTP when enabled.
==============================================================================
"""

import smtplib
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

    def send_alert(self, message):
        """
        Transmits an alert message via SMTP.
        """
        if not self.is_enabled():
            return

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.email_password)
                server.sendmail(self.sender_email, self.receiver_email, message)
                print(f"[+] Alert Email Dispatched to {self.receiver_email}")
        except Exception as e:
            print(f"[-] Email Dispatch Error: {e}")