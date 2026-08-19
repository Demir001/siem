# -*- coding: utf-8 -*-
"""
==============================================================================
LOG FILE SIZE CONTROL & AUTOMATIC ZIP ARCHIVER (file_control_zip.py)
==============================================================================
This module monitors application log sizes and automatically compresses/archives
oversized log files to prevent storage exhaustion.
==============================================================================
"""

import os
import zipfile
import time
import config

class FileManager:
    def __init__(self, file_path=None):
        self.file_path = file_path or getattr(config, 'LINUX_APP_LOG_PATH', 'app.log')

    def check_file_size(self):
        """
        Compresses and rotates log files when exceeding FILE_SIZE_THRESHOLD.
        """
        if not os.path.exists(self.file_path):
            return

        file_size_bytes = os.path.getsize(self.file_path)
        file_size_mb = file_size_bytes / (1024 * 1024)
        threshold_mb = getattr(config, 'FILE_SIZE_THRESHOLD', 5)

        if file_size_mb >= threshold_mb:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            archive_name = f"{self.file_path}_{timestamp}.zip"
            
            print(f"[!] Log file '{self.file_path}' reached {file_size_mb:.2f} MB. Compressing to '{archive_name}'...")

            try:
                with zipfile.ZipFile(archive_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    zipf.write(self.file_path, os.path.basename(self.file_path))

                with open(self.file_path, 'w', encoding='utf-8') as f:
                    f.truncate(0)

                print(f"[+] Log file successfully archived: {archive_name}")
            except Exception as e:
                print(f"[-] Log Archival Error: {e}")

    def start(self):
        """
        Starts the log archival watchdog loop.
        """
        print(f"[+] Log File Archival Manager Started: {time.ctime()}")
        while True:
            try:
                self.check_file_size()
            except Exception as e:
                print(f"[-] File Archival Error: {e}")
            time.sleep(30)