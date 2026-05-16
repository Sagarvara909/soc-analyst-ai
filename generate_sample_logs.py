"""
generate_sample_logs.py
-----------------------
Generates realistic sample log files for testing the parser.
Run once: python generate_sample_logs.py
Creates 4 files in the logs/ folder.
"""

import random
import json
from datetime import datetime, timedelta
import os

os.makedirs("logs", exist_ok=True)

# ── helpers ──────────────────────────────────────────────────────────
def rand_ip():
    return f"{random.randint(10,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def attacker_ip():
    return random.choice(["195.178.55.22", "77.88.44.3", "185.220.101.47", "91.108.4.55"])

def internal_ip():
    return f"10.0.0.{random.randint(2,200)}"

def ts(base, offset_seconds=0):
    t = base + timedelta(seconds=offset_seconds)
    return t.strftime("%b %d %H:%M:%S").replace(" 0", "  ")  # syslog format

def ts_apache(base, offset_seconds=0):
    t = base + timedelta(seconds=offset_seconds)
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")

def ts_win(base, offset_seconds=0):
    t = base + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%d %H:%M:%S")

def ts_iso(base, offset_seconds=0):
    t = base + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")

base = datetime(2026, 1, 15, 8, 0, 0)

# ── 1. SYSLOG ────────────────────────────────────────────────────────
syslog_lines = []
attk = attacker_ip()
for i in range(120):
    t = ts(base, i * 3)
    host = random.choice(["webserver", "db-01", "gateway", "vpn-gw"])
    if i < 60:   # brute-force burst
        user = random.choice(["admin", "root", "deploy", "ubuntu", "postgres"])
        syslog_lines.append(f"{t} {host} sshd[{1000+i}]: Failed password for invalid user {user} from {attk} port {40000+i} ssh2")
    elif i < 80:  # successful login after brute
        syslog_lines.append(f"{t} {host} sshd[{2000+i}]: Accepted password for root from {attk} port {50000+i} ssh2")
    elif i < 100: # lateral movement
        syslog_lines.append(f"{t} {host} sudo[{3000+i}]: authentication failure for user deploy from {internal_ip()}")
    else:         # normal traffic
        syslog_lines.append(f"{t} {host} cron[{4000+i}]: (root) CMD (/usr/bin/backup.sh)")

with open("logs/syslog_sample.log", "w") as f:
    f.write("\n".join(syslog_lines))
print(f"✅ Created logs/syslog_sample.log ({len(syslog_lines)} lines)")


# ── 2. APACHE ────────────────────────────────────────────────────────
apache_lines = []
scan_ips = [attacker_ip() for _ in range(3)]
paths = ["/", "/admin", "/wp-login.php", "/api/login", "/phpmyadmin",
         "/index.html", "/about", "/contact", "/static/main.js", "/.env"]
methods = ["GET", "POST", "GET", "GET", "POST"]

for i in range(150):
    t = ts_apache(base, i * 2)
    ip = random.choice(scan_ips) if i % 5 == 0 else rand_ip()
    path = random.choice(paths)
    method = random.choice(methods)
    # Suspicious paths get 403 or 200 on login
    if path in ["/admin", "/phpmyadmin", "/.env"]:
        status = random.choice(["403", "404"])
    elif path == "/wp-login.php" and method == "POST":
        status = random.choice(["200", "302", "401"])
    else:
        status = random.choice(["200", "200", "200", "404", "500"])
    size = random.randint(100, 50000)
    apache_lines.append(f'{ip} - - [{t}] "{method} {path} HTTP/1.1" {status} {size}')

with open("logs/apache_access.log", "w") as f:
    f.write("\n".join(apache_lines))
print(f"✅ Created logs/apache_access.log ({len(apache_lines)} lines)")


# ── 3. WINDOWS EVENT ─────────────────────────────────────────────────
win_events = [
    ("4625", "CORP\\jsmith",   "An account failed to log on"),
    ("4625", "CORP\\admin",    "An account failed to log on"),
    ("4688", "SYSTEM",         "New process created: cmd.exe parent: word.exe"),
    ("4688", "CORP\\jsmith",   "New process created: powershell.exe -enc SQBFAFgA"),
    ("4698", "CORP\\admin",    "A scheduled task was created: svchost_update"),
    ("4720", "CORP\\IT-Admin", "A user account was created: backdoor_svc"),
    ("4728", "CORP\\IT-Admin", "A member was added to a security-enabled global group: Domain Admins"),
    ("4776", "CORP\\jsmith",   "The domain controller attempted to validate the credentials"),
    ("1102", "SYSTEM",         "The audit log was cleared"),
    ("5156", "SYSTEM",         "Network connection allowed to 185.220.101.47:443"),
]

win_lines = []
for i in range(100):
    t = ts_win(base, i * 36)
    event_id, user, msg = random.choice(win_events)
    src = attacker_ip() if event_id in ("4625", "1102", "5156") else internal_ip()
    win_lines.append(f"{t} EventID={event_id} User={user} Source={src} Message={msg}")

with open("logs/windows_events.log", "w") as f:
    f.write("\n".join(win_lines))
print(f"✅ Created logs/windows_events.log ({len(win_lines)} lines)")


# ── 4. JSON ──────────────────────────────────────────────────────────
json_events = [
    {"severity": "HIGH",     "message": "SQL injection attempt detected in POST /api/login"},
    {"severity": "CRITICAL", "message": "LSASS memory read detected - possible credential dump"},
    {"severity": "HIGH",     "message": "Outbound connection to known C2 IP 185.220.101.47"},
    {"severity": "MEDIUM",   "message": "DNS query flood: 1200 requests per minute to random subdomains"},
    {"severity": "HIGH",     "message": "Encoded PowerShell execution detected: -EncodedCommand"},
    {"severity": "MEDIUM",   "message": "Large file transfer to removable media: 4.2GB"},
    {"severity": "LOW",      "message": "Failed login attempt: 3 failures for user admin"},
    {"severity": "INFO",     "message": "User logged in successfully from known device"},
]

json_lines = []
for i in range(80):
    t = ts_iso(base, i * 45)
    event = random.choice(json_events).copy()
    event["timestamp"] = t
    event["source_ip"] = attacker_ip() if event["severity"] in ("HIGH", "CRITICAL") else internal_ip()
    event["event_id"] = f"EVT-{random.randint(10000, 99999)}"
    event["sensor"] = random.choice(["edr-01", "waf-02", "ids-03", "siem"])
    json_lines.append(json.dumps(event))

with open("logs/json_structured.log", "w") as f:
    f.write("\n".join(json_lines))
print(f"✅ Created logs/json_structured.log ({len(json_lines)} lines)")

print(f"\n🎯 Total: {len(syslog_lines)+len(apache_lines)+len(win_lines)+len(json_lines)} log lines generated across 4 files")
print("Run: python log_parser.py  to parse all of them")
