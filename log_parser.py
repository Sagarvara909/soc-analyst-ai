"""
log_parser.py
-------------
Parses 4 common security log formats into a unified Python dict.

Supported formats:
  1. Syslog (RFC 5424)        e.g. firewall, Linux system logs
  2. Apache / NGINX access    e.g. web server logs
  3. Windows Event Log (text) e.g. failed logins, process creation
  4. JSON structured logs     e.g. modern EDR, cloud logs

Each parsed log returns a dict with these standard fields:
  {
    "timestamp": str,
    "severity":  str,   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    "source_ip": str,
    "message":   str,
    "raw":       str,   # original line, always kept
    "format":    str,   # which parser matched
  }
"""

import re
import json
from datetime import datetime


# ─────────────────────────────────────────────
# REGEX PATTERNS  (compile once for speed)
# ─────────────────────────────────────────────

# Syslog: Jan 15 14:32:01 hostname sshd[1234]: message
SYSLOG_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)'
)

# Apache: 192.168.1.1 - - [15/Jan/2026:14:32:01 +0000] "GET /path HTTP/1.1" 200 1234
APACHE_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<datetime>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
)

# Windows Event Log (simplified text export format)
# Example: 2026-01-15 14:32:01 EventID=4625 User=DOMAIN\admin Source=192.168.1.55 Message=An account failed to log on
WINDOWS_RE = re.compile(
    r'(?P<datetime>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'EventID=(?P<event_id>\d+)\s+'
    r'(?:User=(?P<user>\S+)\s+)?'
    r'(?:Source=(?P<ip>\d+\.\d+\.\d+\.\d+)\s+)?'
    r'Message=(?P<message>.+)'
)

# IP extractor (used as fallback across all formats)
IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')


# ─────────────────────────────────────────────
# SEVERITY MAPPING
# ─────────────────────────────────────────────

# Windows Event IDs → severity
WINDOWS_EVENT_SEVERITY = {
    "4625": "HIGH",    # Failed logon
    "4648": "HIGH",    # Logon with explicit credentials
    "4720": "HIGH",    # User account created
    "4728": "HIGH",    # Member added to privileged group
    "4732": "MEDIUM",  # Member added to local group
    "4756": "MEDIUM",  # Member added to universal group
    "4688": "MEDIUM",  # New process created
    "4698": "HIGH",    # Scheduled task created
    "4702": "MEDIUM",  # Scheduled task updated
    "4769": "MEDIUM",  # Kerberos ticket requested
    "4776": "MEDIUM",  # Credential validation
    "7045": "HIGH",    # New service installed
    "1102": "CRITICAL",# Audit log cleared
    "4657": "MEDIUM",  # Registry value modified
    "5156": "LOW",     # Network connection allowed
    "5158": "LOW",     # Network bind allowed
}

# Apache HTTP status codes → severity
def apache_status_to_severity(status: str) -> str:
    code = int(status)
    if code >= 500:
        return "MEDIUM"     # server errors
    elif code == 403:
        return "MEDIUM"     # forbidden — possible probe
    elif code == 401:
        return "MEDIUM"     # unauthorized
    elif code == 404:
        return "LOW"        # not found — possible scan
    else:
        return "INFO"

# Keywords in syslog messages → severity
SYSLOG_SEVERITY_KEYWORDS = {
    "CRITICAL": ["exploit", "rootkit", "ransomware", "intrusion detected", "critical"],
    "HIGH":     ["authentication failure", "failed password", "invalid user",
                 "refused connect", "port scan", "brute force", "sudo"],
    "MEDIUM":   ["warning", "error", "denied", "rejected", "timeout"],
    "LOW":      ["notice", "info", "started", "stopped", "restarted"],
}

def classify_syslog_severity(message: str) -> str:
    msg_lower = message.lower()
    for severity, keywords in SYSLOG_SEVERITY_KEYWORDS.items():
        for kw in keywords:
            if kw in msg_lower:
                return severity
    return "INFO"


# ─────────────────────────────────────────────
# INDIVIDUAL PARSERS
# ─────────────────────────────────────────────

def parse_syslog(line: str) -> dict | None:
    """Parse a Syslog (RFC 5424 simplified) line."""
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None

    message = m.group("message")
    # Try to find an IP in the message body
    ip_match = IP_RE.search(message)
    source_ip = ip_match.group(1) if ip_match else "unknown"

    return {
        "timestamp": f"{m.group('month')} {m.group('day')} {m.group('time')}",
        "severity":  classify_syslog_severity(message),
        "source_ip": source_ip,
        "message":   message,
        "raw":       line.strip(),
        "format":    "syslog",
    }


def parse_apache(line: str) -> dict | None:
    """Parse an Apache / NGINX Combined Log Format line."""
    m = APACHE_RE.match(line.strip())
    if not m:
        return None

    status  = m.group("status")
    method  = m.group("method")
    path    = m.group("path")
    message = f"{method} {path} → HTTP {status}"

    return {
        "timestamp": m.group("datetime"),
        "severity":  apache_status_to_severity(status),
        "source_ip": m.group("ip"),
        "message":   message,
        "raw":       line.strip(),
        "format":    "apache",
    }


def parse_windows_event(line: str) -> dict | None:
    """Parse a Windows Event Log text export line."""
    m = WINDOWS_RE.match(line.strip())
    if not m:
        return None

    event_id  = m.group("event_id")
    message   = m.group("message")
    source_ip = m.group("ip") or "unknown"

    # Append user to message if present
    user = m.group("user")
    if user:
        message = f"[{user}] {message}"

    return {
        "timestamp": m.group("datetime"),
        "severity":  WINDOWS_EVENT_SEVERITY.get(event_id, "LOW"),
        "source_ip": source_ip,
        "message":   f"EventID {event_id}: {message}",
        "raw":       line.strip(),
        "format":    "windows_event",
    }


def parse_json_log(line: str) -> dict | None:
    """Parse a JSON-structured log line (modern EDR / cloud format)."""
    try:
        data = json.loads(line.strip())
    except json.JSONDecodeError:
        return None

    # Try common field name variations
    timestamp = (data.get("timestamp") or data.get("time") or
                 data.get("@timestamp") or data.get("ts") or "unknown")

    severity  = (data.get("severity") or data.get("level") or
                 data.get("log_level") or "INFO").upper()

    source_ip = (data.get("source_ip") or data.get("src_ip") or
                 data.get("client_ip") or data.get("remote_addr") or "unknown")

    message   = (data.get("message") or data.get("msg") or
                 data.get("description") or str(data))

    # Normalise severity spelling variations
    if severity in ("WARNING", "WARN"):
        severity = "MEDIUM"
    elif severity in ("ERROR", "ERR"):
        severity = "HIGH"
    elif severity in ("DEBUG", "TRACE"):
        severity = "LOW"

    return {
        "timestamp": str(timestamp),
        "severity":  severity,
        "source_ip": str(source_ip),
        "message":   str(message),
        "raw":       line.strip(),
        "format":    "json",
    }


# ─────────────────────────────────────────────
# MAIN PARSER  (auto-detects format)
# ─────────────────────────────────────────────

def parse_log_line(line: str) -> dict | None:
    """
    Auto-detect log format and parse a single line.
    Returns a unified dict or None if the line is empty / unrecognised.
    """
    line = line.strip()
    if not line or line.startswith("#"):   # skip blank lines and comments
        return None

    # Try each parser in order
    for parser in [parse_json_log, parse_windows_event, parse_apache, parse_syslog]:
        result = parser(line)
        if result:
            return result

    # Fallback: unrecognised format — keep the line anyway
    ip_match = IP_RE.search(line)
    return {
        "timestamp": "unknown",
        "severity":  "INFO",
        "source_ip": ip_match.group(1) if ip_match else "unknown",
        "message":   line[:200],          # cap at 200 chars
        "raw":       line,
        "format":    "unknown",
    }


def parse_log_file(filepath: str) -> list[dict]:
    """
    Parse an entire log file. Returns a list of parsed event dicts.
    Skips lines that return None.
    """
    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    results.append(parsed)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
    return results


# ─────────────────────────────────────────────
# QUICK TEST  (run this file directly to test)
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Sample log lines — one of each format
    test_lines = [
        # Syslog
        "Jan 15 14:32:01 webserver sshd[1234]: Failed password for invalid user admin from 195.178.55.22 port 44392 ssh2",
        "Jan 15 14:32:05 webserver sshd[1234]: Failed password for invalid user root from 195.178.55.22 port 44393 ssh2",
        "Jan 15 14:33:00 webserver sudo[5678]: authentication failure for user deploy from 10.0.0.15",

        # Apache
        '195.178.55.22 - - [15/Jan/2026:14:32:01 +0000] "GET /admin HTTP/1.1" 403 512',
        '195.178.55.22 - - [15/Jan/2026:14:32:03 +0000] "POST /wp-login.php HTTP/1.1" 200 1024',
        '10.0.0.5 - - [15/Jan/2026:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 2048',

        # Windows Event
        "2026-01-15 14:32:01 EventID=4625 User=CORP\\jsmith Source=192.168.1.55 Message=An account failed to log on",
        "2026-01-15 14:32:05 EventID=4688 User=SYSTEM Source=10.0.0.88 Message=New process created: cmd.exe parent: word.exe",
        "2026-01-15 14:33:00 EventID=1102 Message=The audit log was cleared",

        # JSON
        '{"timestamp":"2026-01-15T14:32:01Z","severity":"HIGH","source_ip":"77.88.44.3","message":"SQL injection attempt detected in POST body"}',
        '{"timestamp":"2026-01-15T14:32:10Z","level":"warning","src_ip":"10.0.0.5","msg":"Outbound connection to known C2 IP 185.220.101.47"}',
        '{"@timestamp":"2026-01-15T14:32:15Z","severity":"critical","client_ip":"0.0.0.0","message":"LSASS memory read detected - possible credential dump"}',
    ]

    print("=" * 65)
    print("  LOG PARSER TEST — parsing 12 sample lines")
    print("=" * 65)

    passed = 0
    format_counts = {}

    for i, line in enumerate(test_lines, 1):
        result = parse_log_line(line)
        if result:
            passed += 1
            fmt = result["format"]
            format_counts[fmt] = format_counts.get(fmt, 0) + 1
            print(f"\n[{i:02d}] Format   : {fmt.upper()}")
            print(f"     Timestamp: {result['timestamp']}")
            print(f"     Severity : {result['severity']}")
            print(f"     Source IP: {result['source_ip']}")
            print(f"     Message  : {result['message'][:70]}...")
        else:
            print(f"\n[{i:02d}] FAILED to parse: {line[:60]}...")

    print("\n" + "=" * 65)
    print(f"  RESULT: {passed}/{len(test_lines)} lines parsed successfully")
    print(f"  Formats detected: {format_counts}")
    extraction_rate = round(passed / len(test_lines) * 100, 1)
    print(f"  Field extraction rate: {extraction_rate}%")
    if extraction_rate >= 90:
        print("  ✅ PASS — target is 90%+")
    else:
        print("  ❌ FAIL — below 90% target, check regex patterns")
    print("=" * 65)
