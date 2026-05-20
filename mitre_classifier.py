import re
from log_parser import parse_log_file
import os


# ─────────────────────────────────────────────
# MITRE TECHNIQUE DEFINITIONS
# ─────────────────────────────────────────────

TECHNIQUES = {
    "T1110.001": {
        "name":   "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    },
    "T1046": {
        "name":   "Network Service Scanning",
        "tactic": "Discovery",
    },
    "T1190": {
        "name":   "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "T1059.001": {
        "name":   "Command and Scripting: PowerShell",
        "tactic": "Execution",
    },
    "T1059.007": {
        "name":   "Command and Scripting: JavaScript/XSS",
        "tactic": "Execution",
    },
    "T1071.001": {
        "name":   "Application Layer Protocol: Web (C2)",
        "tactic": "Command and Control",
    },
    "T1078": {
        "name":   "Valid Accounts",
        "tactic": "Defense Evasion / Persistence",
    },
    "T1053.005": {
        "name":   "Scheduled Task/Job",
        "tactic": "Persistence",
    },
    "T1055.012": {
        "name":   "Process Injection: LSASS",
        "tactic": "Defense Evasion / Privilege Escalation",
    },
    "T1087.002": {
        "name":   "Account Discovery: Domain Account",
        "tactic": "Discovery",
    },
    "T1562.001": {
        "name":   "Impair Defenses: Disable/Clear Logs",
        "tactic": "Defense Evasion",
    },
    "T1052.001": {
        "name":   "Exfiltration over Physical Medium: USB",
        "tactic": "Exfiltration",
    },
}


# ─────────────────────────────────────────────
# DETECTION RULES
# Each rule is a dict:
#   patterns  : list of regex strings (ANY match = technique detected)
#   technique : MITRE technique ID
#   confidence: HIGH / MEDIUM / LOW
# ─────────────────────────────────────────────

RULES = [
    # ── T1110.001 Brute Force ─────────────────────────────────────
    {
        "technique":  "T1110.001",
        "confidence": "HIGH",
        "patterns": [
            r"failed password",
            r"authentication failure",
            r"invalid user",
            r"failed login",
            r"bad password",
            r"EventID=4625",
            r"Login attempt.*fail",
        ],
    },

    # ── T1046 Network Scanning ────────────────────────────────────
    {
        "technique":  "T1046",
        "confidence": "HIGH",
        "patterns": [
            r"port.?scan",
            r"\d+ ports? in \d+",
            r"nmap",
            r"masscan",
            r"scan sweep",
            r"SYN flood",
        ],
    },

    # ── T1190 Exploit Public App ──────────────────────────────────
    {
        "technique":  "T1190",
        "confidence": "HIGH",
        "patterns": [
            r"sql.?inject",
            r"union.{0,10}select",
            r"1=1",
            r"xp_cmdshell",
            r"exploit",
            r"CVE-\d{4}-\d+",
            r"RCE",
            r"remote code",
            r"\.\.\/",                   # path traversal
            r"wp-login\.php.*POST",
        ],
    },

    # ── T1059.001 PowerShell ──────────────────────────────────────
    {
        "technique":  "T1059.001",
        "confidence": "HIGH",
        "patterns": [
            r"powershell",
            r"-[Ee]nc(odedCommand)?",
            r"-[Ee]xecutionPolicy",
            r"IEX\s*\(",
            r"Invoke-Expression",
            r"downloadstring",
            r"EventID=4688.*powershell",
        ],
    },

    # ── T1059.007 XSS ─────────────────────────────────────────────
    {
        "technique":  "T1059.007",
        "confidence": "MEDIUM",
        "patterns": [
            r"<script",
            r"javascript:",
            r"onerror=",
            r"XSS",
            r"cross.site",
        ],
    },

    # ── T1071.001 C2 Web Protocol ─────────────────────────────────
    {
        "technique":  "T1071.001",
        "confidence": "HIGH",
        "patterns": [
            r"185\.220\.101\.",          # known Tor exit / C2
            r"91\.108\.\d+\.",
            r"beacon",
            r"C2",
            r"cobalt.?strike",
            r"meterpreter",
            r"reverse.?shell",
            r"outbound.*443.*suspicious",
        ],
    },

    # ── T1078 Valid Accounts ──────────────────────────────────────
    {
        "technique":  "T1078",
        "confidence": "MEDIUM",
        "patterns": [
            r"EventID=4624",             # successful logon
            r"EventID=4648",             # logon with explicit credentials
            r"accepted password",
            r"successful.*login",
            r"vpn.*login.*unusual",
            r"geo.*login",
        ],
    },

    # ── T1053.005 Scheduled Task ──────────────────────────────────
    {
        "technique":  "T1053.005",
        "confidence": "HIGH",
        "patterns": [
            r"EventID=4698",
            r"scheduled task.*creat",
            r"schtasks",
            r"crontab",
            r"persistence.*task",
        ],
    },

    # ── T1055.012 Process Injection / LSASS ──────────────────────
    {
        "technique":  "T1055.012",
        "confidence": "HIGH",
        "patterns": [
            r"lsass",
            r"process.?inject",
            r"process.?hollow",
            r"memory.?inject",
            r"credential.?dump",
            r"mimikatz",
        ],
    },

    # ── T1087.002 Domain Account Discovery ───────────────────────
    {
        "technique":  "T1087.002",
        "confidence": "MEDIUM",
        "patterns": [
            r"ldap.*objectclass",
            r"net user",
            r"net group",
            r"domain.*enum",
            r"AD dump",
            r"EventID=4769",
        ],
    },

    # ── T1562.001 Log Clearing ────────────────────────────────────
    {
        "technique":  "T1562.001",
        "confidence": "HIGH",
        "patterns": [
            r"EventID=1102",
            r"audit log.*clear",
            r"log.*delet",
            r"wevtutil.*cl",
        ],
    },

    # ── T1052.001 USB Exfiltration ────────────────────────────────
    {
        "technique":  "T1052.001",
        "confidence": "MEDIUM",
        "patterns": [
            r"removable media",
            r"usb.*transfer",
            r"external.*drive",
            r"\d+\.\d+ GB.*cop",
        ],
    },
]

# Pre-compile all regex patterns for speed
_COMPILED_RULES = [
    {
        **rule,
        "_compiled": [re.compile(p, re.IGNORECASE) for p in rule["patterns"]],
    }
    for rule in RULES
]


# ─────────────────────────────────────────────
# CLASSIFIER FUNCTION
# ─────────────────────────────────────────────

def classify_event(log_event: dict) -> dict:
    """
    Takes a parsed log event dict and returns MITRE classification.

    Returns:
    {
        "technique_id":   str or None,
        "technique_name": str or None,
        "tactic":         str or None,
        "confidence":     str,          # HIGH / MEDIUM / LOW / NONE
        "matched_rule":   str or None,  # which pattern triggered
    }
    """
    message = str(log_event.get("message", ""))
    raw     = str(log_event.get("raw", ""))
    text    = message + " " + raw   # search both fields

    best_match    = None
    best_conf_ord = -1
    conf_order    = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}

    for rule in _COMPILED_RULES:
        for pattern in rule["_compiled"]:
            if pattern.search(text):
                conf = rule["confidence"]
                if conf_order.get(conf, -1) > best_conf_ord:
                    best_conf_ord = conf_order[conf]
                    best_match    = rule
                    best_pattern  = pattern.pattern
                break   # first matching pattern in this rule is enough

    if best_match:
        tid  = best_match["technique"]
        info = TECHNIQUES.get(tid, {})
        return {
            "technique_id":   tid,
            "technique_name": info.get("name", "Unknown"),
            "tactic":         info.get("tactic", "Unknown"),
            "confidence":     best_match["confidence"],
            "matched_rule":   best_pattern,
        }

    return {
        "technique_id":   None,
        "technique_name": None,
        "tactic":         None,
        "confidence":     "NONE",
        "matched_rule":   None,
    }


def classify_events(log_events: list) -> list:
    """Classify a list of log events. Returns list of classification dicts."""
    return [classify_event(e) for e in log_events]


# ─────────────────────────────────────────────
# MAIN TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":

    print("=" * 65)
    print("  MITRE ATT&CK CLASSIFIER TEST")
    print("=" * 65)

    # Test with known-bad events
    test_events = [
        {"message": "Failed password for invalid user admin from 195.178.55.22", "raw": ""},
        {"message": "SQL injection attempt detected in POST /api/login union select", "raw": ""},
        {"message": "powershell.exe -EncodedCommand SQBFAFgA detected", "raw": ""},
        {"message": "LSASS memory read detected - possible credential dump", "raw": ""},
        {"message": "Outbound connection to known C2 IP 185.220.101.47:443 beacon", "raw": ""},
        {"message": "EventID=4698 scheduled task created: svchost_update", "raw": ""},
        {"message": "EventID=1102 The audit log was cleared", "raw": ""},
        {"message": "Large file transfer to removable media: 4.2GB", "raw": ""},
        {"message": "port scan sweep detected from 195.178.55.22", "raw": ""},
        {"message": "Normal user login from known device at 9am", "raw": ""},   # should be NONE
    ]

    print(f"\n  Testing {len(test_events)} events:\n")
    matched = 0
    for evt in test_events:
        result = classify_event(evt)
        if result["technique_id"]:
            matched += 1
            print(f"  ✅ [{result['confidence']:<6}] {result['technique_id']} "
                  f"| {result['tactic']:<35} | {evt['message'][:45]}")
        else:
            print(f"  ⚪ [NONE  ] No technique matched"
                  f"                                   | {evt['message'][:45]}")

    accuracy = matched / (len(test_events) - 1) * 100   # -1 for intentional NONE
    print(f"\n  Classification rate: {matched}/{len(test_events)-1} "
          f"threat events = {accuracy:.0f}%")
    print(f"  Target: 70%+  →  {'✅ PASS' if accuracy >= 70 else '❌ FAIL'}")

    # Now classify all sample log files
    print(f"\n  ── Classifying all sample logs ──")
    all_events = []
    for path in ["logs/syslog_sample.log", "logs/apache_access.log",
                 "logs/windows_events.log", "logs/json_structured.log"]:
        if os.path.exists(path):
            events = parse_log_file(path)
            all_events.extend(events)

    classifications = classify_events(all_events)
    total     = len(classifications)
    tagged    = sum(1 for c in classifications if c["technique_id"])
    tag_rate  = tagged / total * 100 if total > 0 else 0

    print(f"  Total events:    {total}")
    print(f"  Tagged with MITRE technique: {tagged} ({tag_rate:.1f}%)")

    # Technique frequency
    from collections import Counter
    tech_counts = Counter(
        c["technique_id"] for c in classifications
        if c["technique_id"]
    )
    print(f"\n  Top techniques detected:")
    for tid, count in tech_counts.most_common(8):
        name = TECHNIQUES[tid]["name"]
        bar  = "█" * (count // 3)
        print(f"  {tid}  {count:>4}x  {bar}  {name}")

    # Tactic breakdown
    tactic_counts = Counter(
        c["tactic"] for c in classifications
        if c["tactic"]
    )
    print(f"\n  Tactic breakdown:")
    for tactic, count in tactic_counts.most_common():
        print(f"  {tactic:<40} {count:>4}")

    print("=" * 65)