"""
ai_analyzer.py — Week 3 Day 2 (Fixed)
======================================
Uses new google-genai package (old google.generativeai is deprecated).
Includes response caching + 429 quota handling + rule-based fallback.

Setup:
  pip install google-genai python-dotenv
  Add to .env: GEMINI_API_KEY=your_key_here
"""

import os, json, hashlib, time
from dotenv import load_dotenv
load_dotenv()

# ── In-memory response cache ─────────────────────────────────────
_cache: dict = {}
def _make_key(event: dict) -> str:
    """Cache key based on technique + severity + message start."""
    raw = event.get('technique_id','NONE') + "|" + event.get('severity','') + "|" + str(event.get('message',''))[:60]
    {str(event.get('message',''))[:60]}
    return hashlib.md5(raw.encode()).hexdigest()

# ── Few-shot example for better Gemini output ─────────────────────
FEW_SHOT_EXAMPLE = """
Example of a perfect response:

Event: Failed password for invalid user admin from 91.108.4.55 port 22
Severity: HIGH | MITRE: T1110.001

{
  "threat_type": "SSH Brute Force Attack",
  "explanation": "Automated credential stuffing from 91.108.4.55 cycling common passwords at machine speed. Confirms scripted tool like Hydra or Medusa targeting SSH on port 22.",
  "attacker_intent": "Gain initial SSH access by guessing valid credentials for persistent shell access.",
  "risk": "Successful login gives attacker shell — lateral movement, data theft, or ransomware follows.",
  "recommendations": [
    "Block IP 91.108.4.55 at perimeter firewall immediately",
    "Disable SSH password auth — enforce key-based authentication only",
    "Enable fail2ban: 15-minute lockout after 5 failed attempts"
  ],
  "false_positive_probability": 0.01
}

Now analyze the following event with the same quality:
"""


# ── Main function (called by api.py) ─────────────────────────────

def analyze_threat(event: dict) -> dict:
    """
    Analyze a security event using Google Gemini AI.
    Falls back to rule-based if API unavailable or quota exceeded.

    Args:
        event: dict with message, severity, source_ip,
               anomaly_score, technique_id, tactic

    Returns:
        dict with threat_type, explanation, attacker_intent,
               risk, recommendations, false_positive_probability, source
    """
    # Check cache first
    key = _make_key(event)
    if key in _cache:
        cached = _cache[key].copy()
        cached["source"] = cached.get("source", "cache") + " [cached]"
        return cached

    api_key = os.getenv("GEMINI_API_KEY")

    if api_key:
        try:
            from google import genai                         # new package
            from google.genai import types

            client = genai.Client(api_key=api_key)

            sev   = event.get("severity", "UNKNOWN")
            msg   = event.get("message", "")
            ip    = event.get("source_ip", "unknown")
            score = float(event.get("anomaly_score", 0.0))
            tid   = event.get("technique_id") or "not identified"
            tact  = event.get("tactic") or "not identified"

            urgency = ""
            if sev == "CRITICAL":
                urgency = "\n⚠️ CRITICAL SEVERITY — possible active breach. Be urgent.\n"

            prompt = f"""You are a senior SOC analyst with 10 years of incident response experience.
{FEW_SHOT_EXAMPLE}
Security Event:
- Message      : {msg}
- Severity     : {sev}
- Source IP    : {ip}
- Anomaly Score: {score:.2f} / 1.0
- MITRE Technique: {tid}
- MITRE Tactic   : {tact}
{urgency}
Respond ONLY with raw JSON — no markdown, no code blocks, no extra text:
{{
  "threat_type": "specific threat name",
  "explanation": "2-3 sentences explaining what is happening technically",
  "attacker_intent": "what the attacker wants to achieve",
  "risk": "specific consequence if not stopped",
  "recommendations": ["specific action 1", "specific action 2", "specific action 3"],
  "false_positive_probability": 0.05
}}"""

            t0 = time.time()
            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    max_output_tokens=500,
                )
            )
            latency = round((time.time() - t0) * 1000)

            text = response.text.strip()
            # Strip markdown fences if Gemini adds them
            if "```" in text:
                parts = text.split("```")
                text  = parts[1] if len(parts) > 1 else parts[0]
                if text.startswith("json"):
                    text = text[4:]
            text = text.strip()

            result = json.loads(text)
            result["source"]     = "gemini-2.0-flash"
            result["latency_ms"] = latency

            # Save to cache
            _cache[key] = result
            return result

        except json.JSONDecodeError:
            result = {
                "threat_type": "AI Analysis",
                "explanation": response.text[:250],
                "attacker_intent": "See explanation above",
                "risk": "Review manually",
                "recommendations": ["Investigate this event immediately"],
                "false_positive_probability": 0.1,
                "source": "gemini-text",
                "latency_ms": 0,
            }
            _cache[key] = result
            return result

        except Exception as ex:
            err_msg = str(ex)
            # 429 = quota exceeded, 404 = wrong model
            if "429" in err_msg:
                src = "rule-based (Gemini quota exceeded — wait 1 min)"
            elif "404" in err_msg:
                src = "rule-based (Gemini model not found — check model name)"
            else:
                src = f"rule-based (Gemini error: {err_msg[:50]})"
            result = _rule_based(event)
            result["source"] = src
            # Cache rule-based too so same event doesn't retry API
            _cache[key] = result
            return result
    else:
        result = _rule_based(event)
        result["source"] = "rule-based (add GEMINI_API_KEY to .env for AI)"
        _cache[key] = result
        return result


# ── Rule-based fallback ───────────────────────────────────────────

def _rule_based(event: dict) -> dict:
    msg   = str(event.get("message", "")).lower()
    score = float(event.get("anomaly_score", 0.0))
    ip    = event.get("source_ip", "unknown")

    if any(k in msg for k in ["sql", "inject", "union select", "1=1", "xp_cmdshell"]):
        return {
            "threat_type":   "SQL Injection (T1190)",
            "explanation":   f"Attacker from {ip} injecting SQL code into web inputs to bypass authentication or dump database contents. Automated tooling confirmed by pattern.",
            "attacker_intent": "Steal credentials, dump database, or gain admin access.",
            "risk":          "Full database compromise — all user data and passwords exposed.",
            "recommendations": [f"Block {ip} at WAF immediately", "Audit all DB queries last 24h", "Check for successful auth bypasses"],
            "false_positive_probability": 0.03, "latency_ms": 0,
        }
    if any(k in msg for k in ["failed password", "invalid user", "authentication failure", "4625"]):
        return {
            "threat_type":   "Brute Force Attack (T1110.001)",
            "explanation":   f"Automated credential stuffing from {ip} at machine speed. High failure rate confirms scripted tool cycling through password lists.",
            "attacker_intent": "Find valid credentials for initial system access.",
            "risk":          "Account compromise leads to lateral movement across the network.",
            "recommendations": [f"Block IP {ip} at firewall immediately", "Enable account lockout after 5 attempts", "Enforce MFA on all external services"],
            "false_positive_probability": 0.02, "latency_ms": 0,
        }
    if any(k in msg for k in ["powershell", "-enc", "encodedcommand", "invoke-expression", "iex("]):
        return {
            "threat_type":   "Encoded PowerShell (T1059.001)",
            "explanation":   "Base64-encoded PowerShell command detected — obfuscation technique to hide malicious payload from signature-based AV and EDR tools.",
            "attacker_intent": "Execute malware, establish reverse shell, or create persistence while evading detection.",
            "risk":          "Malware installation or backdoor deployment on this host.",
            "recommendations": ["Decode and analyse the Base64 payload immediately", "Isolate affected host from network", "Enable PowerShell Script Block Logging via GPO"],
            "false_positive_probability": 0.07, "latency_ms": 0,
        }
    if any(k in msg for k in ["lsass", "credential dump", "mimikatz", "procdump"]):
        return {
            "threat_type":   "LSASS Credential Dump (T1055.012)",
            "explanation":   "LSASS process memory being read — contains plaintext passwords and NTLM hashes for all logged-in users including domain administrators.",
            "attacker_intent": "Harvest all domain credentials for unrestricted lateral movement.",
            "risk":          "Full domain compromise — every account credential exposed to attacker.",
            "recommendations": ["ISOLATE host from network immediately — do not shut down", "Reset ALL domain admin and service account passwords NOW", "Enable Windows Credential Guard to prevent future LSASS reads"],
            "false_positive_probability": 0.01, "latency_ms": 0,
        }
    if any(k in msg for k in ["185.220", "beacon", "cobalt", "meterpreter", "reverse shell", " c2"]):
        return {
            "threat_type":   "C2 Beacon (T1071.001)",
            "explanation":   "Host communicating with known command-and-control infrastructure. Confirms active malware infection with remote operator having interactive shell access.",
            "attacker_intent": "Maintain persistent remote access for data exfiltration and lateral movement.",
            "risk":          "Active breach — attacker currently has hands-on access to this machine.",
            "recommendations": ["ISOLATE host from all networks immediately", "Capture memory image before powering off", "Hunt same C2 IOC across all other hosts"],
            "false_positive_probability": 0.01, "latency_ms": 0,
        }
    if any(k in msg for k in ["1102", "audit log cleared", "wevtutil", "event log"]):
        return {
            "threat_type":   "Audit Log Cleared (T1562.001)",
            "explanation":   "Windows audit log deliberately cleared — attacker destroying forensic evidence of their activity on this system.",
            "attacker_intent": "Cover tracks and prevent incident timeline reconstruction by defenders.",
            "risk":          "Loss of all forensic evidence — full incident scope may be permanently unrecoverable.",
            "recommendations": ["Treat as fully compromised — initiate incident response NOW", "Check SIEM for log copies forwarded before clearing", "Forensically image disk before any remediation"],
            "false_positive_probability": 0.02, "latency_ms": 0,
        }
    if any(k in msg for k in ["4698", "scheduled task", "schtasks"]):
        return {
            "threat_type":   "Persistence via Scheduled Task (T1053.005)",
            "explanation":   "New scheduled task created — attackers use this to survive reboots and maintain persistent access even after malware removal.",
            "attacker_intent": "Establish long-term persistence so malware reinstalls itself after removal.",
            "risk":          "Persistent foothold that survives system restarts and antivirus scans.",
            "recommendations": ["Review new task name and its target command", "Scan task binary with EDR/VirusTotal", "Audit all recently created scheduled tasks across endpoints"],
            "false_positive_probability": 0.15, "latency_ms": 0,
        }
    if score >= 0.75:
        return {
            "threat_type":   "High-Confidence Anomaly",
            "explanation":   f"Event scored {score:.2f}/1.0 — 2 or more independent ML models flagged this as significantly outside the normal behavioral baseline.",
            "attacker_intent": "Unknown — statistical anomaly requires manual analyst investigation.",
            "risk":          "High — abnormal behaviour with no matching signature needs immediate review.",
            "recommendations": [f"Review complete activity history of {ip} today", "Cross-reference with external threat intel (VirusTotal, Shodan)", "Check all correlated events in same 5-minute window"],
            "false_positive_probability": 0.20, "latency_ms": 0,
        }
    return {
        "threat_type":   "Low-Risk Event",
        "explanation":   f"Anomaly score {score:.2f}/1.0 is within the normal baseline. No known attack signatures detected in the message content.",
        "attacker_intent": "None identified.",
        "risk":          "Low — consistent with normal activity. No action required.",
        "recommendations": ["Continue monitoring for pattern changes", "No immediate action required"],
        "false_positive_probability": 0.80, "latency_ms": 0,
    }


# ── Quick test ────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  AI ANALYZER — Quick Test")
    api_key = os.getenv("GEMINI_API_KEY")
    print(f"  Mode: {'Gemini 2.0 Flash AI' if api_key else 'Rule-based'}")
    print("=" * 60)

    events = [
        {"message": "Failed password for invalid user admin from 195.178.55.22 port 44392 ssh2",
         "severity": "HIGH", "source_ip": "195.178.55.22",
         "anomaly_score": 0.82, "technique_id": "T1110.001", "tactic": "Credential Access"},
        {"message": "LSASS memory read detected — possible credential dump",
         "severity": "CRITICAL", "source_ip": "10.0.0.55",
         "anomaly_score": 0.96, "technique_id": "T1055.012", "tactic": "Privilege Escalation"},
    ]

    for i, e in enumerate(events, 1):
        r = analyze_threat(e)
        print(f"\n  [{i}] {e['severity']} | {r['threat_type']}")
        print(f"       {r['explanation'][:75]}...")
        print(f"       Action: {r['recommendations'][0]}")
        print(f"       Source: {r['source']}")

    # Cache test
    print(f"\n  Cache test (same event called again):")
    t0 = time.time()
    analyze_threat(events[0])
    ms = round((time.time() - t0) * 1000)
    print(f"  Returned in {ms}ms — {'CACHE HIT ✅' if ms < 5 else f'no cache ({ms}ms)'}")
    print("=" * 60)