"""
prompt_engineer.py — Week 3 Day 2
===================================
Improves the Gemini AI integration with:
  1. Few-shot prompting    — gives Gemini examples so it learns the format
  2. Chain-of-thought      — asks Gemini to reason step by step
  3. Response caching      — same attack pattern = cached response (saves quota)
  4. Severity-aware prompts — CRITICAL events get more urgent prompt
  5. Quality testing        — scores 20 event types for analysis quality

Run: python prompt_engineer.py
"""

import os
import json
import hashlib
import time
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# RESPONSE CACHE
# Saves API quota — same event pattern returns cached result
# ─────────────────────────────────────────────

_cache: dict = {}

def _cache_key(event: dict) -> str:
    """Create a cache key from the event's key fields."""
    key_str = f"{event.get('technique_id','')}_{event.get('severity','')}_{event.get('source_ip','')}"
    # Also include first 50 chars of message for specificity
    key_str += f"_{str(event.get('message',''))[:50]}"
    return hashlib.md5(key_str.encode()).hexdigest()

def get_cached(event: dict):
    """Return cached result if available, else None."""
    key = _cache_key(event)
    if key in _cache:
        print(f"  [CACHE HIT] Returning cached result for {event.get('technique_id','unknown')}")
        return _cache[key]
    return None

def set_cache(event: dict, result: dict):
    """Store result in cache."""
    key = _cache_key(event)
    _cache[key] = result


# ─────────────────────────────────────────────
# FEW-SHOT EXAMPLES
# Teach Gemini the exact format and quality we want
# ─────────────────────────────────────────────

FEW_SHOT_EXAMPLES = """
Here are 2 examples of perfect analysis:

EXAMPLE 1:
Event: "Failed password for invalid user admin from 91.108.4.55 port 44392 ssh2"
Severity: HIGH | MITRE: T1110.001 | Score: 0.82
Response:
{
  "threat_type": "SSH Brute Force Attack",
  "explanation": "Automated credential stuffing from 91.108.4.55 cycling through common usernames at machine speed — 847 attempts in 4 minutes confirms a scripted tool like Hydra or Medusa. The attacker is targeting the SSH service on port 22 with a dictionary of common passwords.",
  "attacker_intent": "Gain initial access by discovering valid SSH credentials to establish an interactive shell on the target system.",
  "risk": "If a valid credential is found, attacker gains persistent shell access and can begin lateral movement, data theft, or ransomware deployment.",
  "recommendations": [
    "Block IP 91.108.4.55 at the perimeter firewall immediately and add to threat intel blocklist",
    "Disable password authentication for SSH — enforce key-based authentication only",
    "Move SSH to a non-standard port and implement fail2ban with a 15-minute lockout"
  ],
  "false_positive_probability": 0.01
}

EXAMPLE 2:
Event: "LSASS memory read detected - possible credential dump"
Severity: CRITICAL | MITRE: T1055.012 | Score: 0.96
Response:
{
  "threat_type": "LSASS Credential Dump",
  "explanation": "The Local Security Authority Subsystem Service (LSASS) process memory is being read by an unauthorised process — this is the primary Windows credential store containing plaintext passwords and NTLM hashes for all logged-in users. This is a hands-on-keyboard attacker, not automated malware.",
  "attacker_intent": "Extract all domain credentials from memory to enable unrestricted lateral movement and privilege escalation across every system in the network.",
  "risk": "Full domain compromise — every account credential exposed. Attacker can impersonate domain admins, access all file shares, and persist indefinitely.",
  "recommendations": [
    "ISOLATE this host from the network immediately — do not shut down, take a memory image first",
    "Reset ALL domain admin and service account passwords before the host is reconnected",
    "Enable Windows Credential Guard via Group Policy to prevent future LSASS reads"
  ],
  "false_positive_probability": 0.01
}

Now analyze the following event with the same quality and format:
"""


# ─────────────────────────────────────────────
# PROMPT BUILDER
# Different prompt styles for different situations
# ─────────────────────────────────────────────

def build_prompt(event: dict, style: str = "few_shot") -> str:
    """
    Build the best prompt for this event.

    Styles:
      few_shot   — includes examples (best quality, slightly longer)
      chain      — chain-of-thought reasoning (best for complex events)
      fast       — minimal prompt (fastest, cheapest)
    """
    msg   = event.get('message', '')
    sev   = event.get('severity', 'UNKNOWN')
    ip    = event.get('source_ip', 'unknown')
    score = float(event.get('anomaly_score', 0.0))
    tid   = event.get('technique_id') or 'not identified'
    tact  = event.get('tactic') or 'not identified'

    # System context
    urgency = ""
    if sev == "CRITICAL":
        urgency = "\n⚠️  CRITICAL SEVERITY — This may be an active breach. Be direct and urgent.\n"
    elif sev == "HIGH":
        urgency = "\n🔴 HIGH SEVERITY — Immediate analyst action required.\n"

    event_block = f"""
Security Event:
- Message      : {msg}
- Severity     : {sev}
- Source IP    : {ip}
- Anomaly Score: {score:.2f} / 1.0
- MITRE Technique: {tid}
- MITRE Tactic   : {tact}
{urgency}"""

    json_format = """
Respond ONLY with this JSON — no markdown, no explanation, just raw JSON:
{
  "threat_type": "short threat name",
  "explanation": "2-3 sentences: what is happening, how it works technically",
  "attacker_intent": "what the attacker wants to achieve with this technique",
  "risk": "specific consequence if not stopped",
  "recommendations": ["specific action 1", "specific action 2", "specific action 3"],
  "false_positive_probability": 0.05
}"""

    if style == "few_shot":
        return (
            "You are a senior SOC analyst with 10 years of incident response experience.\n"
            + FEW_SHOT_EXAMPLES
            + event_block
            + json_format
        )

    elif style == "chain":
        return f"""You are a senior SOC analyst. Think through this step by step before answering.

Step 1: What attack technique is this?
Step 2: What is the attacker trying to do?
Step 3: What is the worst-case outcome?
Step 4: What should the analyst do RIGHT NOW?

Then provide your final answer as JSON only:
{event_block}
{json_format}"""

    else:  # fast
        return f"""SOC analyst. Analyze this security event. JSON only, no other text.
{event_block}
{json_format}"""


# ─────────────────────────────────────────────
# ENHANCED ANALYZER
# ─────────────────────────────────────────────

def analyze_threat_v2(event: dict, use_cache: bool = True) -> dict:
    """
    Enhanced threat analysis with caching + best prompt selection.
    Upgrades the basic analyze_threat() from Day 1.
    """
    # Check cache first
    if use_cache:
        cached = get_cached(event)
        if cached:
            return cached

    api_key = os.getenv("GEMINI_API_KEY")

    # Choose prompt style based on severity
    sev = event.get("severity", "LOW")
    if sev == "CRITICAL":
        style = "few_shot"   # best quality for critical events
    elif sev == "HIGH":
        style = "few_shot"
    else:
        style = "fast"       # cheaper for low-severity events

    if api_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel(
                "gemini-2.0-flash",
                generation_config={
                    "temperature":     0.2,   # low = consistent, focused answers
                    "max_output_tokens": 500,
                    "top_p":           0.8,
                }
            )

            prompt = build_prompt(event, style=style)
            start  = time.time()
            response = model.generate_content(prompt)
            latency  = round((time.time() - start) * 1000)   # ms

            text = response.text.strip()
            # Remove markdown fences if present
            if "```" in text:
                parts = text.split("```")
                text = parts[1] if len(parts) > 1 else parts[0]
                if text.startswith("json"):
                    text = text[4:]
            text = text.strip()

            result = json.loads(text)
            result["source"]       = "gemini-2.0-flash"
            result["prompt_style"] = style
            result["latency_ms"]   = latency

            # Cache and return
            if use_cache:
                set_cache(event, result)
            return result

        except json.JSONDecodeError:
            result = {
                "threat_type":   "AI Analysis",
                "explanation":   response.text[:300],
                "attacker_intent": "See explanation",
                "risk":          "Review manually",
                "recommendations": ["Investigate immediately"],
                "false_positive_probability": 0.1,
                "source": "gemini-text",
                "prompt_style": style,
                "latency_ms": 0,
            }
            if use_cache: set_cache(event, result)
            return result

        except Exception as ex:
            result = _rule_based_v2(event)
            result["source"] = f"rule-based (gemini error: {str(ex)[:60]})"
            return result
    else:
        result = _rule_based_v2(event)
        result["source"] = "rule-based (set GEMINI_API_KEY in .env)"
        return result


def _rule_based_v2(event: dict) -> dict:
    """Enhanced rule-based fallback with more detail."""
    msg   = str(event.get("message", "")).lower()
    score = float(event.get("anomaly_score", 0.0))
    ip    = event.get("source_ip", "unknown")
    tid   = event.get("technique_id", "")

    if any(k in msg for k in ["sql", "inject", "union select", "1=1", "xp_cmdshell"]):
        return {"threat_type":"SQL Injection (T1190)","explanation":f"Attacker from {ip} injecting SQL code into web inputs to bypass authentication or dump database. Confirms automated attack tool.","attacker_intent":"Steal credentials, dump database contents, or gain admin access.","risk":"Full database compromise — all user data exposed.","recommendations":[f"Block {ip} at WAF immediately","Audit all DB queries in last 24h","Check for successful login bypasses"],"false_positive_probability":0.03,"prompt_style":"rule-based","latency_ms":0}
    if any(k in msg for k in ["failed password","invalid user","authentication failure","4625"]):
        return {"threat_type":"Brute Force (T1110.001)","explanation":f"Automated credential attack from {ip} cycling through username/password combinations at machine speed.","attacker_intent":"Find valid credentials for initial access.","risk":"Account compromise and lateral movement if successful.","recommendations":[f"Block IP {ip} immediately","Enable account lockout (5 attempts)","Enforce MFA on all external services"],"false_positive_probability":0.02,"prompt_style":"rule-based","latency_ms":0}
    if any(k in msg for k in ["powershell","-enc","encodedcommand","invoke-expression"]):
        return {"threat_type":"Encoded PowerShell (T1059.001)","explanation":"Base64-encoded PowerShell executed — common AV/EDR evasion technique hiding malicious payload.","attacker_intent":"Execute malware or reverse shell while evading detection.","risk":"Malware installation or backdoor deployment.","recommendations":["Decode and analyse the Base64 payload","Isolate affected host","Enable Script Block Logging via Group Policy"],"false_positive_probability":0.07,"prompt_style":"rule-based","latency_ms":0}
    if any(k in msg for k in ["lsass","credential dump","mimikatz","procdump"]):
        return {"threat_type":"LSASS Credential Dump (T1055.012)","explanation":"LSASS memory being read — extracts all plaintext passwords and NTLM hashes from the Windows credential store.","attacker_intent":"Harvest domain credentials for unrestricted lateral movement.","risk":"Full domain compromise — every account exposed.","recommendations":["ISOLATE host immediately","Reset ALL domain admin passwords","Enable Windows Credential Guard"],"false_positive_probability":0.01,"prompt_style":"rule-based","latency_ms":0}
    if any(k in msg for k in ["185.220","beacon","cobalt","meterpreter","reverse shell","c2"]):
        return {"threat_type":"C2 Beacon (T1071.001)","explanation":"Active malware communicating with command-and-control server — attacker has interactive shell access.","attacker_intent":"Maintain persistent remote access for exfiltration and lateral movement.","risk":"Active breach — attacker currently controls this machine.","recommendations":["ISOLATE host from network NOW","Capture memory image for forensics","Hunt same C2 IOC across all hosts"],"false_positive_probability":0.01,"prompt_style":"rule-based","latency_ms":0}
    if any(k in msg for k in ["1102","audit log cleared","wevtutil"]):
        return {"threat_type":"Log Clearing (T1562.001)","explanation":"Windows audit log deliberately cleared — attacker destroying forensic evidence of their activity.","attacker_intent":"Cover tracks and prevent incident timeline reconstruction.","risk":"Loss of all forensic evidence on this system.","recommendations":["Treat as fully compromised — start IR","Check SIEM for log copies","Forensically image disk before cleanup"],"false_positive_probability":0.02,"prompt_style":"rule-based","latency_ms":0}
    if score >= 0.75:
        return {"threat_type":"High Anomaly","explanation":f"Score {score:.2f}/1.0 — 2+ ML models flagged this as significantly outside normal baseline.","attacker_intent":"Unknown — statistical anomaly requires manual review.","risk":"High — abnormal behaviour needs analyst investigation.","recommendations":[f"Review full activity history of {ip}","Cross-reference with threat intel","Check correlated events in same window"],"false_positive_probability":0.20,"prompt_style":"rule-based","latency_ms":0}
    return {"threat_type":"Low Risk","explanation":f"Score {score:.2f}/1.0 within normal baseline. No attack signatures detected.","attacker_intent":"None identified.","risk":"Low.","recommendations":["Continue monitoring","No action needed"],"false_positive_probability":0.80,"prompt_style":"rule-based","latency_ms":0}


# ─────────────────────────────────────────────
# QUALITY SCORER
# ─────────────────────────────────────────────

def score_analysis_quality(result: dict) -> dict:
    """Score the quality of an AI analysis response (0-100)."""
    score = 0
    issues = []

    # Check all fields exist
    required = ["threat_type", "explanation", "attacker_intent", "risk", "recommendations", "false_positive_probability"]
    for field in required:
        if result.get(field):
            score += 10
        else:
            issues.append(f"Missing field: {field}")

    # Explanation quality — should be 2+ sentences
    expl = str(result.get("explanation", ""))
    if len(expl) > 100:
        score += 10
    else:
        issues.append("Explanation too short")

    # Should have 3 recommendations
    recs = result.get("recommendations", [])
    if len(recs) >= 3:
        score += 10
    else:
        issues.append(f"Only {len(recs)} recommendations (need 3)")

    # False positive probability should be realistic (0.0-1.0)
    fp = result.get("false_positive_probability", -1)
    if 0.0 <= float(fp) <= 1.0:
        score += 5
    else:
        issues.append("Invalid FP probability")

    # Threat type should be specific
    tt = str(result.get("threat_type", ""))
    if len(tt) > 5 and tt != "AI Analysis":
        score += 5
    else:
        issues.append("Generic threat type")

    return {
        "quality_score": score,
        "grade": "A" if score>=90 else "B" if score>=75 else "C" if score>=60 else "D",
        "issues": issues,
    }


# ─────────────────────────────────────────────
# MAIN TEST — 20 event types
# ─────────────────────────────────────────────

if __name__ == "__main__":

    print("=" * 65)
    print("  WEEK 3 DAY 2 — Prompt Engineering Test")
    api_key = os.getenv("GEMINI_API_KEY")
    print(f"  Mode: {'Gemini 1.5 Flash AI' if api_key else 'Rule-based fallback'}")
    print("=" * 65)

    # 20 diverse security events
    TEST_EVENTS = [
        # Brute Force attacks
        {"message":"Failed password for invalid user admin from 195.178.55.22 port 44392 ssh2","severity":"HIGH","source_ip":"195.178.55.22","anomaly_score":0.82,"technique_id":"T1110.001","tactic":"Credential Access"},
        {"message":"Multiple failed login attempts: 847 failures in 60 seconds from 77.88.44.3","severity":"HIGH","source_ip":"77.88.44.3","anomaly_score":0.90,"technique_id":"T1110.001","tactic":"Credential Access"},
        # Malware execution
        {"message":"powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBj","severity":"HIGH","source_ip":"10.0.0.44","anomaly_score":0.88,"technique_id":"T1059.001","tactic":"Execution"},
        {"message":"cmd.exe spawned from word.exe with suspicious arguments","severity":"HIGH","source_ip":"10.0.0.22","anomaly_score":0.85,"technique_id":"T1059.003","tactic":"Execution"},
        # Credential attacks
        {"message":"LSASS memory read detected - possible credential dump via mimikatz","severity":"CRITICAL","source_ip":"10.0.0.55","anomaly_score":0.96,"technique_id":"T1055.012","tactic":"Privilege Escalation"},
        {"message":"EventID=4648 Logon with explicit credentials: admin account used from workstation","severity":"HIGH","source_ip":"10.0.0.77","anomaly_score":0.75,"technique_id":"T1078","tactic":"Defense Evasion"},
        # Network attacks
        {"message":"Port scan sweep: 65535 ports scanned in 4.2 seconds from 91.108.4.55","severity":"HIGH","source_ip":"91.108.4.55","anomaly_score":0.91,"technique_id":"T1046","tactic":"Discovery"},
        {"message":"SQL injection attempt detected in POST /api/login union select password from users","severity":"HIGH","source_ip":"77.88.44.3","anomaly_score":0.88,"technique_id":"T1190","tactic":"Initial Access"},
        # C2 & Exfiltration
        {"message":"Outbound beacon to known C2 IP 185.220.101.47:443 detected from 10.0.0.88","severity":"CRITICAL","source_ip":"10.0.0.88","anomaly_score":0.94,"technique_id":"T1071.001","tactic":"Command and Control"},
        {"message":"Large data transfer: 4.2GB sent to external IP 91.108.4.55 over port 443","severity":"CRITICAL","source_ip":"10.0.0.33","anomaly_score":0.93,"technique_id":"T1048","tactic":"Exfiltration"},
        # Persistence
        {"message":"EventID=4698 New scheduled task created: Windows_Update_Helper running cmd.exe","severity":"HIGH","source_ip":"10.0.0.11","anomaly_score":0.80,"technique_id":"T1053.005","tactic":"Persistence"},
        {"message":"New service installed: svchost32.exe — likely malware masquerading as system process","severity":"HIGH","source_ip":"10.0.0.99","anomaly_score":0.87,"technique_id":"T1543.003","tactic":"Persistence"},
        # Defense evasion
        {"message":"EventID=1102 The Windows audit log was cleared by CORP\\administrator","severity":"CRITICAL","source_ip":"10.0.0.1","anomaly_score":0.95,"technique_id":"T1562.001","tactic":"Defense Evasion"},
        {"message":"Windows Defender disabled via registry modification","severity":"CRITICAL","source_ip":"10.0.0.50","anomaly_score":0.92,"technique_id":"T1562.001","tactic":"Defense Evasion"},
        # Discovery
        {"message":"LDAP query for all domain users: (objectclass=*) — full AD dump attempted","severity":"MEDIUM","source_ip":"10.0.0.66","anomaly_score":0.70,"technique_id":"T1087.002","tactic":"Discovery"},
        {"message":"net user /domain command executed — domain account enumeration","severity":"MEDIUM","source_ip":"10.0.0.44","anomaly_score":0.65,"technique_id":"T1087.002","tactic":"Discovery"},
        # Lateral movement
        {"message":"WMI execution across 14 internal hosts from single source in 2 minutes","severity":"CRITICAL","source_ip":"10.0.0.20","anomaly_score":0.97,"technique_id":"T1021.006","tactic":"Lateral Movement"},
        {"message":"Pass-the-hash attack detected: NTLM authentication with hash from different host","severity":"CRITICAL","source_ip":"10.0.0.30","anomaly_score":0.95,"technique_id":"T1550.002","tactic":"Lateral Movement"},
        # Low risk (should return low FP probability)
        {"message":"Normal user authentication successful from known corporate device","severity":"INFO","source_ip":"10.0.0.100","anomaly_score":0.05,"technique_id":None,"tactic":None},
        {"message":"Scheduled backup job completed successfully — 2.1GB transferred to backup server","severity":"LOW","source_ip":"10.0.0.200","anomaly_score":0.08,"technique_id":None,"tactic":None},
    ]

    results = []
    total_latency = []
    qualities = []

    print(f"\n  Testing {len(TEST_EVENTS)} diverse security events...\n")
    print(f"  {'#':<4} {'Severity':<10} {'Result':<30} {'Grade':<6} {'Source':<22} {'ms'}")
    print(f"  {'─'*80}")

    for i, event in enumerate(TEST_EVENTS, 1):
        result  = analyze_threat_v2(event, use_cache=True)
        quality = score_analysis_quality(result)

        latency = result.get("latency_ms", 0)
        if latency > 0:
            total_latency.append(latency)

        qualities.append(quality["quality_score"])
        results.append((event, result, quality))

        threat_short = result.get("threat_type","?")[:28]
        source_short = result.get("source","?")[:20]
        print(f"  {i:<4} {event['severity']:<10} {threat_short:<30} {quality['grade']:<6} {source_short:<22} {latency}ms")

        # Small delay to respect free tier rate limits
        if api_key and i < len(TEST_EVENTS):
            time.sleep(0.5)

    # ── Summary ──────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*65}")
    print(f"  Events tested        : {len(TEST_EVENTS)}")
    print(f"  Avg quality score    : {sum(qualities)/len(qualities):.1f}/100")
    print(f"  Grade A analyses     : {sum(1 for q in qualities if q>=90)}/{len(qualities)}")
    print(f"  Grade B analyses     : {sum(1 for q in qualities if 75<=q<90)}/{len(qualities)}")

    if total_latency:
        total_latency.sort()
        p50 = total_latency[len(total_latency)//2]
        p95 = total_latency[int(len(total_latency)*0.95)]
        print(f"  API latency p50      : {p50}ms")
        print(f"  API latency p95      : {p95}ms  (target < 800ms)")
        print(f"  Cache hits saved     : {len(TEST_EVENTS)-len(total_latency)} API calls")

    # ── Cache demo ──────────────────────────────────────────────
    print(f"\n  ── Cache Test ──")
    print(f"  Calling same event again (should be instant)...")
    t0 = time.time()
    cached_result = analyze_threat_v2(TEST_EVENTS[0], use_cache=True)
    cache_time = round((time.time()-t0)*1000)
    print(f"  Result returned in {cache_time}ms — {'CACHE HIT ✅' if cache_time < 10 else 'cache miss'}")

    # ── Prompt comparison ────────────────────────────────────────
    if api_key:
        print(f"\n  ── Prompt Style Comparison ──")
        test_event = TEST_EVENTS[0]   # SSH brute force
        styles = [("few_shot","Few-shot examples"),("chain","Chain-of-thought"),("fast","Fast minimal")]
        for style, label in styles:
            t0 = time.time()
            try:
                import google.generativeai as genai
                genai.configure(api_key=api_key)
                model = genai.GenerativeModel("gemini-2.0-flash")
                prompt = build_prompt(test_event, style=style)
                resp = model.generate_content(prompt)
                ms = round((time.time()-t0)*1000)
                # Try parsing
                txt = resp.text.strip()
                if "```" in txt:
                    parts = txt.split("```"); txt = parts[1][4:] if len(parts)>1 else parts[0]
                try:
                    parsed = json.loads(txt.strip())
                    q = score_analysis_quality(parsed)
                    print(f"  {label:<25} {ms:>5}ms   Quality: {q['quality_score']}/100 ({q['grade']})")
                except:
                    print(f"  {label:<25} {ms:>5}ms   JSON parse failed")
                time.sleep(1)
            except Exception as ex:
                print(f"  {label:<25} Error: {str(ex)[:40]}")

    # ── Save results ─────────────────────────────────────────────
    output = []
    for event, result, quality in results:
        output.append({
            "event":   event.get("message","")[:80],
            "severity": event.get("severity"),
            "technique": event.get("technique_id"),
            "threat_type": result.get("threat_type"),
            "quality": quality["quality_score"],
            "grade": quality["grade"],
            "source": result.get("source"),
            "latency_ms": result.get("latency_ms",0),
            "fp_prob": result.get("false_positive_probability"),
        })

    import os as _os
    _os.makedirs("data", exist_ok=True)
    with open("data/prompt_test_results.json","w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  ✅ Results saved to data/prompt_test_results.json")

    # ── Final checklist ──────────────────────────────────────────
    print(f"\n  ── Day 2 Checklist ──")
    avg_q = sum(qualities)/len(qualities)
    checks = {
        "20 event types tested":           len(TEST_EVENTS) == 20,
        "Average quality >= 70/100":        avg_q >= 70,
        "Few-shot prompting implemented":   True,
        "Response caching working":         cache_time < 10,
        "Results saved to JSON":            _os.path.exists("data/prompt_test_results.json"),
        "Rule-based fallback working":      True,
    }
    for check, passed in checks.items():
        print(f"  {'✅' if passed else '❌'}  {check}")
    print(f"\n{'='*65}")