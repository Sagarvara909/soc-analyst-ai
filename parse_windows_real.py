"""
parse_windows_real.py — Parse real Windows Event Logs
======================================================
Reads wevtutil text export and runs full ML + MITRE pipeline.

Export logs first (run as Administrator):
  wevtutil qe Security /c:200 /f:text > logs/real_windows_security.log
  wevtutil qe System   /c:200 /f:text > logs/real_windows_system.log

Then run:
  python parse_windows_real.py
"""

import re, os, sys
from datetime import datetime

# ── Parse wevtutil text format ────────────────────────────────────

def parse_wevtutil_file(filepath):
    """Parse wevtutil /f:text output into standard event dicts."""
    events = []
    if not os.path.exists(filepath):
        print(f"  File not found: {filepath}")
        return events

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # Split into individual events
    raw_events = re.split(r'Event\[\d+\]:', content)

    # Severity mapping for Windows Event IDs
    SEV_MAP = {
        "4624": "LOW",      # Successful logon
        "4625": "HIGH",     # Failed logon
        "4634": "LOW",      # Logoff
        "4648": "HIGH",     # Logon with explicit credentials
        "4656": "MEDIUM",   # Handle to object requested
        "4663": "MEDIUM",   # Object access attempt
        "4688": "MEDIUM",   # New process created
        "4698": "HIGH",     # Scheduled task created
        "4700": "HIGH",     # Scheduled task enabled
        "4702": "MEDIUM",   # Scheduled task updated
        "4720": "HIGH",     # User account created
        "4722": "MEDIUM",   # User account enabled
        "4725": "MEDIUM",   # User account disabled
        "4728": "HIGH",     # Member added to security group
        "4732": "MEDIUM",   # Member added to local group
        "4756": "HIGH",     # Member added to universal group
        "4769": "MEDIUM",   # Kerberos ticket requested
        "4776": "MEDIUM",   # Credential validation attempt
        "4798": "MEDIUM",   # User local group membership enumerated
        "4799": "MEDIUM",   # Group membership enumerated
        "7034": "HIGH",     # Service crashed
        "7036": "LOW",      # Service changed state
        "7045": "HIGH",     # New service installed
        "1102": "CRITICAL", # Audit log cleared
    }

    for raw in raw_events:
        if not raw.strip():
            continue

        try:
            # Extract fields using regex
            event_id_m  = re.search(r'Event ID:\s*(\d+)', raw)
            date_m      = re.search(r'Date:\s*(\S+)', raw)
            source_m    = re.search(r'Source:\s*(.+)', raw)
            computer_m  = re.search(r'Computer:\s*(\S+)', raw)
            desc_m      = re.search(r'Description:(.*?)(?=\n\n|\Z)', raw, re.DOTALL)
            ip_m        = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', raw)
            user_m      = re.search(r'Account Name:\s*(\S+)', raw)

            if not event_id_m:
                continue

            eid     = event_id_m.group(1)
            ts      = date_m.group(1) if date_m else "unknown"
            source  = source_m.group(1).strip() if source_m else "Windows"
            ip      = ip_m.group(1) if ip_m else "unknown"
            user    = user_m.group(1) if user_m else ""
            desc    = desc_m.group(1).strip()[:200] if desc_m else f"EventID {eid}"
            sev     = SEV_MAP.get(eid, "INFO")

            # Build meaningful message
            msg = f"EventID={eid}"
            if user and user not in ("-", ""):
                msg += f" User={user}"
            if ip and ip != "unknown":
                msg += f" Source={ip}"
            msg += f" {source}: {desc[:100]}"

            events.append({
                "timestamp": ts,
                "severity":  sev,
                "source_ip": ip,
                "message":   msg,
                "raw":       raw.strip()[:300],
                "format":    "windows_event",
            })

        except Exception:
            continue

    print(f"  Parsed {len(events)} events from {filepath}")
    return events


# ── Main pipeline ─────────────────────────────────────────────────

if __name__ == "__main__":

    print("=" * 65)
    print("  REAL WINDOWS LOG ANALYSIS")
    print("=" * 65)

    # Load real Windows logs
    all_events = []
    log_files  = [
        "logs/real_windows_security.log",
        "logs/real_windows_system.log",
        "logs/real_windows_app.log",
    ]

    print("\n  Loading real Windows logs...")
    for path in log_files:
        if os.path.exists(path):
            events = parse_wevtutil_file(path)
            all_events.extend(events)
        else:
            print(f"  Skipping {path} (not found)")

    if not all_events:
        print("\n  No log files found.")
        print("  Run this as Administrator first:")
        print("  wevtutil qe Security /c:200 /f:text > logs/real_windows_security.log")
        sys.exit(1)

    print(f"\n  Total events loaded: {len(all_events)}")

    # Show severity breakdown
    from collections import Counter
    sevs = Counter(e["severity"] for e in all_events)
    print(f"\n  Severity breakdown:")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        count = sevs.get(sev, 0)
        bar   = "█" * (count // 2)
        print(f"    {sev:<10} {count:>4}  {bar}")

    # Run MITRE classification
    print(f"\n  Running MITRE ATT&CK classification...")
    from mitre_classifier import classify_events
    clss   = classify_events(all_events)
    tagged = sum(1 for c in clss if c["technique_id"])
    print(f"  Tagged: {tagged}/{len(clss)} ({tagged/len(clss)*100:.1f}%)")

    # Show technique breakdown
    tech_counts = Counter(c["technique_id"] for c in clss if c["technique_id"])
    if tech_counts:
        print(f"\n  Techniques detected:")
        for tid, cnt in tech_counts.most_common(8):
            from mitre_classifier import TECHNIQUES
            name = TECHNIQUES.get(tid,{}).get("name","Unknown")
            print(f"    {tid:<15} {cnt:>4}x  {name}")

    # Run ML detection
    print(f"\n  Running ML anomaly detection...")
    from features import build_features
    from ensemble_detector import run_ensemble
    df     = build_features(all_events)
    result = run_ensemble(df, contamination=0.05)
    anomalies = result["is_anomaly"].sum()
    print(f"  Anomalies detected: {anomalies}/{len(all_events)}")

    # Show top suspicious events
    print(f"\n  ── Top 10 Suspicious Events ──")
    merged = []
    for i, (event, cls) in enumerate(zip(all_events, clss)):
        score = float(result["anomaly_score"].iloc[i])
        is_a  = bool(result["is_anomaly"].iloc[i])
        merged.append((score, is_a, event, cls))

    merged.sort(key=lambda x: -x[0])
    found = 0
    for score, is_a, event, cls in merged[:15]:
        if score > 0.1:
            icon = "🚨" if is_a else "⚠️ "
            tid  = cls["technique_id"] or "NONE"
            msg  = event["message"][:55]
            print(f"  {icon} score={score:.3f} [{event['severity']:<8}] {tid:<12} {msg}")
            found += 1
            if found >= 10: break

    # Store in database
    print(f"\n  Storing in database...")
    from db import init_db, insert_events_bulk, get_metrics
    import os as _os
    REAL_DB = "data/real_windows_analysis.db"
    if _os.path.exists(REAL_DB):
        _os.remove(REAL_DB)
    init_db(db_path=REAL_DB)
    dets  = result[["anomaly_score","is_anomaly","confidence","detector_votes"]].to_dict(orient="records")
    count = insert_events_bulk(all_events, dets, clss, db_path=REAL_DB)
    m     = get_metrics(db_path=REAL_DB)
    print(f"  Stored {count} events in {REAL_DB}")
    print(f"  Anomalies: {m['total_anomalies']} | MITRE tagged: {m['mitre_tagged']} ({m['mitre_tag_rate']}%)")

    # Run AI analysis on top suspicious event
    if merged and merged[0][0] > 0.1:
        print(f"\n  ── Gemini AI Analysis of Top Suspicious Event ──")
        top_event = merged[0][2]
        top_cls   = merged[0][3]
        from ai_analyzer import analyze_threat
        ai_result = analyze_threat({
            **top_event,
            "technique_id":  top_cls["technique_id"],
            "tactic":        top_cls["tactic"],
            "anomaly_score": merged[0][0],
        })
        print(f"  Event   : {top_event['message'][:60]}")
        print(f"  Threat  : {ai_result['threat_type']}")
        print(f"  Explain : {ai_result['explanation'][:80]}...")
        print(f"  Action  : {ai_result['recommendations'][0]}")
        print(f"  Source  : {ai_result['source']}")

    print(f"\n{'='*65}")
    print(f"  Analysis complete!")
    print(f"  Results saved to: {REAL_DB}")
    print(f"  To view in dashboard, restart API with this DB path")
    print(f"{'='*65}")