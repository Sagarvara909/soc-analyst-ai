"""
load_real_logs.py
==================
Loads real Windows Event Logs into the MAIN database
so they appear live on the dashboard.

Run ONCE after exporting logs:
  1. Export: wevtutil qe Security /c:500 /f:text > logs/real_windows_security.log
  2. Load:   python load_real_logs.py
  3. Start:  uvicorn api:app --reload --port 8000
  4. Open:   dashboard.html
"""

import re, os, sys
from collections import Counter

# ── Windows wevtutil parser ───────────────────────────────────────

SEV_MAP = {
    "4624":"LOW","4625":"HIGH","4634":"LOW","4647":"LOW",
    "4648":"HIGH","4656":"MEDIUM","4663":"MEDIUM","4672":"MEDIUM",
    "4688":"MEDIUM","4689":"LOW","4698":"HIGH","4700":"HIGH",
    "4702":"MEDIUM","4720":"HIGH","4722":"MEDIUM","4724":"MEDIUM",
    "4725":"MEDIUM","4726":"HIGH","4728":"HIGH","4732":"MEDIUM",
    "4740":"HIGH","4756":"HIGH","4767":"MEDIUM","4769":"MEDIUM",
    "4776":"MEDIUM","4798":"MEDIUM","4799":"MEDIUM",
    "7034":"HIGH","7036":"LOW","7045":"HIGH",
    "1102":"CRITICAL","1100":"HIGH",
}

MSG_MAP = {
    "4624":"Successful logon",
    "4625":"Failed logon attempt",
    "4634":"User logoff",
    "4648":"Logon with explicit credentials",
    "4672":"Special privileges assigned",
    "4688":"New process created",
    "4698":"Scheduled task created",
    "4720":"New user account created",
    "4726":"User account deleted",
    "4728":"Member added to security group",
    "4740":"User account locked out",
    "4769":"Kerberos service ticket requested",
    "4776":"NTLM credential validation",
    "7034":"Service crashed unexpectedly",
    "7045":"New service installed",
    "1102":"Security audit log cleared",
}

def parse_wevtutil(filepath):
    events = []
    if not os.path.exists(filepath):
        print(f"  [SKIP] Not found: {filepath}")
        return events

    with open(filepath,"r",encoding="utf-8",errors="replace") as f:
        content = f.read()

    raw_events = re.split(r'Event\[\d+\]:', content)

    for raw in raw_events:
        if not raw.strip(): continue
        try:
            eid_m  = re.search(r'Event ID:\s*(\d+)', raw)
            date_m = re.search(r'Date:\s*(\S+)', raw)
            ip_m   = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', raw)
            user_m = re.search(r'Account Name:\s*(\S+)', raw)
            comp_m = re.search(r'Computer:\s*(\S+)', raw)
            desc_m = re.search(r'Description:(.*?)(?=\n\n|\Z)', raw, re.DOTALL)
            if not eid_m: continue

            eid  = eid_m.group(1)
            ts   = date_m.group(1) if date_m else "unknown"
            ip   = ip_m.group(1)   if ip_m   else "127.0.0.1"
            user = user_m.group(1) if user_m else ""
            comp = comp_m.group(1) if comp_m else "local"
            desc = desc_m.group(1).strip()[:150] if desc_m else ""
            sev  = SEV_MAP.get(eid, "INFO")

            # Build readable message
            base_msg = MSG_MAP.get(eid, f"Windows Event {eid}")
            msg = f"EventID={eid}: {base_msg}"
            if user and user not in ("-",""):
                msg += f" | User: {user}"
            if ip and ip != "127.0.0.1":
                msg += f" | From: {ip}"
            if comp:
                msg += f" | Host: {comp}"

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

    return events


# ── Main ─────────────────────────────────────────────────────────

if __name__ == "__main__":

    print("=" * 65)
    print("  LOAD REAL WINDOWS LOGS → DASHBOARD")
    print("=" * 65)

    # Step 1: Parse all real log files
    all_events = []
    files = [
        "logs/real_windows_security.log",
        "logs/real_windows_system.log",
        "logs/real_windows_app.log",
        # Add more files here if you have them
    ]

    print("\n  Parsing log files...")
    for f in files:
        evts = parse_wevtutil(f)
        if evts:
            all_events.extend(evts)
            print(f"  ✅ Loaded {len(evts):>4} events from {f}")

    if not all_events:
        print("\n  ❌ No log files found!")
        print("  Run this first (as Administrator):")
        print("  wevtutil qe Security /c:500 /f:text > logs\\real_windows_security.log")
        sys.exit(1)

    print(f"\n  Total real events: {len(all_events)}")

    # Show what we found
    sevs = Counter(e["severity"] for e in all_events)
    print(f"\n  Severity breakdown:")
    for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        n = sevs.get(s,0)
        if n > 0:
            print(f"    {s:<10} {n:>4} events")

    # Step 2: Run feature engineering
    print(f"\n  Running ML feature engineering...")
    from features import build_features, get_ml_columns
    df = build_features(all_events)
    print(f"  Built {len(df)} rows x {len(df.columns)} columns")

    # Step 3: Run ML ensemble detection
    print(f"\n  Running ML ensemble detection...")
    from ensemble_detector import run_ensemble, evaluate
    result = run_ensemble(df, contamination=0.05)
    anomalies = result["is_anomaly"].sum()
    m = evaluate(result)
    print(f"  Anomalies detected: {anomalies}/{len(all_events)}")
    print(f"  Precision: {m['precision']} | FP Rate: {m['fp_rate']}")

    # Step 4: MITRE classification
    print(f"\n  Running MITRE ATT&CK classification...")
    from mitre_classifier import classify_events, TECHNIQUES
    clss   = classify_events(all_events)
    tagged = sum(1 for c in clss if c["technique_id"])
    print(f"  Tagged: {tagged}/{len(clss)} ({tagged/len(clss)*100:.1f}%)")

    tech_counts = Counter(c["technique_id"] for c in clss if c["technique_id"])
    if tech_counts:
        print(f"\n  Techniques found in YOUR logs:")
        for tid, cnt in tech_counts.most_common(6):
            name = TECHNIQUES.get(tid,{}).get("name","Unknown")
            print(f"    {tid:<15} {cnt:>4}x  {name}")

    # Step 5: Store in MAIN database
    print(f"\n  Storing in main database...")
    from db import init_db, insert_events_bulk, get_metrics
    DB = "data/soc_analyst.db"

    # Remove old DB and rebuild with real logs
    if os.path.exists(DB):
        os.remove(DB)
        print(f"  Old database cleared")

    init_db(db_path=DB)

    dets  = result[["anomaly_score","is_anomaly","confidence","detector_votes"]].to_dict(orient="records")
    count = insert_events_bulk(all_events, dets, clss, db_path=DB)
    print(f"  ✅ Inserted {count} real events into database")

    # Get final metrics
    metrics = get_metrics(db_path=DB)
    print(f"\n  ── Dashboard will now show ──")
    print(f"  Total Events   : {metrics['total_events']}")
    print(f"  Anomalies      : {metrics['total_anomalies']}")
    print(f"  Critical       : {metrics['critical_events']}")
    print(f"  High           : {metrics['high_events']}")
    print(f"  MITRE Tagged   : {metrics['mitre_tagged']} ({metrics['mitre_tag_rate']}%)")
    print(f"  Top Attacker   : {metrics['top_attacker_ip']}")
    print(f"  Top Technique  : {metrics['top_technique']}")

    # Show top suspicious events
    merged = sorted(
        zip(result["anomaly_score"], result["is_anomaly"], all_events, clss),
        key=lambda x: -float(x[0])
    )

    print(f"\n  ── Top 5 Suspicious Events on YOUR machine ──")
    shown = 0
    for score, is_a, event, cls in merged:
        score = float(score)
        if score < 0.1: continue
        icon = "🚨" if is_a else "⚠️ "
        tid  = cls["technique_id"] or "NONE"
        print(f"  {icon} score={score:.3f} [{event['severity']:<8}] {tid:<12} {event['message'][:50]}")
        shown += 1
        if shown >= 5: break

    print(f"\n{'='*65}")
    print(f"  ✅ DONE! Real logs loaded into dashboard.")
    print(f"\n  Now run:")
    print(f"    uvicorn api:app --reload --port 8000")
    print(f"  Then open dashboard.html in Chrome")
    print(f"{'='*65}")