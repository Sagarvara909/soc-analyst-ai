"""
integration_test.py — Week 3 Day 5
=====================================
Runs all backend components together for 5 minutes.
Measures: events/sec, AI latency p50/p95/p99, correlation speed.
Saves full report to data/integration_report.json

Run: python integration_test.py
(Make sure uvicorn is NOT running — this tests directly, no HTTP)
"""

import time, json, os, statistics
from datetime import datetime

print("=" * 65)
print("  WEEK 3 DAY 5 — Full Integration Test")
print(f"  Started: {datetime.now().strftime('%H:%M:%S')}")
print("=" * 65)

results = {
    "started_at":    datetime.now().isoformat(),
    "components":    {},
    "performance":   {},
    "bottlenecks":   [],
    "passed":        [],
    "failed":        [],
}

def run_run_test(name):
    """Simple test runner."""
    def decorator(fn):
        print(f"\n  ── {name} ──")
        t0 = time.time()
        try:
            data = fn()
            ms   = round((time.time() - t0) * 1000)
            print(f"  ✅ PASS ({ms}ms)")
            results["passed"].append(name)
            results["components"][name] = {"status": "pass", "ms": ms, "data": data}
            return data
        except Exception as ex:
            ms = round((time.time() - t0) * 1000)
            print(f"  ❌ FAIL — {str(ex)[:80]}")
            results["failed"].append(name)
            results["components"][name] = {"status": "fail", "error": str(ex)[:100]}
            return None
    return decorator


# ── 1. Log Parser ────────────────────────────────────────────────
@run_run_test("Log Parser")
def test_parser():
    from log_parser import parse_log_line, parse_log_file
    lines = [
        "Jan 15 14:32:01 webserver sshd[1234]: Failed password for invalid user admin from 195.178.55.22 port 44392 ssh2",
        '195.178.55.22 - - [15/Jan/2026:14:32:01 +0000] "GET /admin HTTP/1.1" 403 512',
        "2026-01-15 14:32:01 EventID=4625 User=CORP\\jsmith Source=192.168.1.55 Message=An account failed to log on",
        '{"timestamp":"2026-01-15T14:32:01Z","severity":"HIGH","source_ip":"77.88.44.3","message":"SQL injection attempt"}',
    ]
    parsed = [parse_log_line(l) for l in lines]
    assert all(p is not None for p in parsed), "Some lines failed to parse"
    assert all(p.get("source_ip") for p in parsed), "Missing source_ip"
    formats = [p["format"] for p in parsed]
    print(f"  Formats: {formats}")

    # Speed test: parse 450 events
    t0 = time.time()
    all_events = []
    for path in ["logs/syslog_sample.log","logs/apache_access.log","logs/windows_events.log","logs/json_structured.log"]:
        if os.path.exists(path):
            all_events.extend(parse_log_file(path))
    parse_ms = round((time.time()-t0)*1000)
    rate = round(len(all_events) / max(parse_ms/1000, 0.001))
    print(f"  Parsed {len(all_events)} events in {parse_ms}ms = {rate} events/sec")
    results["performance"]["parse_events_per_sec"] = rate
    return {"events_loaded": len(all_events), "formats": 4, "parse_rate": rate}


# ── 2. Feature Engineering ───────────────────────────────────────
@run_test("Feature Engineering")
def test_features():
    from log_parser import parse_log_file
    from features import build_features, get_ml_columns
    all_events = []
    for path in ["logs/syslog_sample.log","logs/apache_access.log","logs/windows_events.log","logs/json_structured.log"]:
        if os.path.exists(path): all_events.extend(parse_log_file(path))

    t0 = time.time()
    df = build_features(all_events)
    ms = round((time.time()-t0)*1000)
    ml_cols = get_ml_columns(df)
    assert len(df) == len(all_events), "Row count mismatch"
    assert len(ml_cols) >= 10, f"Only {len(ml_cols)} ML columns"
    print(f"  {len(df)} rows × {len(df.columns)} columns in {ms}ms")
    print(f"  ML columns: {len(ml_cols)}")
    results["performance"]["feature_eng_ms"] = ms
    return {"rows": len(df), "ml_cols": len(ml_cols)}


# ── 3. ML Ensemble ───────────────────────────────────────────────
@run_test("ML Ensemble Detector")
def test_ml():
    from log_parser import parse_log_file
    from features import build_features
    from ensemble_detector import run_ensemble, evaluate
    all_events = []
    for path in ["logs/syslog_sample.log","logs/apache_access.log","logs/windows_events.log","logs/json_structured.log"]:
        if os.path.exists(path): all_events.extend(parse_log_file(path))
    df = build_features(all_events)

    t0 = time.time()
    result = run_ensemble(df, contamination=0.1)
    ms = round((time.time()-t0)*1000)

    m = evaluate(result)
    anomalies = result["is_anomaly"].sum()
    assert anomalies > 0, "No anomalies detected"
    assert 0 <= m["precision"] <= 1, "Invalid precision"
    print(f"  Anomalies: {anomalies}/{len(df)} | Precision: {m['precision']} | FP Rate: {m['fp_rate']}")
    print(f"  Training time: {ms}ms")
    results["performance"]["ml_training_ms"] = ms
    results["performance"]["anomaly_count"]  = int(anomalies)
    results["performance"]["precision"]      = m["precision"]
    results["performance"]["fp_rate"]        = m["fp_rate"]
    return m


# ── 4. MITRE Classifier ──────────────────────────────────────────
@run_test("MITRE ATT&CK Classifier")
def test_mitre():
    from mitre_classifier import classify_events, classify_event
    from log_parser import parse_log_file
    all_events = []
    for path in ["logs/syslog_sample.log","logs/apache_access.log","logs/windows_events.log","logs/json_structured.log"]:
        if os.path.exists(path): all_events.extend(parse_log_file(path))

    t0 = time.time()
    clss = classify_events(all_events)
    ms   = round((time.time()-t0)*1000)

    tagged    = sum(1 for c in clss if c["technique_id"])
    tag_rate  = round(tagged / len(clss) * 100, 1)
    assert tagged > 0, "No events tagged"

    # Test known events
    known_tests = [
        ({"message":"Failed password for invalid user admin","raw":""}, "T1110.001"),
        ({"message":"SQL injection attempt union select","raw":""},     "T1190"),
        ({"message":"LSASS memory read credential dump","raw":""},      "T1055.012"),
    ]
    correct = sum(1 for e, expected in known_tests if classify_event(e)["technique_id"] == expected)
    print(f"  Tagged: {tagged}/{len(clss)} ({tag_rate}%) in {ms}ms")
    print(f"  Known event accuracy: {correct}/{len(known_tests)}")
    results["performance"]["mitre_tag_rate"]   = tag_rate
    results["performance"]["mitre_accuracy"]   = f"{correct}/{len(known_tests)}"
    return {"tag_rate": tag_rate, "tagged": tagged}


# ── 5. Database ──────────────────────────────────────────────────
@run_test("SQLite Database")
def test_db():
    from db import init_db, get_recent_events, get_metrics, get_anomalies, get_top_ips
    if not os.path.exists("data/soc_analyst.db"):
        from log_parser import parse_log_file
        from features import build_features
        from ensemble_detector import run_ensemble
        from mitre_classifier import classify_events
        from db import insert_events_bulk
        init_db()
        all_events = []
        for path in ["logs/syslog_sample.log","logs/apache_access.log","logs/windows_events.log","logs/json_structured.log"]:
            if os.path.exists(path): all_events.extend(parse_log_file(path))
        df   = build_features(all_events)
        res  = run_ensemble(df)
        clss = classify_events(all_events)
        dets = res[["anomaly_score","is_anomaly","confidence","detector_votes"]].to_dict(orient="records")
        insert_events_bulk(all_events, dets, clss)

    t0     = time.time()
    recent = get_recent_events(limit=50)
    m      = get_metrics()
    anoms  = get_anomalies(limit=20)
    ips    = get_top_ips(limit=5)
    ms     = round((time.time()-t0)*1000)

    assert len(recent) > 0,        "No recent events returned"
    assert m["total_events"] > 0,  "No events in metrics"
    assert m["mitre_tagged"] > 0,  "No MITRE-tagged events"

    print(f"  Total events: {m['total_events']} | Anomalies: {m['total_anomalies']}")
    print(f"  MITRE tagged: {m['mitre_tagged']} ({m['mitre_tag_rate']}%)")
    print(f"  Top attacker: {m['top_attacker_ip']} | Top technique: {m['top_technique']}")
    print(f"  Query time: {ms}ms")
    results["performance"]["db_query_ms"] = ms
    return m


# ── 6. Correlation Engine ────────────────────────────────────────
@run_test("Correlation Engine")
def test_correlation():
    from db import get_recent_events
    from correlation_engine import correlate_events, get_graph_json
    events = get_recent_events(limit=200)

    t0 = time.time()
    G, groups, chains = correlate_events(events)
    ms = round((time.time()-t0)*1000)

    assert G.number_of_nodes() > 0, "Empty graph"
    assert G.number_of_edges() > 0, "No edges in graph"

    # Graph JSON
    t1      = time.time()
    gj      = get_graph_json(events)
    json_ms = round((time.time()-t1)*1000)

    print(f"  Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges in {ms}ms")
    print(f"  Correlated groups: {len(groups)}")
    print(f"  Kill chains detected: {len(chains)}")
    print(f"  Graph JSON: {ms+json_ms}ms total")
    for kc in chains[:2]:
        print(f"  🚨 {kc['chain_name']}")
    results["performance"]["correlation_ms"]  = ms
    results["performance"]["graph_nodes"]     = G.number_of_nodes()
    results["performance"]["graph_edges"]     = G.number_of_edges()
    results["performance"]["kill_chains"]     = len(chains)
    return {"groups": len(groups), "chains": len(chains)}


# ── 7. AI Analyzer ───────────────────────────────────────────────
@run_test("AI Analyzer (Gemini)")
def test_ai():
    from ai_analyzer import analyze_threat
    test_events = [
        {"message":"Failed password for invalid user admin from 195.178.55.22","severity":"HIGH","source_ip":"195.178.55.22","anomaly_score":0.82,"technique_id":"T1110.001","tactic":"Credential Access"},
        {"message":"LSASS memory read detected","severity":"CRITICAL","source_ip":"10.0.0.55","anomaly_score":0.96,"technique_id":"T1055.012","tactic":"Privilege Escalation"},
        {"message":"SQL injection attempt union select","severity":"HIGH","source_ip":"77.88.44.3","anomaly_score":0.88,"technique_id":"T1190","tactic":"Initial Access"},
    ]
    latencies = []
    for e in test_events:
        t0     = time.time()
        result = analyze_threat(e)
        ms     = round((time.time()-t0)*1000)
        latencies.append(ms)
        assert result.get("threat_type"),      "Missing threat_type"
        assert result.get("recommendations"),  "Missing recommendations"
        print(f"  [{e['severity']}] {result['threat_type'][:35]:<35} {ms}ms  [{result['source'][:20]}]")

    # Cache test
    t0 = time.time()
    analyze_threat(test_events[0])
    cache_ms = round((time.time()-t0)*1000)
    print(f"  Cache test: {cache_ms}ms ({'HIT ✅' if cache_ms < 10 else 'miss'})")

    latencies_sorted = sorted(latencies)
    p50 = latencies_sorted[len(latencies_sorted)//2]
    p95 = latencies_sorted[min(int(len(latencies_sorted)*0.95), len(latencies_sorted)-1)]
    print(f"  Latency — p50: {p50}ms | p95: {p95}ms | target: <800ms")
    results["performance"]["ai_latency_p50"] = p50
    results["performance"]["ai_latency_p95"] = p95
    results["performance"]["ai_cache_ms"]    = cache_ms
    if p95 > 800:
        results["bottlenecks"].append(f"AI latency p95={p95}ms exceeds 800ms target")
    return {"p50": p50, "p95": p95}


# ── 8. End-to-End Pipeline ───────────────────────────────────────
@run_test("End-to-End Pipeline Speed")
def test_e2e():
    from log_parser import parse_log_file
    from features import build_features, get_ml_columns
    from ensemble_detector import run_ensemble
    from mitre_classifier import classify_events
    from correlation_engine import correlate_events
    from db import get_recent_events

    t0 = time.time()
    # Step 1: parse
    all_events = []
    for path in ["logs/syslog_sample.log","logs/apache_access.log","logs/windows_events.log","logs/json_structured.log"]:
        if os.path.exists(path): all_events.extend(parse_log_file(path))
    t_parse = time.time()

    # Step 2: features
    df = build_features(all_events)
    t_feat = time.time()

    # Step 3: ML
    result = run_ensemble(df)
    t_ml = time.time()

    # Step 4: classify
    clss = classify_events(all_events)
    t_cls = time.time()

    # Step 5: correlate
    events_for_corr = get_recent_events(limit=100)
    _, groups, chains = correlate_events(events_for_corr)
    t_corr = time.time()

    total_ms = round((t_corr - t0) * 1000)

    breakdown = {
        "parse_ms":    round((t_parse - t0)*1000),
        "features_ms": round((t_feat - t_parse)*1000),
        "ml_ms":       round((t_ml - t_feat)*1000),
        "classify_ms": round((t_cls - t_ml)*1000),
        "correlate_ms":round((t_corr - t_cls)*1000),
        "total_ms":    total_ms,
    }

    print(f"  Parse:      {breakdown['parse_ms']}ms")
    print(f"  Features:   {breakdown['features_ms']}ms")
    print(f"  ML:         {breakdown['ml_ms']}ms")
    print(f"  Classify:   {breakdown['classify_ms']}ms")
    print(f"  Correlate:  {breakdown['correlate_ms']}ms")
    print(f"  ─────────────────────────")
    print(f"  TOTAL:      {total_ms}ms for {len(all_events)} events")
    print(f"  Rate:       {round(len(all_events)/(total_ms/1000))} events/sec end-to-end")

    results["performance"]["e2e_total_ms"]   = total_ms
    results["performance"]["e2e_breakdown"]  = breakdown
    results["performance"]["e2e_events_per_sec"] = round(len(all_events)/(total_ms/1000))
    return breakdown


# ── Summary ──────────────────────────────────────────────────────

print(f"\n{'='*65}")
print(f"  INTEGRATION TEST RESULTS")
print(f"{'='*65}")

total    = len(results["passed"]) + len(results["failed"])
passed   = len(results["passed"])
failed   = len(results["failed"])

print(f"\n  Tests passed : {passed}/{total}")
print(f"  Tests failed : {failed}/{total}")

if results["bottlenecks"]:
    print(f"\n  Bottlenecks found:")
    for b in results["bottlenecks"]:
        print(f"    ⚠️  {b}")

print(f"\n  ── Performance Summary ──")
perf = results["performance"]
metrics_display = [
    ("Parse speed",          f"{perf.get('parse_events_per_sec','N/A')} events/sec"),
    ("ML training",          f"{perf.get('ml_training_ms','N/A')}ms for 450 events"),
    ("MITRE tag rate",       f"{perf.get('mitre_tag_rate','N/A')}%"),
    ("DB query",             f"{perf.get('db_query_ms','N/A')}ms"),
    ("Correlation",          f"{perf.get('correlation_ms','N/A')}ms"),
    ("Kill chains detected", f"{perf.get('kill_chains','N/A')}"),
    ("AI latency p50",       f"{perf.get('ai_latency_p50','N/A')}ms"),
    ("AI latency p95",       f"{perf.get('ai_latency_p95','N/A')}ms"),
    ("AI cache",             f"{perf.get('ai_cache_ms','N/A')}ms"),
    ("E2E pipeline",         f"{perf.get('e2e_total_ms','N/A')}ms total"),
    ("E2E rate",             f"{perf.get('e2e_events_per_sec','N/A')} events/sec"),
    ("ML precision",         f"{perf.get('precision','N/A')}"),
    ("ML FP rate",           f"{perf.get('fp_rate','N/A')}"),
]
for label, value in metrics_display:
    print(f"  {label:<28} {value}")

# Save results
results["finished_at"] = datetime.now().isoformat()
results["summary"] = {"passed": passed, "failed": failed, "total": total}
os.makedirs("data", exist_ok=True)
with open("data/integration_report.json", "w") as f:
    json.dump(results, f, indent=2, default=str)
print(f"\n  ✅ Full report saved to data/integration_report.json")

print(f"\n  ── Week 3 Final Checklist ──")
checks = {
    "Log parser working":        "Log Parser" in results["passed"],
    "Feature engineering":       "Feature Engineering" in results["passed"],
    "ML ensemble detector":      "ML Ensemble Detector" in results["passed"],
    "MITRE classifier":          "MITRE ATT&CK Classifier" in results["passed"],
    "SQLite database":           "SQLite Database" in results["passed"],
    "Correlation engine":        "Correlation Engine" in results["passed"],
    "AI analyzer":               "AI Analyzer (Gemini)" in results["passed"],
    "End-to-end pipeline":       "End-to-End Pipeline Speed" in results["passed"],
    "All 8 components pass":     failed == 0,
}
for check, passed_check in checks.items():
    print(f"  {'✅' if passed_check else '❌'}  {check}")

if failed == 0:
    print(f"\n  🎉 WEEK 3 COMPLETE — All systems operational!")
else:
    print(f"\n  ⚠️  {failed} component(s) need attention")
print("=" * 65)