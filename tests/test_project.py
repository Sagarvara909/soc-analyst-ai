"""
tests/test_project.py — Week 4 Day 3
======================================
20 pytest unit tests covering all components.
Run: pytest tests/test_project.py -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


# ══════════════════════════════════════════════════════
# LOG PARSER TESTS — 5 tests
# ══════════════════════════════════════════════════════

class TestLogParser:

    def test_syslog_parsing(self):
        """Syslog line is parsed correctly with all fields."""
        from log_parser import parse_log_line
        line = "Jan 15 14:32:01 webserver sshd[1234]: Failed password for invalid user admin from 195.178.55.22 port 44392 ssh2"
        result = parse_log_line(line)
        assert result is not None
        assert result["format"]    == "syslog"
        assert result["source_ip"] == "195.178.55.22"
        assert result["severity"]  == "HIGH"
        assert "195.178.55.22" in result["message"]

    def test_apache_parsing(self):
        """Apache access log line is parsed with correct status code."""
        from log_parser import parse_log_line
        line = '195.178.55.22 - - [15/Jan/2026:14:32:01 +0000] "GET /admin HTTP/1.1" 403 512'
        result = parse_log_line(line)
        assert result is not None
        assert result["format"]    == "apache"
        assert result["source_ip"] == "195.178.55.22"
        assert "403" in result["message"]

    def test_windows_event_parsing(self):
        """Windows Event Log line is parsed with correct EventID severity."""
        from log_parser import parse_log_line
        line = "2026-01-15 14:32:01 EventID=4625 User=CORP\\jsmith Source=192.168.1.55 Message=An account failed to log on"
        result = parse_log_line(line)
        assert result is not None
        assert result["format"]   == "windows_event"
        assert result["severity"] == "HIGH"

    def test_json_parsing(self):
        """JSON structured log line is parsed with correct fields."""
        from log_parser import parse_log_line
        import json
        event = {"timestamp":"2026-01-15T14:32:01Z","severity":"HIGH","source_ip":"77.88.44.3","message":"SQL injection attempt"}
        result = parse_log_line(json.dumps(event))
        assert result is not None
        assert result["format"]    == "json"
        assert result["source_ip"] == "77.88.44.3"
        assert result["severity"]  == "HIGH"

    def test_empty_line_returns_none(self):
        """Empty and comment lines return None — not added to event list."""
        from log_parser import parse_log_line
        assert parse_log_line("")     is None
        assert parse_log_line("   ") is None
        assert parse_log_line("# comment") is None


# ══════════════════════════════════════════════════════
# FEATURE ENGINEERING TESTS — 3 tests
# ══════════════════════════════════════════════════════

class TestFeatures:

    def setup_method(self):
        self.events = [
            {"timestamp":"Jan 15 08:00:00","severity":"HIGH","source_ip":"195.178.55.22","message":"Failed password for invalid user admin","raw":"","format":"syslog"},
            {"timestamp":"Jan 15 08:00:01","severity":"HIGH","source_ip":"195.178.55.22","message":"Failed password for root","raw":"","format":"syslog"},
            {"timestamp":"Jan 15 08:00:02","severity":"CRITICAL","source_ip":"10.0.0.55","message":"LSASS memory read detected mimikatz","raw":"","format":"json"},
            {"timestamp":"Jan 15 08:00:03","severity":"INFO","source_ip":"10.0.0.10","message":"User logged in successfully","raw":"","format":"syslog"},
        ]

    def test_dataframe_shape(self):
        """Feature DataFrame has correct number of rows and columns."""
        from features import build_features
        df = build_features(self.events)
        assert len(df) == 4
        assert len(df.columns) >= 14

    def test_ml_columns_no_metadata(self):
        """ML columns do not include metadata or label columns."""
        from features import build_features, get_ml_columns
        df      = build_features(self.events)
        ml_cols = get_ml_columns(df)
        assert len(ml_cols) >= 10
        assert "anomaly_label" not in ml_cols
        assert all(not c.startswith("_") for c in ml_cols)

    def test_ip_fail_rate(self):
        """Attacker IP with high failure rate is correctly calculated."""
        from features import build_features
        df = build_features(self.events)
        attacker = df[df["_source_ip"] == "195.178.55.22"]
        assert len(attacker) == 2
        assert attacker["ip_fail_rate"].iloc[0] > 0.0


# ══════════════════════════════════════════════════════
# MITRE CLASSIFIER TESTS — 5 tests
# ══════════════════════════════════════════════════════

class TestMITREClassifier:

    def test_brute_force(self):
        """Failed password message → T1110.001 Brute Force."""
        from mitre_classifier import classify_event
        r = classify_event({"message":"Failed password for invalid user admin from 195.178.55.22","raw":""})
        assert r["technique_id"] == "T1110.001"
        assert r["tactic"]       == "Credential Access"
        assert r["confidence"]   == "HIGH"

    def test_sql_injection(self):
        """SQL injection payload → T1190 Exploit Public-Facing Application."""
        from mitre_classifier import classify_event
        r = classify_event({"message":"SQL injection attempt union select password from users","raw":""})
        assert r["technique_id"] == "T1190"

    def test_powershell(self):
        """Encoded PowerShell → T1059.001 PowerShell Execution."""
        from mitre_classifier import classify_event
        r = classify_event({"message":"powershell.exe -EncodedCommand SQBFAFgA detected","raw":""})
        assert r["technique_id"] == "T1059.001"

    def test_log_clearing(self):
        """Audit log cleared → T1562.001 Impair Defenses."""
        from mitre_classifier import classify_event
        r = classify_event({"message":"EventID=1102 The audit log was cleared","raw":"EventID=1102 The audit log was cleared"})
        assert r["technique_id"] == "T1562.001"

    def test_benign_event(self):
        """Normal login returns technique_id=None and confidence=NONE."""
        from mitre_classifier import classify_event
        r = classify_event({"message":"Normal user login from known device at 9am","raw":""})
        assert r["technique_id"] is None
        assert r["confidence"]   == "NONE"


# ══════════════════════════════════════════════════════
# DATABASE TESTS — 4 tests
# ══════════════════════════════════════════════════════

class TestDatabase:

    TEST_DB = "data/test_unit.db"

    def setup_method(self):
        from db import init_db
        os.makedirs("data", exist_ok=True)
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        init_db(db_path=self.TEST_DB)

    def teardown_method(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)

    def test_insert_and_retrieve(self):
        """Single event is inserted and retrieved correctly."""
        from db import insert_events_bulk, get_recent_events
        events = [{"timestamp":"2026-01-15 08:00:00","severity":"HIGH",
                   "source_ip":"1.2.3.4","message":"Test event","format":"syslog","raw":"test"}]
        count  = insert_events_bulk(events, db_path=self.TEST_DB)
        assert count == 1
        recent = get_recent_events(limit=10, db_path=self.TEST_DB)
        assert len(recent) == 1
        assert recent[0]["source_ip"] == "1.2.3.4"
        assert recent[0]["severity"]  == "HIGH"

    def test_false_positive_marking(self):
        """Marking an event as FP sets is_false_positive=1."""
        from db import insert_events_bulk, mark_false_positive, get_recent_events
        events = [{"timestamp":"2026-01-15","severity":"HIGH",
                   "source_ip":"1.2.3.4","message":"Test","format":"json","raw":""}]
        insert_events_bulk(events, db_path=self.TEST_DB)
        recent   = get_recent_events(limit=1, db_path=self.TEST_DB)
        event_id = recent[0]["id"]
        result   = mark_false_positive(event_id, reason="scheduled scan", db_path=self.TEST_DB)
        assert result is True

    def test_metrics_query(self):
        """Metrics returns correct counts for inserted events."""
        from db import insert_events_bulk, get_metrics
        events = [
            {"timestamp":"t","severity":"HIGH","source_ip":"1.1.1.1","message":"Attack","format":"syslog","raw":""},
            {"timestamp":"t","severity":"INFO","source_ip":"2.2.2.2","message":"Normal","format":"syslog","raw":""},
        ]
        dets = [
            {"anomaly_score":0.9,"is_anomaly":True, "confidence":"HIGH","detector_votes":3},
            {"anomaly_score":0.1,"is_anomaly":False,"confidence":"NONE","detector_votes":0},
        ]
        insert_events_bulk(events, detections=dets, db_path=self.TEST_DB)
        m = get_metrics(db_path=self.TEST_DB)
        assert m["total_events"]   == 2
        assert m["total_anomalies"]== 1

    def test_bulk_insert_performance(self):
        """100 events inserted in under 2 seconds."""
        import time
        from db import insert_events_bulk
        events = [{"timestamp":"t","severity":"INFO","source_ip":f"1.2.3.{i%254}",
                   "message":f"Event {i}","format":"json","raw":""} for i in range(100)]
        t0    = time.time()
        count = insert_events_bulk(events, db_path=self.TEST_DB)
        ms    = round((time.time()-t0)*1000)
        assert count == 100
        assert ms < 2000, f"Bulk insert took {ms}ms — too slow"


# ══════════════════════════════════════════════════════
# AI ANALYZER TESTS — 3 tests
# ══════════════════════════════════════════════════════

class TestAIAnalyzer:

    def test_brute_force_analysis(self):
        """Brute force event returns correct threat type and recommendations."""
        from ai_analyzer import analyze_threat
        event  = {"message":"Failed password for invalid user admin from 195.178.55.22",
                  "severity":"HIGH","source_ip":"195.178.55.22",
                  "anomaly_score":0.82,"technique_id":"T1110.001","tactic":"Credential Access"}
        result = analyze_threat(event)
        assert result.get("threat_type")     is not None
        assert result.get("recommendations") is not None
        assert len(result.get("recommendations",[])) >= 1
        assert 0.0 <= float(result.get("false_positive_probability", 0)) <= 1.0

    def test_lsass_analysis(self):
        """LSASS dump event returns LSASS or Credential in threat type."""
        from ai_analyzer import analyze_threat
        event  = {"message":"LSASS memory read detected mimikatz credential dump",
                  "severity":"CRITICAL","source_ip":"10.0.0.55","anomaly_score":0.96}
        result = analyze_threat(event)
        tt = result.get("threat_type","").upper()
        assert "LSASS" in tt or "CREDENTIAL" in tt or "DUMP" in tt

    def test_low_risk_high_fp_probability(self):
        """Normal event returns high false positive probability (>0.5)."""
        from ai_analyzer import analyze_threat
        event  = {"message":"User logged in successfully from known corporate device",
                  "severity":"INFO","source_ip":"10.0.0.10","anomaly_score":0.04}
        result = analyze_threat(event)
        assert float(result.get("false_positive_probability", 0)) > 0.5


# ══════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Run with:")
    print("  pytest tests/test_project.py -v")
    print("  pytest tests/test_project.py -v --tb=short")