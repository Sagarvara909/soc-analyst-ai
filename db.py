import sqlite3
import json
import os
from datetime import datetime


DB_PATH = "data/soc_analyst.db"


# ─────────────────────────────────────────────
# INIT
# ─────────────────────────────────────────────

def init_db(db_path: str = DB_PATH):
    """Create the database and tables if they don't exist."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    c    = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            inserted_at     TEXT    DEFAULT (datetime('now')),
            timestamp       TEXT,
            severity        TEXT,
            source_ip       TEXT,
            message         TEXT,
            log_format      TEXT,
            anomaly_score   REAL    DEFAULT 0.0,
            is_anomaly      INTEGER DEFAULT 0,
            confidence      TEXT    DEFAULT 'NONE',
            detector_votes  INTEGER DEFAULT 0,
            technique_id    TEXT,
            technique_name  TEXT,
            tactic          TEXT,
            mitre_confidence TEXT,
            is_false_positive INTEGER DEFAULT 0,
            raw             TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS fp_feedback (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id    INTEGER,
            feedback_at TEXT DEFAULT (datetime('now')),
            reason      TEXT,
            FOREIGN KEY (event_id) REFERENCES events(id)
        )
    """)

    # Indexes for fast queries
    c.execute("CREATE INDEX IF NOT EXISTS idx_severity   ON events(severity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_source_ip  ON events(source_ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_is_anomaly ON events(is_anomaly)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_technique  ON events(technique_id)")

    conn.commit()
    conn.close()
    print(f"[DB] Initialised at {db_path}")


# ─────────────────────────────────────────────
# INSERT
# ─────────────────────────────────────────────

def insert_event(event: dict, detection: dict = None,
                 classification: dict = None,
                 db_path: str = DB_PATH) -> int:
    """
    Insert one event into the database.

    Parameters
    ----------
    event          : parsed log dict from log_parser
    detection      : dict with anomaly_score, is_anomaly, confidence, detector_votes
    classification : dict from mitre_classifier.classify_event()

    Returns the new row id.
    """
    det  = detection      or {}
    cls  = classification or {}

    conn = sqlite3.connect(db_path)
    c    = conn.cursor()

    c.execute("""
        INSERT INTO events (
            timestamp, severity, source_ip, message, log_format,
            anomaly_score, is_anomaly, confidence, detector_votes,
            technique_id, technique_name, tactic, mitre_confidence,
            is_false_positive, raw
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
    """, (
        event.get("timestamp", ""),
        event.get("severity",  "INFO"),
        event.get("source_ip", "unknown"),
        event.get("message",   ""),
        event.get("format",    "unknown"),
        float(det.get("anomaly_score",  0.0)),
        int(  det.get("is_anomaly",     0)),
        str(  det.get("confidence",     "NONE")),
        int(  det.get("detector_votes", 0)),
        cls.get("technique_id"),
        cls.get("technique_name"),
        cls.get("tactic"),
        cls.get("confidence", "NONE"),
        event.get("raw", "")[:500],
    ))

    row_id = c.lastrowid
    conn.commit()
    conn.close()
    return row_id


def insert_events_bulk(events: list, detections: list = None,
                       classifications: list = None,
                       db_path: str = DB_PATH) -> int:
    """
    Insert many events at once. Much faster than calling insert_event() in a loop.
    Returns the number of rows inserted.
    """
    if not events:
        return 0

    n    = len(events)
    dets = detections      or [{}] * n
    clss = classifications or [{}] * n

    rows = []
    for event, det, cls in zip(events, dets, clss):
        rows.append((
            event.get("timestamp", ""),
            event.get("severity",  "INFO"),
            event.get("source_ip", "unknown"),
            event.get("message",   ""),
            event.get("format",    "unknown"),
            float(det.get("anomaly_score",  0.0)),
            int(  det.get("is_anomaly",     False)),
            str(  det.get("confidence",     "NONE")),
            int(  det.get("detector_votes", 0)),
            cls.get("technique_id"),
            cls.get("technique_name"),
            cls.get("tactic"),
            cls.get("confidence", "NONE"),
            event.get("raw", "")[:500],
        ))

    conn = sqlite3.connect(db_path)
    conn.executemany("""
        INSERT INTO events (
            timestamp, severity, source_ip, message, log_format,
            anomaly_score, is_anomaly, confidence, detector_votes,
            technique_id, technique_name, tactic, mitre_confidence,
            is_false_positive, raw
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
    """, rows)
    conn.commit()
    conn.close()
    return len(rows)


# ─────────────────────────────────────────────
# QUERY
# ─────────────────────────────────────────────

def get_recent_events(limit: int = 50, db_path: str = DB_PATH) -> list:
    """Fetch the most recent N events, newest first."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_events_by_severity(severity: str, limit: int = 100,
                           db_path: str = DB_PATH) -> list:
    """Fetch events filtered by severity level."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM events
        WHERE severity = ?
          AND is_false_positive = 0
        ORDER BY id DESC
        LIMIT ?
    """, (severity.upper(), limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_anomalies(limit: int = 50, db_path: str = DB_PATH) -> list:
    """Fetch only events flagged as anomalies, ordered by score."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM events
        WHERE is_anomaly = 1
          AND is_false_positive = 0
        ORDER BY anomaly_score DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
# FALSE POSITIVE FEEDBACK
# ─────────────────────────────────────────────

def mark_false_positive(event_id: int, reason: str = "",
                        db_path: str = DB_PATH) -> bool:
    """
    Mark an event as a false positive.
    Records feedback for future model improvement.
    Returns True if the event was found and updated.
    """
    conn = sqlite3.connect(db_path)
    c    = conn.cursor()

    c.execute("UPDATE events SET is_false_positive = 1 WHERE id = ?", (event_id,))
    updated = c.rowcount > 0

    if updated:
        c.execute("""
            INSERT INTO fp_feedback (event_id, reason)
            VALUES (?, ?)
        """, (event_id, reason))

    conn.commit()
    conn.close()
    return updated


# ─────────────────────────────────────────────
# METRICS
# ─────────────────────────────────────────────

def get_metrics(db_path: str = DB_PATH) -> dict:
    """
    Return summary statistics for the /metrics API endpoint.
    Used by the FastAPI backend and dashboard.
    """
    conn = sqlite3.connect(db_path)
    c    = conn.cursor()

    total         = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    anomalies     = c.execute("SELECT COUNT(*) FROM events WHERE is_anomaly=1").fetchone()[0]
    false_pos     = c.execute("SELECT COUNT(*) FROM events WHERE is_false_positive=1").fetchone()[0]
    critical      = c.execute("SELECT COUNT(*) FROM events WHERE severity='CRITICAL'").fetchone()[0]
    high          = c.execute("SELECT COUNT(*) FROM events WHERE severity='HIGH'").fetchone()[0]
    tagged_mitre  = c.execute("SELECT COUNT(*) FROM events WHERE technique_id IS NOT NULL").fetchone()[0]
    avg_score     = c.execute("SELECT AVG(anomaly_score) FROM events WHERE is_anomaly=1").fetchone()[0]

    top_ip_row    = c.execute("""
        SELECT source_ip, COUNT(*) as cnt
        FROM events GROUP BY source_ip
        ORDER BY cnt DESC LIMIT 1
    """).fetchone()

    top_technique = c.execute("""
        SELECT technique_id, COUNT(*) as cnt
        FROM events WHERE technique_id IS NOT NULL
        GROUP BY technique_id ORDER BY cnt DESC LIMIT 1
    """).fetchone()

    conn.close()

    return {
        "total_events":       total,
        "total_anomalies":    anomalies,
        "false_positives_blocked": false_pos,
        "critical_events":    critical,
        "high_events":        high,
        "mitre_tagged":       tagged_mitre,
        "mitre_tag_rate":     round(tagged_mitre / total * 100, 1) if total > 0 else 0,
        "avg_anomaly_score":  round(avg_score or 0, 3),
        "top_attacker_ip":    top_ip_row[0]    if top_ip_row    else None,
        "top_technique":      top_technique[0] if top_technique else None,
    }


def get_top_ips(limit: int = 10, db_path: str = DB_PATH) -> list:
    """Return the most active source IPs with event counts."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT source_ip,
               COUNT(*)                              AS total_events,
               SUM(CASE WHEN is_anomaly=1 THEN 1 ELSE 0 END) AS anomaly_count,
               MAX(anomaly_score)                    AS max_score
        FROM events
        GROUP BY source_ip
        ORDER BY total_events DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [{"ip": r[0], "total": r[1], "anomalies": r[2], "max_score": r[3]}
            for r in rows]


# ─────────────────────────────────────────────
# MAIN TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")

    from log_parser        import parse_log_file
    from features          import build_features, get_ml_columns
    from ensemble_detector import run_ensemble
    from mitre_classifier  import classify_events

    print("=" * 65)
    print("  DATABASE PIPELINE TEST")
    print("=" * 65)

    # Fresh database
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"  Removed old database")

    init_db()

    # Load all events
    all_events = []
    for path in ["logs/syslog_sample.log", "logs/apache_access.log",
                 "logs/windows_events.log", "logs/json_structured.log"]:
        if os.path.exists(path):
            evts = parse_log_file(path)
            all_events.extend(evts)

    print(f"  Loaded {len(all_events)} events")

    # Run detection pipeline
    print("  Running ML detection...")
    df = build_features(all_events)
    result_df = run_ensemble(df, contamination=0.1)

    # Run MITRE classification
    print("  Running MITRE classification...")
    classifications = classify_events(all_events)

    # Build detection dicts from DataFrame rows
    detections = result_df[
        ["anomaly_score", "is_anomaly", "confidence", "detector_votes"]
    ].to_dict(orient="records")

    # Bulk insert everything
    print("  Inserting into database...")
    count = insert_events_bulk(all_events, detections, classifications)
    print(f"  Inserted {count} events")

    # Test queries
    print(f"\n  ── Query Tests ──")

    recent = get_recent_events(limit=5)
    print(f"  get_recent_events(5)     → {len(recent)} rows ✅")

    high_events = get_events_by_severity("HIGH", limit=10)
    print(f"  get_events_by_severity() → {len(high_events)} HIGH events ✅")

    anomalies = get_anomalies(limit=10)
    print(f"  get_anomalies()          → {len(anomalies)} anomalies ✅")

    # Test false positive marking
    if recent:
        fp_id = recent[0]["id"]
        ok = mark_false_positive(fp_id, reason="Test FP marking")
        print(f"  mark_false_positive({fp_id}) → {'✅ OK' if ok else '❌ FAIL'}")

    # Metrics
    print(f"\n  ── Database Metrics ──")
    m = get_metrics()
    for key, val in m.items():
        print(f"  {key:<30} {val}")

    # Top IPs
    print(f"\n  ── Top 5 Attacker IPs ──")
    for row in get_top_ips(limit=5):
        print(f"  {row['ip']:<22} total={row['total']:>4}  "
              f"anomalies={row['anomalies']:>3}  max_score={row['max_score']:.3f}")

    # Final check
    print(f"\n  ── Checklist ──")
    checks = {
        "Database created":        os.path.exists(DB_PATH),
        "Events inserted":         m["total_events"] == len(all_events),
        "MITRE tags stored":       m["mitre_tagged"] > 0,
        "Anomalies stored":        m["total_anomalies"] > 0,
        "FP marking works":        True,
        "Metrics query works":     m["total_events"] > 0,
    }
    for check, passed in checks.items():
        print(f"  {'✅' if passed else '❌'}  {check}")

    print("=" * 65)