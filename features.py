"""
features.py
-----------
Converts parsed log dicts into a numeric pandas DataFrame
that your ML models can actually learn from.

Each row = one log event
Each column = one numeric feature

Features engineered:
  - hour_of_day         : 0–23 (attacks spike at night)
  - is_weekend          : 0/1  (less admin activity = easier to hide)
  - severity_score      : CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0
  - format_encoded      : syslog=0, apache=1, windows=2, json=3, unknown=4
  - ip_is_external      : 1 if not RFC-1918 private IP
  - ip_event_count      : how many events from this IP in the whole batch
  - ip_fail_rate        : fraction of this IP's events that are HIGH/CRITICAL
  - message_length      : longer messages often = more suspicious payload
  - has_sql_keywords    : 1 if message contains SQL injection patterns
  - has_exec_keywords   : 1 if message contains command execution patterns
  - has_c2_keywords     : 1 if message contains C2/exfil patterns
  - has_auth_failure    : 1 if message contains authentication failure
  - has_privilege_esc   : 1 if message contains privilege escalation
  - rolling_event_rate  : events from this IP in last 60-second window
  - anomaly_label       : placeholder column (0 = normal, filled by detector)
"""

import re
import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict

from log_parser import parse_log_file, parse_log_line


# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

SEVERITY_SCORE = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}

FORMAT_ENCODED = {
    "syslog":        0,
    "apache":        1,
    "windows_event": 2,
    "json":          3,
    "unknown":       4,
}

# Private / internal IP ranges (RFC 1918)
PRIVATE_IP_RE = re.compile(
    r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)'
)

# Keyword patterns for suspicious content
SQL_KEYWORDS    = re.compile(r'union\s+select|insert\s+into|drop\s+table|1=1|or\s+1|sql\s+inject|xp_cmdshell', re.IGNORECASE)
EXEC_KEYWORDS   = re.compile(r'cmd\.exe|powershell|/bin/sh|/bin/bash|exec\(|eval\(|base64|-enc|-encodedcommand|wget |curl ', re.IGNORECASE)
C2_KEYWORDS     = re.compile(r'c2|beacon|185\.220\.|91\.108\.|exfil|reverse.?shell|meterpreter|cobalt.?strike', re.IGNORECASE)
AUTH_FAIL_RE    = re.compile(r'fail|invalid user|authentication failure|bad password|wrong password|unauthorized|4625', re.IGNORECASE)
PRIV_ESC_RE     = re.compile(r'sudo|privilege|escalat|admin|root|4728|4732|domain admin|runas', re.IGNORECASE)


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def is_external_ip(ip: str) -> int:
    """Returns 1 if IP is external (not private/RFC-1918), else 0."""
    if ip == "unknown" or not ip:
        return 0
    return 0 if PRIVATE_IP_RE.match(ip) else 1


def parse_timestamp_hour(ts_str: str) -> int:
    """Extract hour (0–23) from various timestamp formats. Returns -1 if unknown."""
    formats = [
        "%b %d %H:%M:%S",       # syslog: Jan 15 14:32:01
        "%d/%b/%Y:%H:%M:%S %z", # apache: 15/Jan/2026:14:32:01 +0000
        "%Y-%m-%d %H:%M:%S",    # windows: 2026-01-15 14:32:01
        "%Y-%m-%dT%H:%M:%SZ",   # iso8601: 2026-01-15T14:32:01Z
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str.strip(), fmt).hour
        except ValueError:
            continue
    return datetime.now().hour   # fallback to current hour


def is_weekend(ts_str: str) -> int:
    """Returns 1 if timestamp falls on Saturday or Sunday."""
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ]
    for fmt in formats:
        try:
            return 1 if datetime.strptime(ts_str.strip(), fmt).weekday() >= 5 else 0
        except ValueError:
            continue
    return 0


# ─────────────────────────────────────────────
# MAIN FEATURE BUILDER
# ─────────────────────────────────────────────

def build_features(log_events: list[dict]) -> pd.DataFrame:
    """
    Takes a list of parsed log dicts (from log_parser.ipynb) and
    returns a pandas DataFrame of numeric features.

    Parameters
    ----------
    log_events : list of dicts from parse_log_line() / parse_log_file()

    Returns
    -------
    pd.DataFrame with one row per event and all numeric feature columns
    """
    if not log_events:
        print("[WARN] No log events provided — returning empty DataFrame")
        return pd.DataFrame()

    # ── Pass 1: compute per-IP statistics across the whole batch ──
    ip_counts      = defaultdict(int)     # total events per IP
    ip_high_counts = defaultdict(int)     # HIGH/CRITICAL events per IP

    for event in log_events:
        ip = event.get("source_ip", "unknown")
        ip_counts[ip] += 1
        if event.get("severity") in ("HIGH", "CRITICAL"):
            ip_high_counts[ip] += 1

    # ── Pass 2: compute rolling event rate (events per IP in 60s window) ──
    # We sort by timestamp index (approximate) and use a sliding window
    # This is a simplified version — real streaming would use a proper time index
    ip_recent = defaultdict(int)
    window_size = 20   # approximate: treat every 20 consecutive same-IP events as a window

    for i, event in enumerate(log_events):
        ip = event.get("source_ip", "unknown")
        # Count how many of the last `window_size` events share this IP
        start = max(0, i - window_size)
        recent = sum(
            1 for e in log_events[start:i]
            if e.get("source_ip") == ip
        )
        ip_recent[f"{ip}_{i}"] = recent

    # ── Pass 3: build the feature row for each event ──
    rows = []
    for i, event in enumerate(log_events):
        ip      = event.get("source_ip", "unknown")
        msg     = event.get("message", "")
        ts_str  = event.get("timestamp", "")
        sev     = event.get("severity", "INFO")
        fmt     = event.get("format", "unknown")

        ip_total  = ip_counts[ip]
        ip_highs  = ip_high_counts[ip]
        fail_rate = ip_highs / ip_total if ip_total > 0 else 0.0

        row = {
            # ── Time features ──
            "hour_of_day":       parse_timestamp_hour(ts_str),
            "is_weekend":        is_weekend(ts_str),

            # ── Severity & format ──
            "severity_score":    SEVERITY_SCORE.get(sev, 0),
            "format_encoded":    FORMAT_ENCODED.get(fmt, 4),

            # ── IP-based features ──
            "ip_is_external":    is_external_ip(ip),
            "ip_event_count":    ip_total,
            "ip_fail_rate":      round(fail_rate, 4),
            "rolling_event_rate":ip_recent[f"{ip}_{i}"],

            # ── Message content features ──
            "message_length":    len(msg),
            "has_sql_keywords":  1 if SQL_KEYWORDS.search(msg) else 0,
            "has_exec_keywords": 1 if EXEC_KEYWORDS.search(msg) else 0,
            "has_c2_keywords":   1 if C2_KEYWORDS.search(msg) else 0,
            "has_auth_failure":  1 if AUTH_FAIL_RE.search(msg) else 0,
            "has_privilege_esc": 1 if PRIV_ESC_RE.search(msg) else 0,

            # ── Label placeholder (filled by detector later) ──
            "anomaly_label":     0,

            # ── Keep original fields for reference (not used in ML) ──
            "_source_ip":  ip,
            "_message":    msg[:120],
            "_severity":   sev,
            "_format":     fmt,
            "_timestamp":  ts_str,
            "_raw":        event.get("raw", "")[:120],
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    print(f"[INFO] Built feature DataFrame: {len(df)} rows × {len(df.columns)} columns")
    return df


def get_ml_columns(df: pd.DataFrame) -> list[str]:
    """Returns only the numeric feature columns used for ML (drops _ prefixed metadata)."""
    return [c for c in df.columns if not c.startswith("_") and c != "anomaly_label"]


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import os
    import matplotlib
    matplotlib.use("Agg")   # non-interactive backend for Windows
    import matplotlib.pyplot as plt

    print("=" * 65)
    print("  FEATURE ENGINEERING TEST")
    print("=" * 65)

    # Load all 4 sample log files
    all_events = []
    log_files = [
        "logs/syslog_sample.log",
        "logs/apache_access.log",
        "logs/windows_events.log",
        "logs/json_structured.log",
    ]

    for path in log_files:
        if os.path.exists(path):
            events = parse_log_file(path)
            all_events.extend(events)
            print(f"  Loaded {len(events):>4} events from {path}")
        else:
            print(f"  [SKIP] {path} not found — run generate_sample_logs.py first")

    print(f"\n  Total events loaded: {len(all_events)}")

    if not all_events:
        print("  No events to process. Exiting.")
        exit(1)

    # Build features
    df = build_features(all_events)
    ml_cols = get_ml_columns(df)

    print(f"\n  ML feature columns ({len(ml_cols)}):")
    for col in ml_cols:
        print(f"    {col:<25} mean={df[col].mean():.3f}  max={df[col].max():.1f}")

    # Show severity breakdown
    print(f"\n  Severity distribution:")
    sev_counts = df["_severity"].value_counts()
    for sev, count in sev_counts.items():
        bar = "█" * (count // 5)
        print(f"    {sev:<10} {count:>4}  {bar}")

    # Show top attacking IPs
    print(f"\n  Top 5 source IPs by event count:")
    top_ips = df.groupby("_source_ip")["ip_event_count"].first().nlargest(5)
    for ip, count in top_ips.items():
        fail_rate = df[df["_source_ip"] == ip]["ip_fail_rate"].iloc[0]
        print(f"    {ip:<20} {count:>4} events  fail_rate={fail_rate:.2f}")

    # Show suspicious events (has any attack keyword)
    suspicious = df[
        (df["has_sql_keywords"] == 1) |
        (df["has_exec_keywords"] == 1) |
        (df["has_c2_keywords"] == 1)
    ]
    print(f"\n  Suspicious events detected: {len(suspicious)}")
    if len(suspicious) > 0:
        print("  Sample suspicious messages:")
        for _, row in suspicious.head(3).iterrows():
            print(f"    [{row['_severity']}] {row['_message'][:70]}")

    # Save feature CSV
    os.makedirs("data", exist_ok=True)
    df.to_csv("data/features.csv", index=False)
    print(f"\n  ✅ Features saved to data/features.csv")

    # Plot 1: Events per hour
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    hour_counts = df["hour_of_day"].value_counts().sort_index()
    axes[0].bar(hour_counts.index, hour_counts.values, color="#185FA5", alpha=0.8)
    axes[0].set_title("Events by Hour of Day", fontsize=12)
    axes[0].set_xlabel("Hour")
    axes[0].set_ylabel("Event Count")
    axes[0].axvspan(0, 6, alpha=0.1, color="red", label="Off-hours (suspicious)")
    axes[0].axvspan(22, 24, alpha=0.1, color="red")
    axes[0].legend(fontsize=9)

    # Plot 2: Severity distribution
    sev_order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_colors = ["#D32F2F", "#E64A19", "#F57C00", "#388E3C", "#1565C0"]
    sev_vals   = [sev_counts.get(s, 0) for s in sev_order]
    axes[1].bar(sev_order, sev_vals, color=sev_colors, alpha=0.85)
    axes[1].set_title("Events by Severity", fontsize=12)
    axes[1].set_xlabel("Severity Level")
    axes[1].set_ylabel("Event Count")

    plt.tight_layout()
    plt.savefig("data/feature_analysis.png", dpi=120, bbox_inches="tight")
    print(f"  ✅ Chart saved to data/feature_analysis.png")
    print("=" * 65)
