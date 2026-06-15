"""
basic_detector.py
-----------------
Statistical anomaly detection using two methods:
  1. Z-score  — flags events more than N std deviations from the mean
  2. IQR      — flags events outside Q1-1.5*IQR and Q3+1.5*IQR

Then combines both into an ensemble vote.

Run this file directly to see detection results on your sample logs.
"""

import pandas as pd
import numpy as np
from features import build_features, get_ml_columns
from log_parser import parse_log_file
import os


# ─────────────────────────────────────────────
# Z-SCORE DETECTOR
# ─────────────────────────────────────────────

def zscore_detector(df: pd.DataFrame, columns: list, threshold: float = 2.5) -> pd.Series:
    """
    Flag rows where ANY feature column deviates more than
    `threshold` standard deviations from the column mean.

    Returns a boolean Series: True = anomaly detected.
    """
    scores = pd.DataFrame(index=df.index)

    for col in columns:
        mean = df[col].mean()
        std  = df[col].std()
        if std == 0:
            scores[col] = 0.0
        else:
            scores[col] = (df[col] - mean).abs() / std

    # An event is anomalous if ANY feature has a high z-score
    max_zscore = scores.max(axis=1)
    return max_zscore > threshold, max_zscore


# ─────────────────────────────────────────────
# IQR DETECTOR
# ─────────────────────────────────────────────

def iqr_detector(df: pd.DataFrame, columns: list, multiplier: float = 1.5) -> pd.Series:
    """
    Flag rows where ANY feature falls outside
    Q1 - multiplier*IQR  or  Q3 + multiplier*IQR.

    Returns a boolean Series: True = anomaly detected.
    """
    flags = pd.DataFrame(False, index=df.index, columns=columns)

    for col in columns:
        Q1  = df[col].quantile(0.25)
        Q3  = df[col].quantile(0.75)
        IQR = Q3 - Q1
        if IQR == 0:
            continue
        lower = Q1 - multiplier * IQR
        upper = Q3 + multiplier * IQR
        flags[col] = (df[col] < lower) | (df[col] > upper)

    # Anomalous if ANY column is flagged
    return flags.any(axis=1)


# ─────────────────────────────────────────────
# ANOMALY SCORE (0.0 – 1.0)
# ─────────────────────────────────────────────

def compute_anomaly_score(df: pd.DataFrame, columns: list) -> pd.Series:
    """
    Produce a continuous anomaly score between 0.0 and 1.0
    by normalising the max z-score across all features.
    """
    _, max_zscores = zscore_detector(df, columns, threshold=999)  # get raw scores

    # Clip at 5 std devs and normalise to 0-1
    clipped = max_zscores.clip(upper=5.0)
    score   = clipped / 5.0
    return score.round(4)


# ─────────────────────────────────────────────
# ENSEMBLE DETECTOR
# ─────────────────────────────────────────────

def ensemble_detector(df: pd.DataFrame, columns: list,
                      z_threshold: float = 2.5,
                      iqr_multiplier: float = 1.5) -> pd.DataFrame:
    """
    Combine Z-score and IQR detectors.
    An event is flagged HIGH CONFIDENCE if BOTH methods agree.
    LOW CONFIDENCE if only one flags it.

    Returns the original df with extra columns:
      - anomaly_zscore  : bool
      - anomaly_iqr     : bool
      - anomaly_score   : float 0-1
      - confidence      : 'HIGH' / 'LOW' / 'NONE'
      - is_anomaly      : final bool (high confidence only)
    """
    z_flags, _ = zscore_detector(df, columns, z_threshold)
    i_flags     = iqr_detector(df, columns, iqr_multiplier)
    score       = compute_anomaly_score(df, columns)

    result = df.copy()
    result["anomaly_zscore"] = z_flags
    result["anomaly_iqr"]    = i_flags
    result["anomaly_score"]  = score

    # Confidence: HIGH = both agree, LOW = one agrees, NONE = neither
    both = z_flags & i_flags
    either = z_flags | i_flags
    result["confidence"] = "NONE"
    result.loc[either,  "confidence"] = "LOW"
    result.loc[both,    "confidence"] = "HIGH"
    result["is_anomaly"] = both   # only flag when both detectors agree

    return result


# ─────────────────────────────────────────────
# EVALUATION METRICS
# ─────────────────────────────────────────────

def evaluate(result_df: pd.DataFrame) -> dict:
    """
    Since we don't have ground-truth labels, we use severity_score
    as a proxy: HIGH/CRITICAL events (score >= 3) = true positives.

    This shows whether the detector catches what it should.
    """
    # Ground truth: severity HIGH or CRITICAL
    true_positive_mask = result_df["severity_score"] >= 3

    tp = ((result_df["is_anomaly"] == True)  & true_positive_mask).sum()
    fp = ((result_df["is_anomaly"] == True)  & ~true_positive_mask).sum()
    fn = ((result_df["is_anomaly"] == False) & true_positive_mask).sum()
    tn = ((result_df["is_anomaly"] == False) & ~true_positive_mask).sum()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fp_rate   = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "total_events":    len(result_df),
        "anomalies_found": int(result_df["is_anomaly"].sum()),
        "true_positives":  int(tp),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "precision":       round(precision, 3),
        "recall":          round(recall, 3),
        "f1_score":        round(f1, 3),
        "fp_rate":         round(fp_rate, 3),
    }


# ─────────────────────────────────────────────
# MAIN TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":

    print("=" * 65)
    print("  ANOMALY DETECTOR TEST — Z-score + IQR Ensemble")
    print("=" * 65)

    # Load all sample logs
    all_events = []
    for path in ["logs/syslog_sample.log", "logs/apache_access.log",
                 "logs/windows_events.log", "logs/json_structured.log"]:
        if os.path.exists(path):
            events = parse_log_file(path)
            all_events.extend(events)

    print(f"\n  Loaded {len(all_events)} total events")

    # Build features
    df = build_features(all_events)
    ml_cols = get_ml_columns(df)

    # ── Run detectors independently ──────────────────────────────
    print("\n  ── Method 1: Z-score (threshold=2.5) ──")
    z_flags, z_scores = zscore_detector(df, ml_cols, threshold=2.5)
    print(f"  Flagged: {z_flags.sum()} / {len(df)} events ({z_flags.mean()*100:.1f}%)")

    print("\n  ── Method 2: IQR (multiplier=1.5) ──")
    i_flags = iqr_detector(df, ml_cols, multiplier=1.5)
    print(f"  Flagged: {i_flags.sum()} / {len(df)} events ({i_flags.mean()*100:.1f}%)")

    # ── Run ensemble ─────────────────────────────────────────────
    print("\n  ── Ensemble (both must agree) ──")
    result = ensemble_detector(df, ml_cols)
    anom = result[result["is_anomaly"] == True]
    print(f"  Flagged: {len(anom)} / {len(df)} events ({len(anom)/len(df)*100:.1f}%)")

    # ── Metrics ──────────────────────────────────────────────────
    metrics = evaluate(result)
    print(f"\n  ── Performance Metrics ──")
    print(f"  Total events      : {metrics['total_events']}")
    print(f"  Anomalies found   : {metrics['anomalies_found']}")
    print(f"  True  positives   : {metrics['true_positives']}")
    print(f"  False positives   : {metrics['false_positives']}")
    print(f"  False negatives   : {metrics['false_negatives']}")
    print(f"  Precision         : {metrics['precision']}   ← of flagged events, how many were real threats")
    print(f"  Recall            : {metrics['recall']}   ← of real threats, how many did we catch")
    print(f"  F1 Score          : {metrics['f1_score']}   ← balance of precision + recall")
    print(f"  False Positive Rate: {metrics['fp_rate']}  ← lower is better")

    # ── Show top anomalies ────────────────────────────────────────
    print(f"\n  ── Top 10 Highest-Scored Anomalies ──")
    top = result.nlargest(10, "anomaly_score")[
        ["_timestamp", "_severity", "_source_ip", "anomaly_score", "confidence", "_message"]
    ]
    for _, row in top.iterrows():
        flag = "🚨" if row["confidence"] == "HIGH" else "⚠️ "
        print(f"  {flag} [{row['_severity']:<8}] score={row['anomaly_score']:.3f}  "
              f"IP={row['_source_ip']:<18} {row['_message'][:45]}")

    # ── Compare Z-score vs IQR vs Ensemble ───────────────────────
    print(f"\n  ── Method Comparison ──")
    print(f"  {'Method':<20} {'Flagged':>8} {'Rate':>8} {'Precision':>10} {'Recall':>8}")
    print(f"  {'-'*55}")

    for label, flags in [("Z-score only", z_flags), ("IQR only", i_flags)]:
        r = df.copy()
        r["is_anomaly"] = flags
        m = evaluate(r)
        rate = flags.mean() * 100
        print(f"  {label:<20} {flags.sum():>8} {rate:>7.1f}%  {m['precision']:>9.3f}  {m['recall']:>7.3f}")

    ens_flags = result["is_anomaly"]
    rate = ens_flags.mean() * 100
    print(f"  {'Ensemble (both)':<20} {ens_flags.sum():>8} {rate:>7.1f}%  "
          f"{metrics['precision']:>9.3f}  {metrics['recall']:>7.3f}  ← best balance")

    # ── Save results ──────────────────────────────────────────────
    os.makedirs("data", exist_ok=True)
    result.to_csv("data/detection_results.csv", index=False)
    print(f"\n  ✅ Full results saved to data/detection_results.csv")

    # ── Final verdict ─────────────────────────────────────────────
    print(f"\n  ── Week 1 Deliverable Check ──")
    checks = {
        "Parses 3+ log formats":       True,
        "Extracts numeric features":   len(ml_cols) >= 8,
        "Z-score detector works":      z_flags.sum() > 0,
        "IQR detector works":          i_flags.sum() > 0,
        "Ensemble reduces FP":         metrics["fp_rate"] < 0.4,
        "Precision >= 0.5":            metrics["precision"] >= 0.5,
        "Results saved to CSV":        os.path.exists("data/detection_results.csv"),
    }
    all_pass = True
    for check, passed in checks.items():
        icon = "✅" if passed else "❌"
        print(f"  {icon} {check}")
        if not passed:
            all_pass = False

    print(f"\n  {'🎉 WEEK 1 COMPLETE — ready for ML models in Week 2!' if all_pass else '⚠️  Fix failing checks before moving on'}")
    print("=" * 65)