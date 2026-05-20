import os
import numpy as np
import pandas as pd
import joblib
 
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
 
from log_parser  import parse_log_file
from features    import build_features, get_ml_columns

def zscore_detector(df, columns, threshold=2.5):
    scores = pd.DataFrame(index=df.index)
    for col in columns:
        mean = df[col].mean()
        std  = df[col].std()
        scores[col] = 0.0 if std == 0 else (df[col] - mean).abs() / std
    max_z = scores.max(axis=1)
    return max_z > threshold, max_z


def evaluate(result_df):
    true_pos_mask = result_df["severity_score"] >= 3
    tp = ((result_df["is_anomaly"] == True)  &  true_pos_mask).sum()
    fp = ((result_df["is_anomaly"] == True)  & ~true_pos_mask).sum()
    fn = ((result_df["is_anomaly"] == False) &  true_pos_mask).sum()
    tn = ((result_df["is_anomaly"] == False) & ~true_pos_mask).sum()
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "total_events":    len(result_df),
        "anomalies_found": int(result_df["is_anomaly"].sum()),
        "true_positives":  int(tp),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "precision":       round(float(precision), 3),
        "recall":          round(float(recall), 3),
        "f1_score":        round(float(f1), 3),
        "fp_rate":         round(float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0, 3),
    }
 
 
# ─────────────────────────────────────────────
# ISOLATION FOREST
# ─────────────────────────────────────────────
 
def train_isolation_forest(X: np.ndarray, contamination: float = 0.1):
    """
    Train an Isolation Forest on the feature matrix X.
 
    contamination = expected fraction of anomalies (0.1 = 10%).
    Lower = fewer flags, higher precision but worse recall.
    """
    model = IsolationForest(
        n_estimators=200,       # more trees = more stable
        contamination=contamination,
        random_state=42,
        n_jobs=-1,              # use all CPU cores
    )
    model.fit(X)
    return model
 
 
def predict_isolation_forest(model, X: np.ndarray):
    """
    Returns:
      flags  : bool array — True = anomaly
      scores : float array — higher = more anomalous (0-1 normalised)
    """
    # sklearn returns -1 for anomaly, 1 for normal
    raw_pred   = model.predict(X)
    flags      = raw_pred == -1
 
    # decision_function: more negative = more anomalous
    raw_scores = model.decision_function(X)
    # Normalise to 0–1 (flip so higher = more anomalous)
    min_s, max_s = raw_scores.min(), raw_scores.max()
    if max_s == min_s:
        scores = np.zeros(len(raw_scores))
    else:
        scores = 1.0 - (raw_scores - min_s) / (max_s - min_s)
 
    return flags, np.round(scores, 4)
 
 
# ─────────────────────────────────────────────
# LOCAL OUTLIER FACTOR
# ─────────────────────────────────────────────
 
def train_predict_lof(X: np.ndarray, contamination: float = 0.1):
    """
    LOF doesn't separate train/predict — it runs on the full dataset.
    Good for detecting events that are far from their nearest neighbours.
    """
    model = LocalOutlierFactor(
        n_neighbors=20,
        contamination=contamination,
        n_jobs=-1,
    )
    raw_pred = model.fit_predict(X)
    flags    = raw_pred == -1
 
    # Negative outlier factor: more negative = more anomalous
    raw_scores = -model.negative_outlier_factor_
    min_s, max_s = raw_scores.min(), raw_scores.max()
    if max_s == min_s:
        scores = np.zeros(len(raw_scores))
    else:
        scores = (raw_scores - min_s) / (max_s - min_s)
 
    return flags, np.round(scores, 4)
 
 
# ─────────────────────────────────────────────
# ENSEMBLE COMBINER
# ─────────────────────────────────────────────
 
def run_ensemble(df: pd.DataFrame, contamination: float = 0.1) -> pd.DataFrame:
    """
    Full pipeline:
      1. Scale features
      2. Run IF, LOF, Z-score
      3. Vote: 2 of 3 → anomaly
      4. Combine scores (weighted average)
      5. Return enriched DataFrame
 
    Saves scaler + IF model to models/ for later API use.
    """
    ml_cols = get_ml_columns(df)
    X_raw   = df[ml_cols].values
 
    # ── Scale features (zero mean, unit variance) ────────────────
    scaler = StandardScaler()
    X      = scaler.fit_transform(X_raw)
 
    # ── Detector 1: Isolation Forest ─────────────────────────────
    print("  [1/3] Training Isolation Forest...")
    if_model              = train_isolation_forest(X, contamination)
    if_flags, if_scores   = predict_isolation_forest(if_model, X)
    print(f"        Flagged: {if_flags.sum()} events")
 
    # ── Detector 2: Local Outlier Factor ─────────────────────────
    print("  [2/3] Running Local Outlier Factor...")
    lof_flags, lof_scores = train_predict_lof(X, contamination)
    print(f"        Flagged: {lof_flags.sum()} events")
 
    # ── Detector 3: Z-score ──────────────────────────────────────
    print("  [3/3] Running Z-score baseline...")
    z_flags, _ = zscore_detector(df, ml_cols, threshold=2.5)
    z_flags = z_flags.values
    print(f"        Flagged: {z_flags.sum()} events")
 
    # ── Ensemble vote ─────────────────────────────────────────────
    votes        = if_flags.astype(int) + lof_flags.astype(int) + z_flags.astype(int)
    is_anomaly   = votes >= 2          # majority vote: 2 of 3
 
    # Weighted anomaly score: IF=40%, LOF=40%, Z-score=20%
    combined_score = (0.4 * if_scores + 0.4 * lof_scores +
                      0.2 * (df["anomaly_score"].values
                             if "anomaly_score" in df.columns
                             else np.zeros(len(df))))
    combined_score = np.clip(combined_score, 0, 1).round(4)
 
    # Confidence label
    confidence = np.where(votes == 3, "HIGH",
                 np.where(votes == 2, "MEDIUM",
                 np.where(votes == 1, "LOW", "NONE")))
 
    # ── Build result DataFrame ────────────────────────────────────
    result                     = df.copy()
    result["if_flag"]          = if_flags
    result["lof_flag"]         = lof_flags
    result["zscore_flag"]      = z_flags
    result["detector_votes"]   = votes
    result["anomaly_score"]    = combined_score
    result["confidence"]       = confidence
    result["is_anomaly"]       = is_anomaly
 
    # ── Save models ───────────────────────────────────────────────
    os.makedirs("models", exist_ok=True)
    joblib.dump(scaler,   "models/scaler.joblib")
    joblib.dump(if_model, "models/isolation_forest.joblib")
    print("\n  Models saved: models/scaler.joblib, models/isolation_forest.joblib")
 
    return result
 
 
# ─────────────────────────────────────────────
# LOAD SAVED MODEL (for API use later)
# ─────────────────────────────────────────────
 
def load_and_predict(df: pd.DataFrame) -> pd.DataFrame:
    """
    Load saved models and predict on new data.
    Used by the FastAPI backend in Week 2 Day 5.
    """
    if not os.path.exists("models/scaler.joblib"):
        raise FileNotFoundError("No saved model found. Run ensemble_detector.py first.")
 
    scaler   = joblib.load("models/scaler.joblib")
    if_model = joblib.load("models/isolation_forest.joblib")
    ml_cols  = get_ml_columns(df)
 
    X            = scaler.transform(df[ml_cols].values)
    if_flags, if_scores = predict_isolation_forest(if_model, X)
 
    result               = df.copy()
    result["is_anomaly"] = if_flags
    result["anomaly_score"] = if_scores
    result["confidence"] = np.where(if_scores > 0.75, "HIGH",
                           np.where(if_scores > 0.50, "MEDIUM", "LOW"))
    return result
 
 
# ─────────────────────────────────────────────
# MAIN TEST
# ─────────────────────────────────────────────
 
if __name__ == "__main__":
 
    print("=" * 65)
    print("  WEEK 2 — ML ENSEMBLE DETECTOR")
    print("  Isolation Forest + Local Outlier Factor + Z-score")
    print("=" * 65)
 
    # ── Load data ─────────────────────────────────────────────────
    all_events = []
    for path in ["logs/syslog_sample.log", "logs/apache_access.log",
                 "logs/windows_events.log", "logs/json_structured.log"]:
        if os.path.exists(path):
            all_events.extend(parse_log_file(path))
 
    print(f"\n  Loaded {len(all_events)} events")
    df = build_features(all_events)
 
    # ── Run ensemble ──────────────────────────────────────────────
    print("\n  Running ensemble detectors...\n")
    result = run_ensemble(df, contamination=0.1)
 
    # ── Metrics ───────────────────────────────────────────────────
    metrics = evaluate(result)
 
    print(f"\n  ── Performance Metrics ──")
    print(f"  Precision  : {metrics['precision']}   (Week 1 target was 0.50+)")
    print(f"  Recall     : {metrics['recall']}")
    print(f"  F1 Score   : {metrics['f1_score']}")
    print(f"  FP Rate    : {metrics['fp_rate']}")
    print(f"  Anomalies  : {metrics['anomalies_found']} / {metrics['total_events']}")
 
    # ── Confidence breakdown ──────────────────────────────────────
    conf_counts = result["confidence"].value_counts()
    print(f"\n  ── Confidence Breakdown ──")
    for level in ["HIGH", "MEDIUM", "LOW", "NONE"]:
        count = conf_counts.get(level, 0)
        bar   = "█" * (count // 3)
        print(f"  {level:<8} {count:>4}  {bar}")
 
    # ── Top anomalies ─────────────────────────────────────────────
    print(f"\n  ── Top 10 Anomalies (by score) ──")
    top = result[result["is_anomaly"]].nlargest(10, "anomaly_score")
    for _, row in top.iterrows():
        votes = int(row["detector_votes"])
        icons = "🔴" if row["confidence"] == "HIGH" else "🟡"
        print(f"  {icons} score={row['anomaly_score']:.3f} "
              f"votes={votes}/3  [{row['_severity']:<8}]  "
              f"{str(row['_message'])[:50]}")
 
    # ── Compare Week 1 vs Week 2 ──────────────────────────────────
    print(f"\n  ── Week 1 vs Week 2 Comparison ──")
    print(f"  {'Method':<28} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    print(f"  {'-'*55}")
    print(f"  {'Week 1: Z-score + IQR':<28} {'~0.55':>10} {'~0.70':>8} {'~0.62':>8}")
    print(f"  {'Week 2: IF + LOF + Z-score':<28} {metrics['precision']:>10} "
          f"{metrics['recall']:>8} {metrics['f1_score']:>8}  ← should be better")
 
    # ── Save ──────────────────────────────────────────────────────
    os.makedirs("data", exist_ok=True)
    result.to_csv("data/ml_detection_results.csv", index=False)
    print(f"\n  ✅ Results saved → data/ml_detection_results.csv")
 
    # ── Checklist ─────────────────────────────────────────────────
    print(f"\n  ── Day 1 Checklist ──")
    checks = {
        "Isolation Forest trained":     os.path.exists("models/isolation_forest.joblib"),
        "Scaler saved":                 os.path.exists("models/scaler.joblib"),
        "LOF running":                  result["lof_flag"].sum() > 0,
        "Ensemble voting working":      result["detector_votes"].max() >= 2,
        "HIGH confidence alerts exist": (result["confidence"] == "HIGH").sum() > 0,
        "Precision improved vs Week 1": metrics["precision"] >= 0.55,
    }
    for check, passed in checks.items():
        print(f"  {'✅' if passed else '❌'}  {check}")
 
    print("=" * 65)