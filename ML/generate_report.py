import os
import sys
import argparse
from datetime import datetime
import json
import numpy as np
import pandas as pd
import joblib

# Support running as a script from within the ML folder
if __package__ is None or __package__ == "":
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from ML.robust_anomaly_trainer import parse_log_file, extract_features, classify_log_entry
else:
    from .robust_anomaly_trainer import parse_log_file, extract_features, classify_log_entry


ANOMALY_LEVELS = {"WARN", "ERROR", "FATAL", "CRITICAL"}


def load_model_artifacts(model_dir: str):
    try:
        model = joblib.load(os.path.join(model_dir, "model.joblib"))
        tfidf = joblib.load(os.path.join(model_dir, "tfidf.joblib"))
        scaler = joblib.load(os.path.join(model_dir, "scaler.joblib"))
        feature_columns = joblib.load(os.path.join(model_dir, "feature_columns.joblib"))
        meta = None
        meta_path = os.path.join(model_dir, "model_meta.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        return model, tfidf, scaler, feature_columns, meta
    except Exception:
        return None, None, None, None, None


def rule_reason(message: str) -> str:
    msg = (message or "").lower()
    # Specific reasons mirroring the sample phrasing
    if "failed password" in msg and ("invalid user" in msg or "user" in msg):
        return "Suspicious brute-force attempt on invalid account from external IP."
    if "connection refused" in msg and ("mysql" in msg or "database" in msg):
        return "Database outage or denial-of-service possibility."
    if "password check failed" in msg and "root" in msg:
        return "Unauthorized root login attempt — HIGH severity."
    if "critical" in msg or "fatal" in msg:
        return "Critical system error observed."
    if "out of memory" in msg or "oom" in msg:
        return "System memory pressure or OOM condition."
    if "connection refused" in msg:
        return "Service unreachable; possible outage or port block."
    if "unauthorized" in msg or "forbidden" in msg:
        return "Unauthorized access attempt detected."
    return "Heuristic anomaly based on security/error cues."


def ascii_bar(n: int) -> str:
    return "█" * max(0, n)


def generate_report(df: pd.DataFrame, model_pack, outfile_md: str, max_list: int = 20):
    model, tfidf, scaler, feature_columns, meta = model_pack

    total = int(len(df))
    warn_err = int(df["log_level"].isin(ANOMALY_LEVELS).sum())
    normal = int(total - warn_err)

    # Expected anomalies via rules
    df["_rule_class"] = (df["log_level"] + " " + df["module"] + " " + df["message"]).apply(
        lambda s: classify_log_entry(str(s))
    )
    expected_idx = list(df.index[df["_rule_class"] == "anomaly"]) 
    expected_count = int(len(expected_idx))

    # Model anomalies if model available
    model_count = 0
    model_idx = []
    if model is not None:
        X, _, _ = extract_features(df.copy(), tfidf_vectorizer=tfidf, scaler=scaler)
        X = X.reindex(columns=feature_columns, fill_value=0)
        if meta and meta.get("type") == "supervised" and hasattr(model, "predict_proba"):
            thr = float(meta.get("threshold", 0.5))
            proba = model.predict_proba(X)[:, 1]
            preds = (proba >= thr).astype(int)
            model_idx = list(np.where(preds == 1)[0])
        else:
            preds = model.predict(X)
            model_idx = list(np.where(np.array(preds) == -1)[0])
        model_count = int(len(model_idx))

    anomaly_rate = (expected_count / total * 100.0) if total else 0.0

    # Compose Markdown
    lines = []
    lines.append("# 📊 Anomaly Detection Report")
    lines.append("")
    lines.append("**Dataset summary**")
    lines.append("")
    lines.append(f"* Total log entries analyzed: **{total}**")
    lines.append(f"* Normal events: **{normal}**")
    lines.append(f"* Warnings/Errors: **{warn_err}**")
    lines.append(f"* Anomalies detected: **{expected_count} (Expected)**")
    lines.append(f"* Anomaly rate: **{anomaly_rate:.0f}%**")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Detected Anomalies (Expected)
    lines.append("## 🔎 Detected Anomalies (Expected)")
    lines.append("")
    for i, idx in enumerate(expected_idx[:max_list], start=1):
        r = df.iloc[idx]
        ts = r.get("timestamp", "?")
        content = f"{r.get('log_level','')} [{r.get('module','')}] {r.get('message','')}".strip()
        reason = rule_reason(r.get("message", ""))
        lines.append(f"{i}. **{ts}** –")
        lines.append(f"   `{content}`")
        lines.append(f"   ➝ *{reason}*")
        lines.append("")
    if not expected_idx:
        lines.append("No expected anomalies found by rules.")
        lines.append("")
    lines.append("---")
    lines.append("")

    # Visualizations (textual)
    lines.append("## 📈 Visualizations (Expected)")
    lines.append("")
    sev_counts = (
        df["log_level"].fillna("INFO").str.upper().value_counts().to_dict()
    )
    info_n = int(sev_counts.get("INFO", 0))
    warn_n = int(sev_counts.get("WARN", 0))
    err_n = int(sev_counts.get("ERROR", 0) + sev_counts.get("FATAL", 0) + sev_counts.get("CRITICAL", 0))
    lines.append("1. **Event Type Distribution**")
    lines.append("")
    lines.append(f"   * INFO: {ascii_bar(info_n)} {info_n}")
    lines.append(f"   * WARN: {ascii_bar(warn_n)} {warn_n}")
    lines.append(f"   * ERROR: {ascii_bar(err_n)} {err_n}")
    lines.append(f"   * ANOMALY (flagged subset): {ascii_bar(expected_count)} {expected_count}")
    if total:
        info_p = info_n / total * 100
        warn_p = warn_n / total * 100
        err_p = err_n / total * 100
        anom_p = expected_count / total * 100
        lines.append("")
        lines.append(f"   *(Pie chart: {info_p:.0f}% INFO, {warn_p:.0f}% WARN, {err_p:.0f}% ERROR, {anom_p:.0f}% flagged anomalies)*")
    lines.append("")
    lines.append("2. **Timeline of Events**")
    lines.append("")
    lines.append("   * A line chart with timestamps on the X-axis and log severity on the Y-axis.")
    if expected_idx:
        ts_marks = ", ".join([str(df.iloc[i]["timestamp"]) for i in expected_idx[:5]])
        lines.append(f"   * Spikes at {ts_marks} marking anomaly points.")
    lines.append("")
    lines.append("3. **Source IP Analysis**")
    lines.append("")
    lines.append("   * Internal IPs (192.168.x.x, 10.x.x.x): Mostly normal traffic.")
    lines.append("   * External IPs: highlight addresses associated with failed logins or errors.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Conclusion comparing model vs expected (if model available)
    lines.append("## ✅ Conclusion")
    lines.append("")
    if model is not None:
        lines.append(f"* Model flagged **{model_count}** anomalies vs **{expected_count}** expected (rule-based).")
        if model_count < expected_count:
            lines.append("* False negatives likely exist; consider threshold tuning or enriching contextual rules.")
        elif model_count > expected_count:
            lines.append("* Model flagged more than expected; review potential false positives.")
        else:
            lines.append("* Model count matches expected signals.")
    else:
        lines.append("* No trained model loaded; report reflects rule-based expectations only.")
    lines.append("* Consider tuning for failed logins, privileged account usage, and critical service errors.")
    lines.append("")

    os.makedirs(os.path.dirname(outfile_md), exist_ok=True)
    with open(outfile_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # Also write a small JSON summary
    summary = {
        "total": int(total),
        "normal": int(normal),
        "warnings_errors": int(warn_err),
        "expected_anomalies": int(expected_count),
        "model_anomalies": int(model_count),
        "expected_indices": [int(i) for i in expected_idx[:max_list]],
        "model_indices": [int(i) for i in model_idx[:max_list]],
        "outfile": str(outfile_md),
    }
    with open(os.path.splitext(outfile_md)[0] + ".json", "w", encoding="utf-8") as jf:
        json.dump(summary, jf, indent=2)


def main():
    ap = argparse.ArgumentParser(description="Generate a Markdown anomaly detection report for a log file")
    ap.add_argument("--file", required=False, help="Path to a structured CSV or plain text log file")
    ap.add_argument("--model-dir", default=".", help="Directory with model.joblib and preprocessors (optional)")
    ap.add_argument("--out", default=None, help="Output .md path (default: ML/reports/<file>_report.md)")
    ap.add_argument("--max-anomalies", type=int, default=20, help="Max anomalies to list in the report")
    args = ap.parse_args()

    # Interactive prompts if not provided via CLI
    file_path = args.file
    if not file_path:
        file_path = input("Enter path to the log file to analyze: ").strip()
    model_dir = args.model_dir or "."
    if not os.path.isdir(model_dir):
        md_in = input(f"Model dir '{model_dir}' not found. Enter model dir (blank for current .): ").strip()
        model_dir = md_in or "."
    out_arg = args.out

    if not os.path.isfile(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return

    df = parse_log_file(file_path)
    if df.empty:
        print(f"[ERROR] No valid entries parsed from {file_path}")
        return

    model_pack = load_model_artifacts(model_dir)

    if out_arg:
        out_md = out_arg if out_arg.lower().endswith(".md") else out_arg + ".md"
    else:
        base = os.path.splitext(os.path.basename(file_path))[0]
        out_md = os.path.join(os.path.dirname(__file__), "reports", f"{base}_report.md")

    generate_report(df, model_pack, out_md, max_list=args.max_anomalies)
    print(f"[REPORT] Wrote Markdown report to {out_md}")


if __name__ == "__main__":
    main()
