import os
import argparse
import json
from datetime import datetime
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix

import sys
# Support running as a script from within the ML folder
if __package__ is None or __package__ == "":
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from ML.robust_anomaly_trainer import parse_log_file, extract_features
else:
    from .robust_anomaly_trainer import parse_log_file, extract_features


ANOMALY_LEVELS = {"WARN", "ERROR", "FATAL", "CRITICAL"}


def load_artifacts(model_dir: str):
    model = joblib.load(os.path.join(model_dir, "model.joblib"))
    tfidf = joblib.load(os.path.join(model_dir, "tfidf.joblib"))
    scaler = joblib.load(os.path.join(model_dir, "scaler.joblib"))
    feature_columns = joblib.load(os.path.join(model_dir, "feature_columns.joblib"))
    meta_path = os.path.join(model_dir, "model_meta.json")
    meta = None
    if os.path.exists(meta_path):
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    return model, tfidf, scaler, feature_columns, meta


def evaluate_on_file(path: str, model, tfidf, scaler, feature_columns, meta=None):
    df = parse_log_file(path)
    if df.empty:
        print(f"[WARN] No valid data in {path}; skipping.")
        return None
    df["is_anomaly"] = df["log_level"].apply(lambda x: 1 if x in ANOMALY_LEVELS else 0)

    X, _, _ = extract_features(df.drop("is_anomaly", axis=1), tfidf_vectorizer=tfidf, scaler=scaler)
    X = X.reindex(columns=feature_columns, fill_value=0)

    preds_binary = None
    if meta and meta.get("type") == "supervised" and hasattr(model, "predict_proba"):
        thr = float(meta.get("threshold", 0.5))
        proba = model.predict_proba(X)[:, 1]
        preds_binary = (proba >= thr).astype(int)
    else:
        preds = model.predict(X)
        preds_binary = np.where(preds == -1, 1, 0)

    report = classification_report(df["is_anomaly"], preds_binary, output_dict=True, zero_division=0)
    cm = confusion_matrix(df["is_anomaly"], preds_binary)

    # Collect top anomalies for qualitative review
    anomalies_idx = np.where(preds_binary == 1)[0]
    preview = df.iloc[anomalies_idx][["timestamp", "log_level", "module", "message"]].head(20)

    return {
        "file": path,
        "report": report,
        "confusion_matrix": cm.tolist(),
        "anomaly_preview": preview.to_dict(orient="records"),
        "counts": {
            "total": int(len(df)),
            "true_anomalies": int(df["is_anomaly"].sum()),
            "predicted_anomalies": int(int((preds_binary == 1).sum())),
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Evaluate a trained anomaly model on CSV logs")
    ap.add_argument("--model-dir", default=".", help="Directory containing model.joblib and preprocessors")
    ap.add_argument("--files", nargs="+", required=True, help="One or more CSV file paths to evaluate")
    ap.add_argument("--out", default=None, help="Optional path to write a JSON and CSV report")
    args = ap.parse_args()

    model, tfidf, scaler, feature_columns, meta = load_artifacts(args.model_dir)

    results = []
    summary_rows = []
    for f in args.files:
        res = evaluate_on_file(f, model, tfidf, scaler, feature_columns, meta)
        if not res:
            continue
        results.append(res)
        rep = res["report"]
        summary_rows.append({
            "file": os.path.basename(f),
            "accuracy": rep.get("accuracy", 0.0),
            "f1_anomaly": rep.get("1", {}).get("f1-score", 0.0),
            "recall_anomaly": rep.get("1", {}).get("recall", 0.0),
            "precision_anomaly": rep.get("1", {}).get("precision", 0.0),
            "true_anomalies": res["counts"]["true_anomalies"],
            "predicted_anomalies": res["counts"]["predicted_anomalies"],
            "total": res["counts"]["total"],
        })

        # Pretty print per-file summary
        print(f"\n=== {os.path.basename(f)} ===")
        print(f"Total={summary_rows[-1]['total']} true_anom={summary_rows[-1]['true_anomalies']} pred_anom={summary_rows[-1]['predicted_anomalies']}")
        print(f"Accuracy={summary_rows[-1]['accuracy']:.3f} F1(Anom)={summary_rows[-1]['f1_anomaly']:.3f} Recall(Anom)={summary_rows[-1]['recall_anomaly']:.3f}")
        print("Top anomalies preview:")
        for r in res["anomaly_preview"]:
            print(f" - [{r['timestamp']}] {r['log_level']} [{r['module']}] {r['message']}")

    if args.out:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_base = args.out
        os.makedirs(os.path.dirname(out_base), exist_ok=True)
        # JSON dump with full details
        with open(out_base + f"_{ts}.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        # CSV summary
        pd.DataFrame(summary_rows).to_csv(out_base + f"_{ts}.csv", index=False)
        print(f"\n[REPORT] Wrote reports to {out_base}_{ts}.json and .csv")


if __name__ == "__main__":
    main()
