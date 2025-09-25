import os
import glob
import time
import json
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report

from ML.robust_anomaly_trainer import parse_log_file, extract_features


ANOMALY_LEVELS = {"WARN", "ERROR", "FATAL", "CRITICAL"}


def discover_datasets():
    roots = [
        os.path.join("Data", "raw_logs"),
        os.path.join("Regex", "Data", "raw_logs"),
    ]
    files = []
    for r in roots:
        files.extend(glob.glob(os.path.join(r, "**", "*.csv"), recursive=True))
    # Prefer structured CSVs
    files = [f for f in files if f.lower().endswith("log_structured.csv")]
    return sorted(files)


def load_dataset(path):
    df = parse_log_file(path)
    if df.empty:
        return df
    df["is_anomaly"] = df["log_level"].apply(lambda x: 1 if x in ANOMALY_LEVELS else 0)
    return df


def fit_and_eval(train_df, test_df, contamination):
    X_train_raw = train_df.drop("is_anomaly", axis=1)
    y_train = train_df["is_anomaly"]
    X_test_raw = test_df.drop("is_anomaly", axis=1)
    y_test = test_df["is_anomaly"]

    # Fit preprocessors on train, transform both
    X_train, vec, scaler = extract_features(X_train_raw)
    X_test, _, _ = extract_features(X_test_raw, tfidf_vectorizer=vec, scaler=scaler)

    # Align columns
    missing_in_test = set(X_train.columns) - set(X_test.columns)
    for c in missing_in_test:
        X_test[c] = 0
    X_test = X_test[X_train.columns]

    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(X_train)
    preds = model.predict(X_test)
    preds_binary = np.where(preds == -1, 1, 0)
    report = classification_report(y_test, preds_binary, output_dict=True, zero_division=0)
    return report


def leave_one_out(datasets, contaminations=(0.05, 0.10, 0.15, 0.20)):
    results = []
    for i, test_path in enumerate(datasets):
        train_paths = [p for j, p in enumerate(datasets) if j != i]
        train_frames = [load_dataset(p) for p in train_paths]
        train_frames = [df for df in train_frames if not df.empty]
        test_df = load_dataset(test_path)
        if not train_frames or test_df.empty:
            print(f"[WARN] Skipping LOO for {test_path} due to empty data.")
            continue
        train_df = pd.concat(train_frames, ignore_index=True)
        for cont in contaminations:
            rep = fit_and_eval(train_df, test_df, cont)
            results.append({
                "test_dataset": os.path.basename(test_path),
                "contamination": cont,
                "f1_anomaly": rep.get('1', {}).get('f1-score', 0.0),
                "recall_anomaly": rep.get('1', {}).get('recall', 0.0),
                "precision_anomaly": rep.get('1', {}).get('precision', 0.0),
                "accuracy": rep.get('accuracy', 0.0),
                "f1_weighted": rep.get('weighted avg', {}).get('f1-score', 0.0),
            })
            print(f"[LOO] test={os.path.basename(test_path)} cont={cont:.2f} f1(1)={results[-1]['f1_anomaly']:.3f} acc={results[-1]['accuracy']:.3f}")
    return pd.DataFrame(results)


def train_all_and_save(datasets, contamination=0.10):
    frames = [load_dataset(p) for p in datasets]
    frames = [df for df in frames if not df.empty]
    if not frames:
        print("[ERROR] No data to train.")
        return None
    all_df = pd.concat(frames, ignore_index=True)
    X_raw = all_df.drop("is_anomaly", axis=1)
    y = all_df["is_anomaly"]
    X, vec, scaler = extract_features(X_raw)
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    model.fit(X)

    # Persist artifacts in timestamped dir
    import joblib
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join("models", f"iforest_all_{ts}")
    os.makedirs(out_dir, exist_ok=True)
    joblib.dump(model, os.path.join(out_dir, "model.joblib"))
    joblib.dump(vec, os.path.join(out_dir, "tfidf.joblib"))
    joblib.dump(scaler, os.path.join(out_dir, "scaler.joblib"))
    joblib.dump(list(X.columns), os.path.join(out_dir, "feature_columns.joblib"))
    manifest = {"datasets": datasets, "contamination": contamination, "timestamp": ts}
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[SAVE] Model and preprocessors saved to {out_dir}")
    return out_dir


def main():
    datasets = discover_datasets()
    if not datasets:
        print("No structured CSV datasets found.")
        return
    print("Discovered datasets:")
    for p in datasets:
        print(" -", p)

    print("\nRunning Leave-One-Dataset-Out (LOO) evaluation...")
    df_res = leave_one_out(datasets)
    os.makedirs(os.path.join("ML", "reports"), exist_ok=True)
    out_csv = os.path.join("ML", "reports", "lodo_results.csv")
    df_res.to_csv(out_csv, index=False)
    print(f"[REPORT] LOO results written to {out_csv}")

    # Pick contamination with best mean f1 on anomalies
    if not df_res.empty:
        agg = df_res.groupby("contamination")["f1_anomaly"].mean().sort_values(ascending=False)
        best_cont = float(agg.index[0])
        print(f"Best contamination by mean f1(anomaly): {best_cont:.2f}")
    else:
        best_cont = 0.10

    print("\nTraining final model on all datasets...")
    out_dir = train_all_and_save(datasets, contamination=best_cont)
    if out_dir:
        print(f"Done. Use this directory for scoring: {out_dir}")


if __name__ == "__main__":
    main()
