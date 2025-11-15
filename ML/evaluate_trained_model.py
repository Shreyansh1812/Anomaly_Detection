from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
import joblib
try:
    from sklearn.exceptions import InconsistentVersionWarning  # type: ignore
except (ImportError, AttributeError):
    class InconsistentVersionWarning(UserWarning):
        """Fallback warning when running on older/newer scikit-learn versions."""
        pass
import warnings

# allow local imports
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ML.robust_anomaly_trainer import build_numeric_feature_frame, parse_log_file
from src.anomaly_detection_engine import LogAnomalyDetector

warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

ANOMALY_LEVELS = {"WARN", "ERROR", "FATAL", "CRITICAL"}

SUGGESTION_MAP = {
    "sshd": "Repeated authentication failures—tighten SSH access controls and monitor offending IPs.",
    "pam_unix": "Credential-related issues—enforce strong passwords and investigate user accounts.",
    "database": "Database connectivity problems—check DB availability and network paths.",
    "mysql": "MySQL errors—verify service health and firewall settings.",
    "kernel": "Kernel/system faults—inspect hardware resources and recent kernel changes.",
    "httpd": "HTTP service anomalies—inspect web server configs and client behavior.",
}

NUMERIC_FEATURE_SUBSET: Sequence[str] = ("message_length", "response_bytes")


def load_numeric_artifacts(model_dir: Optional[str]):
    if not model_dir:
        return None
    base = Path(model_dir)
    try:
        model = joblib.load(base / "iforest_numeric.joblib")
        scaler = joblib.load(base / "numeric_scaler.joblib")
        feature_columns = joblib.load(base / "numeric_feature_columns.joblib")
    except FileNotFoundError as exc:
        missing = exc.filename or str(exc)
        print(f"[WARN] Numeric artifacts missing ({missing}); ML engine disabled.")
        return None

    meta_path = base / "numeric_model_meta.json"
    meta = None
    if meta_path.exists():
        try:
            with open(meta_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
        except json.JSONDecodeError:
            meta = None

    return {
        "model": model,
        "scaler": scaler,
        "feature_columns": feature_columns,
        "meta": meta,
    }


def count_file_lines(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            total = sum(1 for _ in f)
        if path.lower().endswith(".csv") and total > 0:
            return max(total - 1, 0)
        return total
    except Exception:
        return 0


def summarize_root_cause(df_subset: pd.DataFrame):
    if df_subset.empty:
        return {
            "module": None,
            "description": "No anomalies detected—system operating within expected parameters.",
            "suggestion": "Continue monitoring; no immediate remediation required.",
        }
    top_module = df_subset["module"].value_counts().idxmax()
    suggestion = None
    for key, msg in SUGGESTION_MAP.items():
        if key in str(top_module or "").lower():
            suggestion = msg
            break
    if not suggestion:
        suggestion = "Review the highlighted module for misconfiguration or unusual activity."
    description = f"Most anomalies originate from module '{top_module}'."
    return {"module": top_module, "description": description, "suggestion": suggestion}


def format_anomaly_entries(df_subset: pd.DataFrame):
    entries = []
    for _, row in df_subset.iterrows():
        entries.append(
            f"{row['timestamp']} – {row['log_level']} [{row['module']}] {row['message']}"
        )
    return entries


def _to_detector_record(row: pd.Series) -> Dict[str, Any]:
    record = {
        "timestamp": str(row.get("timestamp", "")),
        "log_level": str(row.get("log_level", "")),
        "module": str(row.get("module", "")),
        "message": str(row.get("message", "")),
        "_row_index": int(row.get("_row_index", 0)),
    }
    for ip_field in ("ip", "client_ip", "source_ip"):
        if ip_field in row.index and row.get(ip_field) is not None:
            record[ip_field] = row.get(ip_field)
    if "http_status" in row.index and row.get("http_status") is not None:
        record["http_status"] = row.get("http_status")
    if "response_bytes" in row.index and row.get("response_bytes") is not None:
        record["response_bytes"] = row.get("response_bytes")
    if "http_method" in row.index and row.get("http_method") is not None:
        record["http_method"] = row.get("http_method")
    if "path" in row.index and row.get("path") is not None:
        record["path"] = row.get("path")
    return record


def evaluate_on_file(
    path: str,
    detector: Optional[LogAnomalyDetector] = None,
    numeric_model=None,
    numeric_scaler=None,
    numeric_feature_columns: Optional[Sequence[str]] = None,
    numeric_feature_subset: Sequence[str] = NUMERIC_FEATURE_SUBSET,
):
    df = parse_log_file(path)
    if df.empty:
        print(f"[WARN] No valid data in {path}; skipping.")
        return None

    df = df.reset_index(drop=True)
    total_lines = count_file_lines(path)
    df["is_anomaly"] = df["log_level"].apply(lambda x: 1 if x in ANOMALY_LEVELS else 0)

    detector_records: List[Dict[str, Any]] = []
    if detector is not None:
        enriched = df.reset_index().rename(columns={"index": "_row_index"})
        detector_records = [_to_detector_record(row) for _, row in enriched.iterrows()]

    rule_based_hits = detector.detect(detector_records) if detector else []

    preds_binary = np.zeros(len(df), dtype=int)
    final_hits: List[Dict[str, Any]] = []
    flagged_indices = set()
    for hit in rule_based_hits:
        hit["source"] = "rule"
        row_idx = hit.get("log", {}).get("_row_index")
        if row_idx is not None:
            try:
                idx_int = int(row_idx)
            except (TypeError, ValueError):
                idx_int = None
            if idx_int is not None and 0 <= idx_int < len(df):
                preds_binary[idx_int] = 1
                flagged_indices.add(idx_int)
        final_hits.append(hit)

    ml_hits: List[Dict[str, Any]] = []
    if numeric_model is not None and numeric_scaler is not None and numeric_feature_columns is not None:
        normal_mask = ~df.index.isin(flagged_indices)
        residual_df = df[normal_mask].copy()
        residual_df["_row_index"] = residual_df.index
        residual_df["module"] = residual_df["module"].fillna("")
        http_mask = residual_df["module"].str.upper() == "HTTP_ACCESS"
        candidate_df = residual_df[http_mask]
        if not candidate_df.empty:
            numeric_frame, _, _ = build_numeric_feature_frame(
                candidate_df,
                scaler=numeric_scaler,
                feature_order=list(numeric_feature_columns),
                allowed_columns=list(numeric_feature_subset),
            )
            if not numeric_frame.empty:
                preds = numeric_model.predict(numeric_frame)
                anomaly_mask = preds == -1
                anomaly_indices = numeric_frame.index[anomaly_mask]
                for idx in anomaly_indices:
                    row = df.loc[idx]
                    log_payload = {**{k: v for k, v in row.items() if k != "is_anomaly"}, "_row_index": int(idx)}
                    preds_binary[idx] = 1
                    ml_hits.append(
                        {
                            "source": "ml",
                            "reasons": ["numeric_iforest"],
                            "log": log_payload,
                        }
                    )
    final_hits.extend(ml_hits)

    report = classification_report(
        df["is_anomaly"], preds_binary, output_dict=True, zero_division=0
    )
    cm = confusion_matrix(df["is_anomaly"], preds_binary)

    anomalies_idx = np.where(preds_binary == 1)[0]
    anomaly_rows = df.iloc[anomalies_idx]
    preview = anomaly_rows[["timestamp", "log_level", "module", "message"]].head(20)

    severity_alerts = sum("severity" in hit.get("reasons", []) for hit in rule_based_hits)

    return {
        "file": path,
        "report": report,
        "confusion_matrix": cm.tolist(),
        "anomaly_preview": preview.to_dict(orient="records"),
        "counts": {
            "raw_total": int(total_lines or len(df)),
            "total": int(len(df)),
            "true_anomalies": int(df["is_anomaly"].sum()),
            "predicted_anomalies": int((preds_binary == 1).sum()),
            "rule_alerts": len(final_hits),
            "severity_alerts": int(severity_alerts),
        },
        "anomaly_entries": format_anomaly_entries(anomaly_rows),
        "root_cause": summarize_root_cause(anomaly_rows),
        "rule_based_hits": final_hits,
    }


def save_report(out_path: Path, results: List[Dict]):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "files": results,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"[INFO] Saved evaluation summary to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate trained anomaly model on logs.")
    parser.add_argument(
        "--files",
        nargs="+",
        required=True,
        help="One or more log files/CSVs to evaluate.",
    )
    parser.add_argument("--out", help="Optional JSON file to store full results.")
    parser.add_argument(
        "--disable-rule-detector",
        action="store_true",
        help="Skip the rule-based LogAnomalyDetector augmentation.",
    )
    parser.add_argument(
        "--numeric-model-dir",
        default="models/numeric_baseline",
        help="Directory containing the numeric IsolationForest artifacts.",
    )
    parser.add_argument(
        "--disable-ml-detector",
        action="store_true",
        help="Skip the numeric IsolationForest stage.",
    )
    args = parser.parse_args()

    detector = None if args.disable_rule_detector else LogAnomalyDetector()
    numeric_artifacts = None
    if not args.disable_ml_detector and args.numeric_model_dir:
        numeric_artifacts = load_numeric_artifacts(args.numeric_model_dir)

    results = []
    for f in args.files:
        res = evaluate_on_file(
            f,
            detector=detector,
            numeric_model=(numeric_artifacts or {}).get("model") if numeric_artifacts else None,
            numeric_scaler=(numeric_artifacts or {}).get("scaler") if numeric_artifacts else None,
            numeric_feature_columns=(numeric_artifacts or {}).get("feature_columns") if numeric_artifacts else None,
            numeric_feature_subset=(
                tuple((numeric_artifacts or {}).get("meta", {}).get("feature_order", ()))
                or NUMERIC_FEATURE_SUBSET
            ),
        )
        if res:
            results.append(res)

    if args.out and results:
        save_report(Path(args.out), results)

    if not results:
        print("[WARN] No evaluation results to display.")
        return

    for res in results:
        f = res["file"]
        rep = res["report"]
        precision = rep.get("1", {}).get("precision", 0.0)
        recall = rep.get("1", {}).get("recall", 0.0)

        print(f"\n=== {os.path.basename(f)} ===")
        print(f"Total Lines : {res['counts']['raw_total']}")
        print(f"Read Lines : {res['counts']['total']}")
        print(f"Recall : {recall:.3f}")
        print(f"Precision : {precision:.3f}")
        print("\nList of Anomalies recorded :")
        if res["anomaly_entries"]:
            for idx, entry in enumerate(res["anomaly_entries"], 1):
                print(f"{idx}. {entry}")
        else:
            print("(No anomalies were flagged for this file.)")

        if res.get("rule_based_hits"):
            print("\nHybrid detector alerts (rule + ml):")
            for idx, hit in enumerate(res["rule_based_hits"], 1):
                reasons = ",".join(hit.get("reasons", [])) or "(no reasons)"
                msg = hit.get("log", {}).get("message", "")
                source = hit.get("source", "unknown")
                print(f"{idx}. ({source}) [{reasons}] {msg}")
        else:
            print("\nHybrid detector alerts: (none)")

        root = res["root_cause"]
        print(
            "\nThe Major cause / location from where the anomalies are coming and a small suggestion"
        )
        print(f"Cause : {root['description']}")
        print(f"Suggestion : {root['suggestion']}")


if __name__ == "__main__":
    main()