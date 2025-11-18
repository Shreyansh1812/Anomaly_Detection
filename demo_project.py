"""
Hybrid Log Anomaly Detection System - Complete Demonstration
=============================================================

This script demonstrates the entire project pipeline:
1. Load/validate baseline training data
2. Load trained ML model
3. Run hybrid detection (Rules + ML) on test logs
4. Validate results against golden set
5. Display comprehensive metrics and findings
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add project paths
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.anomaly_detection_engine import LogAnomalyDetector
from ML.robust_anomaly_trainer import parse_log_file, build_numeric_feature_frame
import joblib
import pandas as pd

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    """Print formatted section header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}")
    print(f"{text.center(70)}")
    print(f"{'='*70}{Colors.ENDC}\n")

def print_success(text):
    """Print success message"""
    print(f"{Colors.OKGREEN}✓ {text}{Colors.ENDC}")

def print_info(text):
    """Print info message"""
    print(f"{Colors.OKCYAN}ℹ {text}{Colors.ENDC}")

def print_warning(text):
    """Print warning message"""
    print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")

def print_error(text):
    """Print error message"""
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")


def _row_to_detector_record(row: pd.Series) -> dict:
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
    for optional in ("http_status", "status_code", "response_bytes", "http_method", "path"):
        if optional in row.index and row.get(optional) is not None:
            record[optional] = row.get(optional)
    return record


def load_test_logs(file_path):
    """Load and parse test log file into a DataFrame with row indices"""
    df = parse_log_file(file_path)
    if isinstance(df, pd.DataFrame):
        df = df.reset_index(drop=True)
        df["_row_index"] = df.index
        return df
    if isinstance(df, list):
        normalized = []
        for idx, entry in enumerate(df):
            if isinstance(entry, dict):
                entry = entry.copy()
                entry.setdefault("_row_index", idx)
                normalized.append(entry)
        return pd.DataFrame(normalized)
    return pd.DataFrame()


def stage1_rule_detection(log_df: pd.DataFrame):
    """Stage 1: Rule-based detection"""
    print_header("STAGE 1: Rule Engine Detection")
    
    detector = LogAnomalyDetector()
    enriched = log_df.reset_index(drop=True)
    if "_row_index" not in enriched.columns:
        enriched["_row_index"] = enriched.index
    detector_records = [_row_to_detector_record(row) for _, row in enriched.iterrows()]
    rule_hits = detector.detect(detector_records)
    
    print_info(f"Total logs analyzed: {len(log_df)}")
    print_success(f"Anomalies detected by rules: {len(rule_hits)}")
    
    if rule_hits:
        print(f"\n{Colors.BOLD}Rule Detection Breakdown:{Colors.ENDC}")
        rule_types = {}
        for hit in rule_hits:
            reasons = hit.get('reasons')
            if not reasons:
                reasons = [hit.get('reason', 'rule_alert')]
            for reason in reasons:
                rule_types[reason] = rule_types.get(reason, 0) + 1
        
        for reason, count in rule_types.items():
            print(f"  • {reason}: {count} anomalies")
    
    return rule_hits


def stage2_ml_detection(log_df: pd.DataFrame, flagged_indices, model_dir):
    """Stage 2: ML-based detection on residual logs"""
    print_header("STAGE 2: ML Specialist Detection (Residual Analysis)")
    
    # Filter out logs already flagged by rules
    residual_mask = ~log_df.index.isin(flagged_indices)
    residual_df = log_df[residual_mask].copy()
    if "module" not in residual_df.columns:
        residual_df["module"] = ""
    residual_df["module"] = residual_df["module"].fillna("")
    residual_df["_row_index"] = residual_df.index
    http_mask = residual_df["module"].str.upper() == "HTTP_ACCESS"
    candidate_df = residual_df[http_mask]
    
    print_info(f"Logs flagged by rules: {len(flagged_indices)}")
    print_info(f"Residual logs for ML analysis: {len(residual_df)}")
    print_info(f"HTTP candidate logs: {len(candidate_df)}")
    
    ml_hits = []
    
    if not candidate_df.empty and os.path.exists(model_dir):
        try:
            # Load trained model
            model = joblib.load(os.path.join(model_dir, "iforest_numeric.joblib"))
            scaler = joblib.load(os.path.join(model_dir, "numeric_scaler.joblib"))
            feature_columns = joblib.load(os.path.join(model_dir, "numeric_feature_columns.joblib"))
            
            print_success(f"Loaded ML model: {model_dir}")
            print_info(f"Features: {feature_columns}")
            
            numeric_frame, _, _ = build_numeric_feature_frame(
                candidate_df,
                scaler=scaler,
                feature_order=list(feature_columns),
                allowed_columns=list(feature_columns),
            )

            if numeric_frame.empty:
                print_warning("Numeric feature frame is empty; skipping ML detection")
            else:
                predictions = model.predict(numeric_frame)
                anomaly_scores = model.decision_function(numeric_frame)

                # Collect ML anomalies
                for idx, pred, score_val in zip(numeric_frame.index, predictions, anomaly_scores):
                    if pred == -1:  # -1 indicates anomaly in IsolationForest
                        row = candidate_df.loc[idx]
                        score = float(score_val)
                        log_payload = row.to_dict()
                        log_payload["_row_index"] = int(row.get("_row_index", idx))
                        ml_hits.append({
                            'log': log_payload,
                            'source': 'ml',
                            'reason': '[numeric_iforest]',
                            'anomaly_score': score
                        })
            
            print_success(f"Anomalies detected by ML: {len(ml_hits)}")
            
            if ml_hits:
                print(f"\n{Colors.BOLD}ML Detections:{Colors.ENDC}")
                for hit in ml_hits:
                    log = hit['log']
                    score = hit['anomaly_score']
                    method = log.get('http_method') or log.get('method', 'GET')
                    path = log.get('path') or log.get('request_path', '<unknown>')
                    bytes_out = log.get('response_bytes', 0)
                    print(f"  • Row {log['_row_index']}: {method} {path} "
                          f"({bytes_out} bytes, score: {score:.3f})")
        
        except Exception as e:
            print_warning(f"ML model not available or error occurred: {e}")
    else:
        print_warning("ML model directory not found or no eligible residual logs to analyze")
    
    return ml_hits, len(residual_df), len(candidate_df)


def validate_with_golden_set(rule_hits, ml_hits, golden_file, total_logs):
    """Validate results against golden set"""
    print_header("STAGE 3: Golden Set Validation")
    
    if not os.path.exists(golden_file):
        print_warning(f"Golden set file not found: {golden_file}")
        return
    
    # Load golden set
    with open(golden_file, 'r') as f:
        golden_data = json.load(f)
    
    if isinstance(golden_data, list):
        golden_anomalies = golden_data
    else:
        golden_anomalies = golden_data.get('anomalies', [])
    
    print_info(f"Golden set: {len(golden_anomalies)} manually-labeled anomalies")
    
    # Build ground truth array
    y_true = [0] * total_logs
    for anomaly in golden_anomalies:
        idx = anomaly.get('row_index', anomaly.get('_row_index'))
        if idx is None:
            continue
        try:
            idx = int(idx)
        except (TypeError, ValueError):
            continue
        if 0 <= idx < total_logs:
            y_true[idx] = 1
    
    # Build prediction arrays
    y_pred_rules = [0] * total_logs
    y_pred_ml = [0] * total_logs
    y_pred_hybrid = [0] * total_logs
    
    def mark_predictions(hits, target_array):
        for hit in hits:
            log_payload = hit.get('log', {})
            idx = log_payload.get('_row_index')
            if idx is None:
                continue
            try:
                idx = int(idx)
            except (TypeError, ValueError):
                continue
            if 0 <= idx < len(target_array):
                target_array[idx] = 1
    
    mark_predictions(rule_hits, y_pred_rules)
    mark_predictions(ml_hits, y_pred_ml)
    for i in range(total_logs):
        y_pred_hybrid[i] = 1 if y_pred_rules[i] or y_pred_ml[i] else 0
    
    # Calculate metrics
    def calculate_metrics(y_true, y_pred, name):
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / len(y_true)
        
        print(f"\n{Colors.BOLD}{name}:{Colors.ENDC}")
        print(f"  Precision: {precision:.3f}  (TP={tp}, FP={fp})")
        print(f"  Recall:    {recall:.3f}  (TP={tp}, FN={fn})")
        print(f"  F1-Score:  {f1:.3f}")
        print(f"  Accuracy:  {accuracy:.3f}")
        print(f"\n  Confusion Matrix:")
        print(f"  [[{tn:>3} {fp:>3}]  ← TN  FP (Normal)")
        print(f"   [{fn:>3} {tp:>3}]] ← FN  TP (Anomaly)")
        
        return {'precision': precision, 'recall': recall, 'f1': f1, 'accuracy': accuracy}
    
    # Calculate and display metrics for each engine
    rule_metrics = calculate_metrics(y_true, y_pred_rules, "Rule Engine Performance")
    ml_metrics = calculate_metrics(y_true, y_pred_ml, "ML Specialist Performance")
    hybrid_metrics = calculate_metrics(y_true, y_pred_hybrid, "Hybrid System Performance")
    
    return hybrid_metrics


def display_summary(total_logs, residual_logs_count, http_candidate_count, rule_hits, ml_hits, hybrid_metrics):
    """Display final summary"""
    print_header("FINAL SUMMARY")
    
    print(f"{Colors.BOLD}Detection Results:{Colors.ENDC}")
    print(f"  Total logs processed: {total_logs}")
    print(f"  Rule engine detections: {len(rule_hits)}")
    print(f"  ML specialist detections: {len(ml_hits)}")
    print(f"  Total hybrid detections: {len(rule_hits) + len(ml_hits)}")
    
    if hybrid_metrics:
        print(f"\n{Colors.BOLD}Performance Metrics:{Colors.ENDC}")
        print(f"  Precision: {Colors.OKGREEN}{hybrid_metrics['precision']:.1%}{Colors.ENDC}")
        print(f"  Recall:    {Colors.OKGREEN}{hybrid_metrics['recall']:.1%}{Colors.ENDC}")
        print(f"  F1-Score:  {Colors.OKGREEN}{hybrid_metrics['f1']:.1%}{Colors.ENDC}")
        print(f"  Accuracy:  {Colors.OKGREEN}{hybrid_metrics['accuracy']:.1%}{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}Key Insights:{Colors.ENDC}")
    print(f"  ✓ Sequential architecture: ML analyzed {residual_logs_count} residual logs")
    print(f"  ✓ HTTP specialists evaluated {http_candidate_count} clean HTTP sessions")
    print(f"  ✓ Rule engine handles 'known-knowns' (severity, keywords, bursts)")
    print(f"  ✓ ML specialist finds 'unknown-unknowns' (statistical outliers)")
    print(f"  ✓ Golden set validation ensures honest, independent metrics")
    
    print(f"\n{Colors.OKGREEN}{Colors.BOLD}✓ PROJECT DEMONSTRATION COMPLETE{Colors.ENDC}\n")


def main():
    """Main demonstration pipeline"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                                                                    ║")
    print("║        HYBRID LOG ANOMALY DETECTION SYSTEM                        ║")
    print("║        Complete Project Demonstration                             ║")
    print("║                                                                    ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.ENDC}")
    
    # Configuration
    TEST_LOG_FILE = "Data/test_logs/test_log15(1).txt"
    MODEL_DIR = "models/http_numeric_specialist"
    GOLDEN_SET_FILE = "Data/golden_sets/test_log15(1).golden.json"
    
    try:
        # Check if files exist
        if not os.path.exists(TEST_LOG_FILE):
            print_error(f"Test log file not found: {TEST_LOG_FILE}")
            return
        
        # Load test logs
        print_header("DATA LOADING")
        log_df = load_test_logs(TEST_LOG_FILE)
        if log_df.empty:
            print_error("Parsed log DataFrame is empty; aborting demo")
            return 1
        print_success(f"Loaded {len(log_df)} logs from {TEST_LOG_FILE}")
        
        # Stage 1: Rule-based detection
        rule_hits = stage1_rule_detection(log_df)
        flagged_indices = set()
        for hit in rule_hits:
            log_payload = hit.get('log', {})
            idx = log_payload.get('_row_index')
            if idx is None:
                continue
            try:
                flagged_indices.add(int(idx))
            except (TypeError, ValueError):
                continue
        
        # Stage 2: ML-based detection
        ml_hits, residual_count, http_candidates = stage2_ml_detection(log_df, flagged_indices, MODEL_DIR)
        
        # Validate against golden set
        hybrid_metrics = None
        if os.path.exists(GOLDEN_SET_FILE):
            hybrid_metrics = validate_with_golden_set(rule_hits, ml_hits, GOLDEN_SET_FILE, len(log_df))
        else:
            print_warning(f"Skipping golden set validation (file not found: {GOLDEN_SET_FILE})")
        
        # Display final summary
        display_summary(len(log_df), residual_count, http_candidates, rule_hits, ml_hits, hybrid_metrics)
        
        # Save results
        results = {
            'timestamp': datetime.now().isoformat(),
            'test_file': TEST_LOG_FILE,
            'total_logs': len(log_df),
            'residual_logs': residual_count,
            'http_candidates': http_candidates,
            'rule_anomalies': [
                {
                    'row_index': hit.get('log', {}).get('_row_index'),
                    'reasons': hit.get('reasons', []),
                    'log': hit.get('log', {})
                } for hit in rule_hits
            ],
            'ml_anomalies': [
                {
                    'row_index': hit.get('log', {}).get('_row_index'),
                    'reason': hit.get('reason'),
                    'anomaly_score': hit.get('anomaly_score'),
                    'log': hit.get('log', {})
                } for hit in ml_hits
            ],
            'metrics': hybrid_metrics
        }
        
        output_file = "ML/reports/demo_results.json"
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print_info(f"Detailed results saved to: {output_file}")
        
    except Exception as e:
        print_error(f"Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
