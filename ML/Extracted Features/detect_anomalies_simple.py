
import os
import pandas as pd
from drain3 import TemplateMiner
from sklearn.ensemble import IsolationForest

def main():
    log_file = input("Please enter the path to your file: ").strip()
    if not os.path.isfile(log_file):
        print("File not found. Please check the path and try again.")
        return
    os.environ["DRAIN3_CONFIG_PATH"] = "drain3.ini"
    import re
    template_miner = TemplateMiner()
    templates = []
    feature_rows = []
    log_lines = []
    severities = []
    event_types = []
    keyword_severity = []
    # Common benign INFO events
    benign_info_events = {'SystemInit', 'ServiceStart', 'Network', 'UserLogin', 'UserLogout'}
    event_freq = {}
    # Define critical keywords and their severity scores
    critical_keywords = {
        'error': 3, 'fail': 3, 'exception': 3, 'critical': 3, 'panic': 3,
        'warn': 2, 'timeout': 2, 'denied': 2, 'unreachable': 2,
        'info': 1, 'start': 1, 'login': 1, 'logout': 1
    }
    # Mine templates and build features per log entry
    healthcheck_cpu = []
    healthcheck_mem = []
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            result = template_miner.add_log_message(line.strip())
            tpl = result['template_mined']
            templates.append(tpl)
            log_lines.append(line.strip())
            # Parse severity and event type
            m = re.search(r'\b(INFO|WARN|ERROR)\b', line)
            severity = m.group(1) if m else 'INFO'
            severities.append(severity)
            evt = None
            evt_match = re.search(r'\[(.*?)\]', line)
            if evt_match:
                evt = evt_match.group(1)
            else:
                evt = tpl.split()[0] if tpl else 'Unknown'
            event_types.append(evt)
            event_freq[evt] = event_freq.get(evt, 0) + 1
            # Keyword severity scoring
            score = 0
            for kw, val in critical_keywords.items():
                if re.search(rf'\b{kw}\b', line, re.IGNORECASE):
                    score = max(score, val)
            keyword_severity.append(score)
            # --- FEAT_ENG_HC_01: Extract and store HealthCheck CPU/Memory ---
            if '[HealthCheck]' in line and 'PASSED' in line:
                cpu_match = re.search(r'CPU:\s*(\d+)%', line)
                mem_match = re.search(r'Memory:\s*(\d+)%', line)
                cpu_val = float(cpu_match.group(1)) if cpu_match else 0.0
                mem_val = float(mem_match.group(1)) if mem_match else 0.0
                healthcheck_cpu.append(cpu_val)
                healthcheck_mem.append(mem_val)
            else:
                healthcheck_cpu.append(None)
                healthcheck_mem.append(None)
    all_templates = list(set(templates))
    # Feature: one-hot encoding of template per entry, severity, event type, frequency, keyword severity
    for i, tpl in enumerate(templates):
        row = {t: 0 for t in all_templates}
        row[tpl] = 1
        # Severity encoding
        for sev in ['INFO', 'WARN', 'ERROR']:
            row[f'sev_{sev}'] = int(severities[i] == sev)
        # Event type encoding
        for evt in set(event_types):
            row[f'evt_{evt}'] = int(event_types[i] == evt)
        # Frequency feature
        row['event_freq'] = event_freq[event_types[i]]
        # Keyword severity feature
        row['keyword_severity'] = keyword_severity[i]
        # --- FEAT_ENG_HC_01: Add normalized HealthCheck CPU/Memory ---
        # These features are normalized below using MinMaxScaler
        row['healthcheck_cpu'] = healthcheck_cpu[i]
        row['healthcheck_mem'] = healthcheck_mem[i]
        feature_rows.append(row)
    features = pd.DataFrame(feature_rows)
    # --- FEAT_ENG_HC_01: Normalize HealthCheck CPU/Memory ---
    from sklearn.preprocessing import MinMaxScaler
    scaler = MinMaxScaler()
    hc_cpu = features['healthcheck_cpu'].fillna(0).values.reshape(-1, 1)
    hc_mem = features['healthcheck_mem'].fillna(0).values.reshape(-1, 1)
    features['healthcheck_cpu_norm'] = scaler.fit_transform(hc_cpu)
    features['healthcheck_mem_norm'] = scaler.fit_transform(hc_mem)
    # Comment: Normalizing HealthCheck CPU/Memory prevents common operational values from being flagged as anomalies.
    # TF-IDF features
    from sklearn.feature_extraction.text import TfidfVectorizer
    tfidf = TfidfVectorizer(max_features=20, stop_words='english')
    tfidf_matrix = tfidf.fit_transform(log_lines)
    tfidf_df = pd.DataFrame(tfidf_matrix.todense(), columns=[f'tfidf_{w}' for w in tfidf.get_feature_names_out()])
    features = pd.concat([features, tfidf_df], axis=1)

    # Run Isolation Forest
    if len(features) == 0:
        print("No log entries found. Check log format.")
        return
    # Threshold tuning: allow user to set quantile
    try:
        quantile = float(input("Enter anomaly threshold quantile (e.g., 0.05 for 5%): ").strip())
        if not (0 < quantile < 1):
            quantile = 0.10
    except Exception:
        quantile = 0.10
    # --- TUNING_SENSITIVITY_01: Try multiple contamination values and print metrics ---
    from sklearn.metrics import precision_score, recall_score, f1_score
    contamination_values = [0.20, 0.18, 0.16]
    best_f1 = -1
    best_contam = contamination_values[0]
    best_preds = None
    best_scores = None
    for contam in contamination_values:
        model = IsolationForest(n_estimators=100, contamination=contam, random_state=42)
        model.fit(features)
        scores = model.decision_function(features)
        preds = (scores < pd.Series(scores).quantile(contam)).astype(int)
        # --- POST_PROC_FILTER_01: Override PASSED HealthCheck anomalies ---
        for idx, (pred, log) in enumerate(zip(preds, log_lines)):
            if pred == 1 and '[HealthCheck]' in log and 'PASSED' in log:
                preds[idx] = 0  # Override: known benign
        # For metrics, assume ground truth: anomaly if not PASSED HealthCheck and severity is WARN/ERROR or keyword_severity >=2
        gt = [1 if (('[HealthCheck]' not in log or 'PASSED' not in log) and (sev in ['WARN', 'ERROR'] or keyword_severity[i] >= 2)) else 0 for i, (log, sev) in enumerate(zip(log_lines, severities))]
        precision = precision_score(gt, preds)
        recall = recall_score(gt, preds)
        f1 = f1_score(gt, preds)
        print(f"Contamination={contam:.2f} | Precision={precision:.3f} | Recall={recall:.3f} | F1={f1:.3f}")
        if f1 > best_f1:
            best_f1 = f1
            best_contam = contam
            best_preds = preds.copy()
            best_scores = scores.copy()
    # Use best contamination value
    print(f"\nBest contamination value: {best_contam:.2f} (F1={best_f1:.3f})")
    features['anomaly_score'] = best_scores
    features['log_entry'] = log_lines
    features['severity'] = severities
    features['event_type'] = event_types
    # Quantile-based threshold
    threshold = pd.Series(best_scores).quantile(best_contam)
    # Rule-based pre-filter: guarantee critical anomalies
    def rule_based_anomaly(row):
        return (row['keyword_severity'] >= 2) or (row['severity'] in ['WARN', 'ERROR'])
    features['is_anomaly'] = ((features['anomaly_score'] < threshold) | features.apply(rule_based_anomaly, axis=1)).astype(int)
    # --- POST_PROC_FILTER_01: Override PASSED HealthCheck anomalies in final output ---
    for idx, log in enumerate(log_lines):
        if features.at[idx, 'is_anomaly'] == 1 and '[HealthCheck]' in log and 'PASSED' in log:
            features.at[idx, 'is_anomaly'] = 0

    # Save output in dedicated folder
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'Analysis', 'Output')
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.basename(log_file)
    output_path = os.path.join(output_dir, base_name + '_anomaly_report.csv')
    features.to_csv(output_path, index=False)
    print(f"Anomaly report saved to: {output_path}")

    # Generate concise human-readable report
    report_path = os.path.join(output_dir, base_name + '_isolation_forest_report.txt')
    num_entries = len(features)
    num_features = len(all_templates)
    num_anomalies = features['is_anomaly'].sum()
    anomaly_pct = (num_anomalies / num_entries) * 100 if num_entries else 0
    strong_thresh = threshold - 0.01 * abs(threshold)  # 1% below threshold
    # Post-filtering: suppress benign INFO events unless rare
    def is_benign_info(row):
        return (row['severity'] == 'INFO' and row['event_type'] in benign_info_events and row['event_freq'] > 1)
    # Critical: WARN/ERROR or rare INFO events
    critical_anomalies = features[(features['is_anomaly'] == 1) & ((features['severity'].isin(['WARN', 'ERROR'])) | (~features.apply(is_benign_info, axis=1)))]
    benign_anomalies = features[(features['is_anomaly'] == 1) & (features.apply(is_benign_info, axis=1))]
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('Isolation Forest Log Analysis Report\n')
        f.write('====================================\n\n')
        f.write(f'Total log entries tested : {num_entries}\n')
        f.write(f'Features per entry       : {num_features}\n')
        f.write(f'Anomalies detected       : {num_anomalies}\n')
        f.write(f'Anomaly percentage       : {anomaly_pct:.1f}%\n')
        f.write(f'Threshold used ({int(quantile*100)}% quantile): {threshold:.3f}\n\n')
        f.write('Critical Anomalies (WARN/ERROR or rare INFO):\n')
        for i, row in enumerate(critical_anomalies.sort_values('anomaly_score').itertuples(), 1):
            f.write(f'{i}. [Entry {row.Index}] [{row.severity}] [{row.event_type}] {row.log_entry} → Score: {row.anomaly_score:.3f}\n')
        f.write('\nBenign Anomalies (common INFO events):\n')
        for i, row in enumerate(benign_anomalies.sort_values('anomaly_score').itertuples(), 1):
            f.write(f'{i}. [Entry {row.Index}] [{row.severity}] [{row.event_type}] {row.log_entry} → Score: {row.anomaly_score:.3f}\n')

    # Visualizations: save in dedicated Plots folder
    plots_dir = os.path.join(os.path.dirname(output_dir), 'Plots')
    os.makedirs(plots_dir, exist_ok=True)
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        import numpy as np
        # Histogram of anomaly scores
        plt.figure(figsize=(8,4))
        sns.histplot(features['anomaly_score'].to_numpy(), bins=30, color='skyblue', edgecolor='black')
        plt.axvline(threshold, color='red', linestyle='--', label=f'Threshold ({quantile*100:.0f}%)')
        plt.title('Anomaly Score Distribution')
        plt.xlabel('Anomaly Score')
        plt.ylabel('Count')
        plt.legend()
        hist_path = os.path.join(plots_dir, base_name + '_anomaly_score_histogram.png')
        plt.tight_layout()
        plt.savefig(hist_path)
        plt.close()
        print(f"Histogram plot saved to: {hist_path}")

        # Bar chart: count of critical vs benign anomalies
        plt.figure(figsize=(6,4))
        anomaly_counts = [len(critical_anomalies), len(benign_anomalies)]
        sns.barplot(x=['Critical', 'Benign'], y=anomaly_counts, palette=['#d7263d', '#1b998b'])
        plt.title('Anomaly Type Counts')
        plt.ylabel('Count')
        bar_path = os.path.join(plots_dir, base_name + '_anomaly_type_bar.png')
        plt.tight_layout()
        plt.savefig(bar_path)
        plt.close()
        print(f"Bar chart saved to: {bar_path}")

        # Timeline plot: anomalies over time, color-coded by severity
        # Try to extract timestamps from log entries
        import datetime
        def extract_time(log):
            m = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,\.]\d+)', log)
            if m:
                try:
                    return datetime.datetime.strptime(m.group(1).replace(',', '.'), '%Y-%m-%d %H:%M:%S.%f')
                except Exception:
                    return None
            return None
        anomaly_df = pd.concat([critical_anomalies, benign_anomalies])
        anomaly_df = anomaly_df.copy()
        anomaly_df['timestamp'] = anomaly_df['log_entry'].apply(extract_time)
        anomaly_df = anomaly_df.dropna(subset=['timestamp'])
        plt.figure(figsize=(10,4))
        colors = anomaly_df['severity'].map({'ERROR': '#d7263d', 'WARN': '#fbb13c', 'INFO': '#1b998b'})
        plt.scatter(anomaly_df['timestamp'], anomaly_df['anomaly_score'], c=colors, s=60, edgecolor='black')
        plt.axhline(threshold, color='red', linestyle='--', label='Threshold')
        plt.title('Anomalies Over Time')
        plt.xlabel('Timestamp')
        plt.ylabel('Anomaly Score')
        plt.legend()
        timeline_path = os.path.join(plots_dir, base_name + '_anomaly_timeline.png')
        plt.tight_layout()
        plt.savefig(timeline_path)
        plt.close()
        print(f"Timeline plot saved to: {timeline_path}")
    except Exception as e:
        print(f"Could not generate one or more plots: {e}")

    print(f"Human-readable report saved to: {report_path}")

if __name__ == "__main__":
    main()
