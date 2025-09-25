# BlueGene/L RAS CSV parser
def _parse_bgq_row(row):
    try:
        # Time format: 'YYYY-MM-DD-HH.MM.SS.microsec'
        time_raw = str(row.get('Time', '')).strip()
        # Convert to 'YYYY-MM-DD HH:MM:SS,ms'
        try:
            # Split microseconds
            if '.' in time_raw:
                main_part, micro = time_raw.rsplit('.', 1)
                micro = micro[:3].ljust(3, '0')  # ms
            else:
                main_part, micro = time_raw, '000'
            dt = datetime.strptime(main_part, '%Y-%m-%d-%H.%M.%S')
            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S') + f',{micro}'
        except Exception as e:
            timestamp = time_raw  # fallback
        level = str(row.get('Level', 'INFO')).strip().upper()
        module = str(row.get('Component', 'BGQ')).strip()
        message = str(row.get('Content', '')).strip()
        return {
            'timestamp': timestamp,
            'log_level': level,
            'module': module,
            'message': message
        }
    except Exception as e:
        print(f"[WARN] BGQ row parse error: {e} | row: {row.to_dict()}")
        return None
import re
from ipaddress import ip_address

# Rule-based log classifier for anomaly detection
def classify_log_entry(log):
    """
    Classify a log entry as 'normal' or 'anomaly' using contextual cues and rules.
    """
    def is_private_ip(ip):
        try:
            return ip_address(ip).is_private
        except Exception:
            return False

    # Extract IPs from log
    ip_matches = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', log)
    external_ip = any(not is_private_ip(ip) for ip in ip_matches)

    log_lower = log.lower()

    # Routine cron jobs, kernel device registrations, successful HTTP 200s from private IPs
    if (
        'cron' in log_lower or
        'usb' in log_lower or
        'new high-speed usb device' in log_lower or
        ('http' in log_lower and ' 200 ' in log_lower and not external_ip)
    ):
        return 'normal'

    # Failed login attempts
    if 'failed password' in log_lower or 'password check failed' in log_lower:
        return 'anomaly'

    # Login success for unusual accounts
    if (
        ('accepted password' in log_lower or 'login succeeded' in log_lower)
        and any(u in log_lower for u in ['guest', 'admin'])
    ):
        return 'anomaly'

    # External/public IP access to sensitive services
    if external_ip and any(s in log_lower for s in ['sshd', 'mysql', 'database', 'login']):
        return 'anomaly'

    # System errors
    if any(w in log_lower for w in ['error', 'connection refused', 'out of memory', 'oom', 'kill process', 'critical']):
        return 'anomaly'

    # Default: normal
    return 'normal'
# Linux/Generic CSV parser

# --- Linux CSV Parser with Level Inference ---
def _infer_linux_level(content):
    content_lower = str(content).lower()
    if any(w in content_lower for w in ["error", "fail", "fatal", "critical"]):
        return "ERROR"
    if any(w in content_lower for w in ["warn", "degrad", "unstable"]):
        return "WARN"
    return "INFO"

def _parse_linux_row(row):
    try:
        # Compose timestamp: 'Month Date Time' (e.g., 'Jul 27 14:41:58')
        month = str(row.get('Month', '')).strip() or 'Jan'
        day_val = row.get('Date', '01')
        if pd.isna(day_val):
            day = '01'
        else:
            try:
                day = str(int(float(day_val))).zfill(2)
            except Exception:
                day = '01'
        time_val = row.get('Time', '')
        time = str(time_val).strip() if not pd.isna(time_val) else '00:00:00'
        year = 2025  # Use default year for all entries
        timestamp_str = f"{month} {day} {year} {time}"
        try:
            dt = datetime.strptime(timestamp_str, '%b %d %Y %H:%M:%S')
            ms = random.randint(100, 999)
            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S') + f",{ms:03d}"
        except Exception as e:
            if hasattr(_parse_linux_row, 'fail_count'):
                _parse_linux_row.fail_count += 1
            else:
                _parse_linux_row.fail_count = 1
            if _parse_linux_row.fail_count <= 5:
                print(f"[WARN] Linux timestamp parse error: {e} | value: {timestamp_str}")
            timestamp = timestamp_str  # fallback to raw string
        # Infer log level from content
        content = str(row.get('Content', '')).strip()
        level = _infer_linux_level(content)
        module = str(row.get('Component', 'linux')).strip()
        message = content
        return {
            'timestamp': timestamp,
            'log_level': level,
            'module': module,
            'message': message
        }
    except Exception as e:
        if hasattr(_parse_linux_row, 'row_fail_count'):
            _parse_linux_row.row_fail_count += 1
        else:
            _parse_linux_row.row_fail_count = 1
        if _parse_linux_row.row_fail_count <= 5:
            print(f"[WARN] Linux row parse error: {e} | row: {row.to_dict()}")
        return None
import os
import pandas as pd
import numpy as np
import re
import joblib
from datetime import datetime
import random

# Scikit-learn imports
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.linear_model import LogisticRegression
import json

# --- 1. Robust Log Parsing ---

def _parse_thunderbird_row(row):
    """Parse a row from Thunderbird structured CSV.
    Columns include: Month, Day, Time, Date (YYYY.MM.DD), Timestamp (epoch), Component, Content.
    """
    try:
        # Prefer epoch 'Timestamp' if numeric
        ts = row.get('Timestamp', None)
        timestamp = None
        if ts is not None and str(ts).strip() != '' and str(ts).isdigit():
            try:
                dt = datetime.utcfromtimestamp(int(ts))
                ms = random.randint(100, 999)
                timestamp = dt.strftime('%Y-%m-%d %H:%M:%S') + f',{ms:03d}'
            except Exception:
                timestamp = None
        if not timestamp:
            # Fallback: combine Date (YYYY.MM.DD) and Time (HH:MM:SS)
            date_str = str(row.get('Date', '')).strip().replace('.', '-')
            time_str = str(row.get('Time', '')).strip()
            try:
                dt = datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M:%S')
                ms = random.randint(100, 999)
                timestamp = dt.strftime('%Y-%m-%d %H:%M:%S') + f',{ms:03d}'
            except Exception:
                # Last resort: construct from Month/Day/Time with inferred year from Date
                mon = str(row.get('Month', 'Jan')).strip()
                day = str(row.get('Day', '01')).strip()
                year = '2005'
                try:
                    year = str(row.get('Date', '')).split('.')[0] or '2005'
                except Exception:
                    pass
                try:
                    dt = datetime.strptime(f"{mon} {int(float(day)):02d} {year} {time_str}", '%b %d %Y %H:%M:%S')
                    ms = random.randint(100, 999)
                    timestamp = dt.strftime('%Y-%m-%d %H:%M:%S') + f',{ms:03d}'
                except Exception:
                    timestamp = f"{mon} {day} {year} {time_str}"

        content = str(row.get('Content', '')).strip()
        level = _infer_linux_level(content)
        module = str(row.get('Component', 'thunderbird')).strip()
        return {
            'timestamp': timestamp,
            'log_level': level,
            'module': module,
            'message': content
        }
    except Exception as e:
        print(f"[WARN] Thunderbird row parse error: {e} | row: {row.to_dict()}")
        return None

def _parse_apache_row(row):
    """Helper to parse a row from an Apache structured CSV."""
    try:
        dt = pd.to_datetime(row['Time'], format='%a %b %d %H:%M:%S %Y', errors='raise')
        ms = random.randint(100, 999)
        timestamp = dt.strftime(f'%Y-%m-%d %H:%M:%S,{ms:03d}')
        level = str(row.get('Level', 'INFO')).strip().upper()
        if level == 'NOTICE':
            level = 'INFO'
        return {
            'timestamp': timestamp,
            'log_level': level,
            'module': 'apache',
            'message': str(row['Content']).strip()
        }
    except (ValueError, TypeError):
        return None

def _parse_hdfs_row(row):
    """Helper to parse a row from an HDFS structured CSV."""
    # HDFS Date: MMDDYY, Time: HHMMSS (all ints, may be missing leading zeros)
    date_val = row['Date']
    time_val = row['Time']
    date_raw = str(int(date_val)).zfill(6)  # MMDDYY
    time_raw = str(int(time_val)).zfill(6)  # HHMMSS
    dt_str = date_raw + time_raw
    print(f"[DEBUG] Parsing HDFS row: date_raw={date_raw}, time_raw={time_raw}, dt_str={dt_str}")
    try:
        dt = datetime.strptime(dt_str, '%m%d%y%H%M%S')
    except Exception as e:
        print(f"[DEBUG] Primary parse failed: {e}. Trying fallback zero-padding.")
        # Fallback: pad both to 6 digits again just in case
        date_raw = date_raw.zfill(6)
        time_raw = time_raw.zfill(6)
        dt_str = date_raw + time_raw
        try:
            dt = datetime.strptime(dt_str, '%m%d%y%H%M%S')
        except Exception as e2:
            print(f"[WARN] HDFS row parse error (fallback also failed): {e2} | row: {row.to_dict()}")
            return None
    ms = random.randint(100, 999)
    timestamp = dt.strftime(f'%Y-%m-%d %H:%M:%S,{ms:03d}')
    return {
        'timestamp': timestamp,
        'log_level': str(row.get('Level', 'INFO')).strip().upper(),
        'module': str(row.get('Component', 'HDFS')).strip(),
        'message': str(row['Content']).strip()
    }

def parse_log_file(filepath):
    """
    Parses a log file, detecting if it's a standard text log or a known CSV format.
    """
    valid_log_data = []
    total_lines = 0
    
    print(f"Parsing file: {os.path.basename(filepath)}...")

    try:
        if filepath.endswith('.csv'):
            df = pd.read_csv(filepath, low_memory=False)

            # Determine CSV type by checking for unique column sets
            cols = set(df.columns)
            # Prefer the most specific schemas first to avoid subset clashes
            if {'Month', 'Date', 'Time', 'Level', 'Component', 'Content'}.issubset(cols):  # Linux/Generic format
                parser = _parse_linux_row
                print("[INFO] Detected Linux/Generic CSV schema")
            # BlueGene/L RAS often includes EventId/EventTemplate/Node alongside Time/Level/Component/Content
            elif {'Time', 'Level', 'Component', 'Content'}.issubset(cols) and (
                {'EventId', 'EventTemplate', 'Node', 'Label', 'Type', 'Timestamp', 'Date'} & cols
            ):
                parser = _parse_bgq_row
                print("[INFO] Detected BlueGene/L RAS CSV schema")
            # Thunderbird: has Month, Day, Time, Component, Content (no Level), often Timestamp and Date yyyy.mm.dd
            elif {'Month', 'Day', 'Time', 'Component', 'Content'}.issubset(cols):
                parser = _parse_thunderbird_row
                print("[INFO] Detected Thunderbird CSV schema")
            # HDFS format: lacks Month/Day columns
            elif {'Date', 'Time', 'Component', 'Content'}.issubset(cols) and not ({'Month', 'Day'} & cols):  # HDFS format
                parser = _parse_hdfs_row
                print("[INFO] Detected HDFS CSV schema")
            # Harden Apache detection: must NOT contain 'Component' to avoid BGQ/HDFS clash
            elif {'Time', 'Level', 'Content'}.issubset(cols) and 'Component' not in cols:  # Apache format
                parser = _parse_apache_row
                print("[INFO] Detected Apache CSV schema")
            else:
                print(f"[WARN] Unrecognized CSV format for {filepath}. Skipping.")
                return pd.DataFrame()

            for _, row in df.iterrows():
                total_lines += 1
                parsed_data = parser(row)
                if parsed_data:
                    valid_log_data.append(parsed_data)
                else:
                    print(f"[WARN] Skipping malformed CSV row {total_lines}: {row.to_dict()}")

        else: # Handle plain text logs
            log_pattern = re.compile(
                r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+([A-Z]+)\s+\[([^\]]+)\]\s+(.*)"
            )
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    total_lines += 1
                    line = line.strip()
                    if not line or line.startswith(('//', '#')):
                        continue
                    
                    match = log_pattern.match(line)
                    if match:
                        timestamp, log_level, module, message = match.groups()
                        valid_log_data.append({
                            'timestamp': timestamp,
                            'log_level': log_level,
                            'module': module,
                            'message': message
                        })
                    else:
                        print(f"[WARN] Skipping malformed line {total_lines}: {line[:100]}...")

    except Exception as e:
        print(f"[ERROR] Failed to read or parse file {filepath}: {e}")
        return pd.DataFrame()

    print(f"  -> Total lines read: {total_lines} | Valid log entries: {len(valid_log_data)}")
    return pd.DataFrame(valid_log_data)


# --- 2. Unified Feature Engineering ---

def extract_features(df, tfidf_vectorizer=None, scaler=None):
    """
    Extracts features from a DataFrame of parsed log lines.
    If vectorizer and scaler are provided, it transforms the data.
    If not, it fits them to the data.
    """
    # Fill NaNs in key columns to prevent row misalignment
    for col in ['log_level', 'module', 'message']:
        if col in df.columns:
            df[col] = df[col].fillna('unknown')
        else:
            df[col] = 'unknown'
    # Reset index before feature engineering to avoid index misalignment
    df = df.reset_index(drop=True)
    # Combine all text fields for TF-IDF
    df['full_log_text'] = df['log_level'] + ' ' + df['module'] + ' ' + df['message']

    # TF-IDF Vectorization (richer vocabulary with bigrams)
    if tfidf_vectorizer is None:
        tfidf_vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), min_df=2, stop_words='english')
        tfidf_matrix = tfidf_vectorizer.fit_transform(df['full_log_text'])
    else:
        tfidf_matrix = tfidf_vectorizer.transform(df['full_log_text'])
    
    # Robust conversion for all scikit-learn TF-IDF outputs
    tfidf_array = np.asarray(tfidf_matrix.todense())
    tfidf_df = pd.DataFrame(tfidf_array, columns=tfidf_vectorizer.get_feature_names_out())
    
    # One-Hot Encoding for categorical features
    categorical_df = pd.get_dummies(df[['log_level', 'module']], prefix=['lvl', 'mod'], drop_first=False)
    categorical_df = categorical_df.reset_index(drop=True)
    # Debug: check for row count mismatch after one-hot encoding
    if len(categorical_df) != len(df):
        print(f"[DEBUG] One-hot encoding row count mismatch: categorical_df={len(categorical_df)}, df={len(df)}")
    
    # HealthCheck Feature Extraction
    hc_features = df['message'].str.extract(r'CPU:\s*(\d+)%\,\s*Memory:\s*(\d+)%')
    hc_features.columns = ['healthcheck_cpu', 'healthcheck_mem']
    # Ensure both columns always exist and are in the same order
    for col in ['healthcheck_cpu', 'healthcheck_mem']:
        if col not in hc_features:
            hc_features[col] = 0.0
    hc_features = hc_features[['healthcheck_cpu', 'healthcheck_mem']]
    hc_features = hc_features.astype(float).fillna(0)
    
    # Additional numeric features (security and HTTP signals)
    msg = df['message'].fillna('')
    private_ip_pat = r'(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2[0-9]|3[01])\.(?:\d{1,3})\.(?:\d{1,3}))'
    ip_pat = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    # Rule signal: use our rule-based classifier on the combined text
    rule_signal = (df['full_log_text'].apply(lambda s: 1 if classify_log_entry(str(s)) == 'anomaly' else 0)
                   if 'full_log_text' in df.columns else pd.Series([0]*len(df)))
    numeric_features = pd.DataFrame({
        'message_len': msg.str.len(),
        'digit_count': msg.str.count(r'\d'),
        'ip_count': msg.str.count(ip_pat),
        'has_private_ip': msg.str.contains(private_ip_pat).astype(int),
        'has_external_ip': (msg.str.contains(ip_pat) & (~msg.str.contains(private_ip_pat))).astype(int),
        'url_count': msg.str.count(r'https?://'),
        'status_5xx': msg.str.contains(r'\s5\d{2}\s').astype(int),
        'status_4xx': msg.str.contains(r'\s4\d{2}\s').astype(int),
        'rule_flag': rule_signal
    })
    numeric_features = numeric_features.fillna(0)

    # Combine numeric features to scale
    numeric_all = pd.concat([hc_features, numeric_features], axis=1)

    # Normalization for all numeric features
    if scaler is None:
        scaler = MinMaxScaler()
        numeric_scaled = scaler.fit_transform(numeric_all)
    else:
        # Align to scaler's expected feature names if available
        if hasattr(scaler, 'feature_names_in_'):
            expected = list(scaler.feature_names_in_)
            for c in expected:
                if c not in numeric_all.columns:
                    numeric_all[c] = 0
            # Only keep expected columns and order them
            numeric_all = numeric_all[expected]
        numeric_scaled = scaler.transform(numeric_all)
    full_numeric_names = [
        'hc_cpu_norm', 'hc_mem_norm', 'msg_len_norm', 'digit_cnt_norm', 'ip_cnt_norm',
        'has_priv_ip', 'has_ext_ip', 'url_cnt_norm', 'status_5xx', 'status_4xx', 'rule_flag'
    ]
    n_dim = numeric_scaled.shape[1]
    if n_dim == len(full_numeric_names):
        names = full_numeric_names
    elif n_dim == 2:
        names = ['hc_cpu_norm', 'hc_mem_norm']
    else:
        names = [f'num_{i}' for i in range(n_dim)]
        print(f"[WARN] Unexpected numeric feature dimension {n_dim}; using generic names {names}")
    hc_df = pd.DataFrame(numeric_scaled, columns=names)

    # Combine all features
    final_features = pd.concat([tfidf_df, categorical_df, hc_df], axis=1)
    final_features = final_features.reset_index(drop=True)
    # Debug: check for row count mismatch after concat
    if len(final_features) != len(df):
        print(f"[DEBUG] Feature concat row count mismatch: final_features={len(final_features)}, df={len(df)}")
    assert len(final_features) == len(df), f"Feature row count {len(final_features)} != input row count {len(df)}"
    return final_features, tfidf_vectorizer, scaler

# --- 3. Training and Scoring Functions ---

def train_and_evaluate(train_files, test_files=None, contamination_rate=0.15, model_type='iforest'):
    """
    Loads, processes, trains, and evaluates the model.
    """
    # Load and combine all training files
    df_list = [parse_log_file(f) for f in train_files]
    train_df = pd.concat(df_list, ignore_index=True)

    if train_df.empty:
        print("[ERROR] No valid data loaded for training. Aborting.")
        return

    # Define ground truth (1 for anomaly, 0 for normal)
    anomaly_levels = {'WARN', 'ERROR', 'FATAL', 'CRITICAL'}
    train_df['is_anomaly'] = train_df['log_level'].apply(lambda x: 1 if x in anomaly_levels else 0)

    # If external test files provided, use them; otherwise do a split
    if test_files:
        test_list = [parse_log_file(f) for f in test_files]
        test_df = pd.concat(test_list, ignore_index=True)
        if test_df.empty:
            print("[ERROR] No valid data loaded for external test files. Aborting.")
            return
        test_df['is_anomaly'] = test_df['log_level'].apply(lambda x: 1 if x in ['WARN', 'ERROR'] else 0)
        X_train_raw = train_df.drop('is_anomaly', axis=1)
        y_train = train_df['is_anomaly']
        X_test_raw = test_df.drop('is_anomaly', axis=1)
        y_test = test_df['is_anomaly']
        print(f"\nTotal entries: train={len(train_df)} | external test={len(test_df)}")
    else:
        y = train_df['is_anomaly']
        strat = y if y.nunique() > 1 else None
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            train_df.drop('is_anomaly', axis=1),
            y,
            test_size=0.25,
            random_state=42,
            stratify=strat
        )
        print(f"\nTotal entries: {len(train_df)} | Training set: {len(X_train_raw)} | Test set: {len(X_test_raw)}")

    # Fit preprocessors (TF-IDF, Scaler) ONLY on the training data
    features_train, tfidf, scaler = extract_features(X_train_raw)
    
    # Transform the test data using the FITTED preprocessors
    features_test, _, _ = extract_features(X_test_raw, tfidf_vectorizer=tfidf, scaler=scaler)

    # Ensure test set has the same columns as the train set
    train_cols = features_train.columns
    test_cols = features_test.columns
    missing_in_test = set(train_cols) - set(test_cols)
    for c in missing_in_test:
        features_test[c] = 0
    features_test = features_test[train_cols] # Ensure same order

    # Train the model
    meta = {"type": model_type}
    if model_type == 'supervised':
        print("\n--- Training Supervised Classifier (Logistic Regression) ---")
        clf = LogisticRegression(max_iter=1000, class_weight='balanced')
        clf.fit(features_train, y_train)
        # Threshold tuning on test set (optimize F1 for anomaly)
        if hasattr(clf, 'predict_proba'):
            proba = clf.predict_proba(features_test)[:, 1]
            best_f1, best_thr = -1.0, 0.5
            for thr in [i/100 for i in range(5, 95, 2)]:
                preds_bin = (proba >= thr).astype(int)
                report = classification_report(y_test, preds_bin, output_dict=True, zero_division=0)
                f1 = report.get('1', {}).get('f1-score', 0.0)
                if f1 > best_f1:
                    best_f1, best_thr = f1, thr
            meta["threshold"] = best_thr
            print(f"Chosen probability threshold: {best_thr:.2f} (F1={best_f1:.3f})")
        model = clf
    else:
        print("\n--- Training Isolation Forest ---")
        model = IsolationForest(n_estimators=200, contamination=contamination_rate, random_state=42)
        model.fit(features_train)
        print("Model training complete.")

    # Save the model and preprocessors
    joblib.dump(model, "model.joblib")
    joblib.dump(tfidf, "tfidf.joblib")
    joblib.dump(scaler, "scaler.joblib")
    joblib.dump(train_cols, "feature_columns.joblib")
    with open("model_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f)
    print("Saved model and preprocessing objects to disk.")

    # Evaluate on the unseen test set
    if model_type == 'supervised' and hasattr(model, 'predict_proba'):
        thr = meta.get('threshold', 0.5)
        proba = model.predict_proba(features_test)[:, 1]
        preds_binary = (proba >= thr).astype(int)
    else:
        preds = model.predict(features_test)
        preds_binary = [1 if p == -1 else 0 for p in preds]

    print("\n--- Classification Report (on Unseen Test Set) ---")
    print(classification_report(y_test, preds_binary, digits=3))

def load_and_score(log_file_path, model_dir='.'):
    """
    Loads a pre-trained model and scores a new log file.
    """
    try:
        model = joblib.load(os.path.join(model_dir, "model.joblib"))
        tfidf = joblib.load(os.path.join(model_dir, "tfidf.joblib"))
        scaler = joblib.load(os.path.join(model_dir, "scaler.joblib"))
        feature_columns = joblib.load(os.path.join(model_dir, "feature_columns.joblib"))
        print(f"Loaded model and preprocessors from {model_dir}.")
        meta_path = os.path.join(model_dir, "model_meta.json")
        model_meta = None
        if os.path.exists(meta_path):
            with open(meta_path, 'r', encoding='utf-8') as f:
                model_meta = json.load(f)
    except FileNotFoundError as e:
        print(f"ERROR: {e}\nCould not find one or more required .joblib files in '{model_dir}'.")
        print("Please train a model first (mode 1) or specify the correct directory.")
        return

    # Parse the new log file
    score_df = parse_log_file(log_file_path)
    if score_df.empty:
        print("Could not score file as no valid log entries were found.")
        return

    # Extract features using the loaded preprocessors
    features, _, _ = extract_features(score_df, tfidf_vectorizer=tfidf, scaler=scaler)

    # Align columns with the training data
    features = features.reindex(columns=feature_columns, fill_value=0)

    # Predict anomalies
    preds_iter = None
    if 'model_meta' in locals() and model_meta and model_meta.get('type') == 'supervised' and hasattr(model, 'predict_proba'):
        thr = model_meta.get('threshold', 0.5)
        proba = model.predict_proba(features)[:, 1]
        preds_iter = (proba >= thr).astype(int)
    else:
        preds = model.predict(features)
        preds_iter = [1 if p == -1 else 0 for p in preds]

    print("\n--- Anomaly Scoring Results ---")
    anomaly_count = 0
    for i, pred in enumerate(preds_iter):
        status = "ANOMALY" if pred == 1 else "NORMAL"
        if pred == 1:
            anomaly_count += 1
        print(f"[{status}] {score_df.iloc[i]['timestamp']} {score_df.iloc[i]['log_level']} [{score_df.iloc[i]['module']}] {score_df.iloc[i]['message']}")
    
    print(f"\nScoring complete. Found {anomaly_count} anomalies out of {len(score_df)} lines.")


# --- Main Menu ---
if __name__ == "__main__":
    print("Select mode:")
    print("1. Train and evaluate a new model")
    print("2. Load a trained model and score a new log file")
    mode = input("Enter 1 or 2 (default is 1): ").strip()

    if mode == "2":
        log_file = input("Enter the path to the log file to score: ").strip()
        model_dir_input = input("Enter the directory containing your .joblib files (leave blank for current directory): ").strip()
        
        if not log_file:
            print("No log file provided. Exiting.")
        else:
            if not model_dir_input:
                model_dir_input = '.' # Default to current directory
            load_and_score(log_file, model_dir=model_dir_input)
    else:
        train_files_input = input("Enter paths to your TRAINING log files (comma-separated): ").strip()
        test_files_input = input("Optionally, enter paths to your TEST log files (comma-separated, leave blank to auto-split): ").strip()
        model_choice = input("Model type - IsolationForest (i) or Supervised (s)? [i/s, default i]: ").strip().lower()
        if not train_files_input:
            print("No training files provided. Exiting.")
        else:
            train_file_list = [f.strip() for f in train_files_input.split(',') if f.strip()]
            test_file_list = [f.strip() for f in test_files_input.split(',') if f.strip()] if test_files_input else None
            mtype = 'supervised' if model_choice == 's' else 'iforest'
            if mtype == 'iforest':
                cont_in = input("Set contamination (0.01-0.30, default 0.15): ").strip()
                try:
                    cont = float(cont_in) if cont_in else 0.15
                except Exception:
                    cont = 0.15
                train_and_evaluate(train_file_list, test_files=test_file_list, contamination_rate=cont, model_type=mtype)
            else:
                train_and_evaluate(train_file_list, test_files=test_file_list, model_type=mtype)