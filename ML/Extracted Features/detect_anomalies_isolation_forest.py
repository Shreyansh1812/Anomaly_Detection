import os
import pandas as pd
from sklearn.ensemble import IsolationForest

# List of feature CSVs to process
feature_csvs = [
    r"c:\Users\shrey\Downloads\SGP-II\Data\test_logs\Linux_test.txt_features.csv",
    r"c:\Users\shrey\Downloads\SGP-II\Regex\Data\raw_logs\raw_logs\Thunderbird_2k.log_structured.csv_features.csv"
]

for csv_path in feature_csvs:
    print(f"Processing: {csv_path}")
    df = pd.read_csv(csv_path)
    feature_cols = df.columns[1:]  # Exclude window_start
    X = df[feature_cols].fillna(0)
    # Train Isolation Forest
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)
    scores = model.decision_function(X)
    anomalies = model.predict(X)
    # Add results to DataFrame
    df['anomaly_score'] = scores
    df['is_anomaly'] = (anomalies == -1).astype(int)
    out_csv = csv_path.replace('.csv', '_anomaly.csv')
    df.to_csv(out_csv, index=False)
    print(f"Anomaly detection complete. Output: {out_csv}")
