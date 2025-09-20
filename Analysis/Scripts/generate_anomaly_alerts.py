import pandas as pd
import os

# Input: path to anomaly report CSV

# Use robust absolute paths
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
input_csv = os.path.join(base_dir, 'Output', 'HDFS_test.txt_anomaly_report.csv')
output_txt = os.path.join(base_dir, 'Reports', 'HDFS_test_anomaly_alerts.txt')

def main():
    df = pd.read_csv(input_csv)
    anomalies = df[df['is_anomaly'] == 1]
    with open(output_txt, 'w', encoding='utf-8') as f:
        if anomalies.empty:
            f.write("No anomalies detected in the log file.\n")
            print("No anomalies detected in the log file.")
            return
        f.write("ALERT: Anomalies detected in the log file!\n")
        f.write("========================================\n\n")
        for i, (_, row) in enumerate(anomalies.iterrows(), 1):
            f.write(f"Anomalous window {i}:\n")
            f.write(f"  Anomaly score: {row['anomaly_score']:.4f}\n")
            # Show top 3 templates in this window
            template_counts = row.iloc[:-2]
            top_templates = template_counts.sort_values(ascending=False).head(3)
            f.write("  Most frequent log templates in window:\n")
            for tpl, cnt in top_templates.items():
                if cnt > 0:
                    f.write(f"    - {tpl} (count: {int(cnt)})\n")
            f.write("\n")
    print(f"Anomaly alert report saved to: {output_txt}")

if __name__ == "__main__":
    main()
