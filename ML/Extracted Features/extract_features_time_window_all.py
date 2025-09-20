import os
import re
import csv
from drain3 import TemplateMiner
from datetime import datetime, timedelta

def extract_timestamp(line):
    # Example: Linux log format 'Sep 20 08:15:32 ...'
    match = re.match(r"([A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2})", line)
    if match:
        try:
            return datetime.strptime(match.group(1), "%b %d %H:%M:%S")
        except Exception:
            return None
    return None

# List of log files to process
log_files = [
    r"c:\Users\shrey\Downloads\SGP-II\Data\test_logs\Linux_test.txt",
    r"c:\Users\shrey\Downloads\SGP-II\Regex\Data\raw_logs\raw_logs\Thunderbird_2k.log_structured.csv"
]
window_minutes = 1  # Window size in minutes
os.environ["DRAIN3_CONFIG_PATH"] = "drain3.ini"

for log_file in log_files:
    template_file = log_file + "_templates.txt"
    if not os.path.exists(template_file):
        print(f"Template file not found for {log_file}, skipping.")
        continue
    print(f"Processing {log_file} with templates from {template_file}")
    # Load templates
    with open(template_file, 'r', encoding='utf-8') as f:
        templates = [line.strip().split(': ', 1)[1] for line in f if line.startswith('Template')]
    feature_rows = []
    current_window_start = None
    current_window_end = None
    window_counts = {tpl: 0 for tpl in templates}
    template_miner = TemplateMiner()
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if not line.strip():
                continue
            ts = extract_timestamp(line)
            if ts is None:
                continue
            if current_window_start is None:
                current_window_start = ts
                current_window_end = ts + timedelta(minutes=window_minutes)
            if current_window_end is not None and ts >= current_window_end:
                if current_window_start is not None:
                    feature_rows.append([current_window_start.strftime('%Y-%m-%d %H:%M:%S')] + [window_counts[tpl] for tpl in templates])
                current_window_start = ts
                current_window_end = ts + timedelta(minutes=window_minutes)
                window_counts = {tpl: 0 for tpl in templates}
            result = template_miner.add_log_message(line.strip())
            tpl = result['template_mined']
            if tpl in window_counts:
                window_counts[tpl] += 1
    if any(window_counts.values()) and current_window_start is not None:
        feature_rows.append([current_window_start.strftime('%Y-%m-%d %H:%M:%S')] + [window_counts[tpl] for tpl in templates])
    out_csv = log_file + "_features.csv"
    with open(out_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['window_start'] + templates)
        writer.writerows(feature_rows)
    print(f"Feature extraction complete. Output: {out_csv}")
