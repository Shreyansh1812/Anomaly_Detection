import joblib
import os
os.environ["DRAIN3_CONFIG_PATH"] = "drain3.ini"
from drain3 import TemplateMiner

template_miner = TemplateMiner()
print("Using drain3.ini config if present, otherwise default config.")

# Parse the log file
log_file = r'C:\Users\shrey\Downloads\SGP-II\Data\test_logs\Linux_test.txt'
templates = []
with open(log_file, 'r') as f:
    for line_num, line in enumerate(f, 1):
        if line.strip():
            result = template_miner.add_log_message(line.strip())
            if result["change_type"] != "none":
                print(f"Line {line_num}: New template - {result['template_mined']}")

print(f"\nTotal templates generated: {len(template_miner.drain.clusters)}")
print(f"Your model expects: 101 features")

# Show all templates
for i, cluster in enumerate(template_miner.drain.clusters):
    print(f"Template {i+1}: {cluster.get_template()}")
