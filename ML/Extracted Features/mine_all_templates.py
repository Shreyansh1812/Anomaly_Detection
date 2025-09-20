import os
from drain3 import TemplateMiner

# List of log files to process
log_files = [
    r"c:\Users\shrey\Downloads\SGP-II\Data\test_logs\Linux_test.txt",
    r"c:\Users\shrey\Downloads\SGP-II\Data\raw_logs\BGL_2k.log_structured.csv",
    r"c:\Users\shrey\Downloads\SGP-II\Data\raw_logs\HDFS_2k.log_structured.csv",
    r"c:\Users\shrey\Downloads\SGP-II\Regex\Data\raw_logs\raw_logs\Thunderbird_2k.log_structured.csv"
]

os.environ["DRAIN3_CONFIG_PATH"] = "drain3.ini"

for log_file in log_files:
    print(f"\nProcessing: {log_file}")
    template_miner = TemplateMiner()
    templates = []
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if line.strip():
                    result = template_miner.add_log_message(line.strip())
                    if result["change_type"] != "none":
                        print(f"Line {line_num}: New template - {result['template_mined']}")
        print(f"Total templates generated for {os.path.basename(log_file)}: {len(template_miner.drain.clusters)}")
        # Save templates to a file
        out_path = os.path.join(os.path.dirname(log_file), f"{os.path.basename(log_file)}_templates.txt")
        with open(out_path, 'w', encoding='utf-8') as out_f:
            for i, cluster in enumerate(template_miner.drain.clusters):
                out_f.write(f"Template {i+1}: {cluster.get_template()}\n")
        print(f"Templates saved to: {out_path}")
    except Exception as e:
        print(f"Error processing {log_file}: {e}")
