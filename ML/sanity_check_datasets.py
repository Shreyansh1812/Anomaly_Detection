import os
import sys
import glob
import json
import pandas as pd

# Support running as a script from within the ML folder
if __package__ is None or __package__ == "":
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from ML.robust_anomaly_trainer import parse_log_file
else:
    from .robust_anomaly_trainer import parse_log_file


def main():
    import argparse

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    default_data_dir = os.path.join(repo_root, "Data")
    ap = argparse.ArgumentParser(description="Sanity-check CSV datasets: schema detection and valid row counts")
    ap.add_argument("--dir", default=default_data_dir, help="Directory to scan for CSV files (recursively)")
    args = ap.parse_args()

    data_dir = args.dir
    out_dir = os.path.join(repo_root, "ML", "reports")
    os.makedirs(out_dir, exist_ok=True)

    csv_files = sorted(glob.glob(os.path.join(data_dir, "**", "*.csv"), recursive=True))
    if not csv_files:
        print(f"[WARN] No CSV files found under {data_dir}")
        return

    rows = []
    print(f"Found {len(csv_files)} CSV files. Parsing each to verify schemas and counts...\n")
    for fp in csv_files:
        try:
            print(f"--- {os.path.basename(fp)} ---")
            df = parse_log_file(fp)
            valid = len(df)
            modules = ",".join(sorted(df["module"].dropna().astype(str).str[:20].unique()[:5])) if not df.empty else ""
            levels = ",".join(sorted(df["log_level"].dropna().astype(str).unique())) if not df.empty else ""
            rows.append({
                "file": os.path.basename(fp),
                "path": os.path.relpath(fp, repo_root),
                "valid_rows": valid,
                "unique_modules_preview": modules,
                "levels_present": levels,
            })
        except Exception as e:
            print(f"[ERROR] Failed sanity-check for {fp}: {e}")
            rows.append({
                "file": os.path.basename(fp),
                "path": os.path.relpath(fp, repo_root),
                "valid_rows": 0,
                "unique_modules_preview": "",
                "levels_present": "",
                "error": str(e),
            })

    out_csv = os.path.join(out_dir, "sanity_check.csv")
    pd.DataFrame(rows).to_csv(out_csv, index=False)
    print(f"\n[REPORT] Wrote sanity summary to {out_csv}")


if __name__ == "__main__":
    main()
