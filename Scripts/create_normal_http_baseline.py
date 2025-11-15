from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Set

import pandas as pd

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ML.robust_anomaly_trainer import parse_log_file
from src.anomaly_detection_engine import LogAnomalyDetector

PRIVATE_CIDRS = [
    "192.168.1.",
    "10.0.0.",
    "172.16.0.",
    "172.16.1.",
]

HTTP_PATHS = [
    "/",
    "/index.html",
    "/login",
    "/dashboard",
    "/status",
    "/reports/daily",
    "/api/health",
    "/redirect",
    "/assets/app.js",
    "/assets/styles.css",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/119.0",
    "curl/8.2.1",
]


def _random_private_ip() -> str:
    prefix = random.choice(PRIVATE_CIDRS)
    return prefix + str(random.randint(2, 250))


def _random_http_line(dt: datetime) -> str:
    ip = _random_private_ip()
    method = random.choices(["GET", "POST"], weights=[0.85, 0.15])[0]
    path = random.choice(HTTP_PATHS)
    scenario = random.random()
    if scenario < 0.6:
        status = 200
        size = random.randint(1000, 50000)
    elif scenario < 0.8:
        status = 304
        size = 0
    else:
        status = 302
        size = random.randint(500, 5000)
    if method == "POST" and path.startswith("/api"):
        status = random.choice([200, 201])
    ua = random.choice(USER_AGENTS)
    timestamp = dt.strftime("[%Y-%m-%dT%H:%M:%S+05:30]")
    return f"{timestamp} {ip} \"{method} {path} HTTP/1.1\" {status} {size} \"{ua}\""


def synthesize_http_logs(out_path: Path, count: int) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    base = datetime(2025, 11, 1, 0, 0, 0)
    with open(out_path, "w", encoding="utf-8") as handle:
        dt = base
        for _ in range(count):
            handle.write(_random_http_line(dt) + "\n")
            dt += timedelta(seconds=random.randint(1, 3))
    print(f"[INFO] Wrote {count} synthetic HTTP lines to {out_path}")


def _build_records(df: pd.DataFrame) -> List[dict]:
    enriched = df.reset_index(drop=True).copy()
    enriched["_row_index"] = enriched.index
    records = enriched.to_dict(orient="records")
    return records


def filter_with_rules(df: pd.DataFrame) -> Set[int]:
    detector = LogAnomalyDetector()
    records = _build_records(df)
    hits = detector.detect(records)
    flagged = {
        int(hit.get("log", {}).get("_row_index"))
        for hit in hits
        if isinstance(hit, dict) and isinstance(hit.get("log"), dict)
    }
    print(f"[INFO] Rule engine flagged {len(flagged)} rows")
    return flagged


def build_baseline(raw_log: Path, out_csv: Path, clean_log: Path | None = None) -> None:
    df = parse_log_file(str(raw_log))
    if df.empty:
        raise RuntimeError(f"Parsed dataframe is empty for {raw_log}")
    flagged = filter_with_rules(df)
    baseline = df.drop(index=list(flagged)).reset_index(drop=True)
    print(
        f"[INFO] Baseline contains {len(baseline)} rows (filtered {len(flagged)} from {len(df)})"
    )
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    baseline.to_csv(out_csv, index=False)
    print(f"[INFO] Saved clean baseline to {out_csv}")
    if clean_log:
        with open(raw_log, "r", encoding="utf-8") as src:
            lines = src.readlines()
        keep_indices = set(range(len(lines))) - flagged
        clean_log.parent.mkdir(parents=True, exist_ok=True)
        with open(clean_log, "w", encoding="utf-8") as dst:
            for idx in sorted(keep_indices):
                dst.write(lines[idx])
        print(f"[INFO] Saved filtered log copy to {clean_log}")


def main():
    parser = argparse.ArgumentParser(description="Create a clean HTTP baseline dataset")
    parser.add_argument("--count", type=int, default=4000, help="Number of synthetic HTTP lines")
    parser.add_argument(
        "--raw-log",
        default="Data/generated/normal_http_raw.log",
        help="Path to store the raw synthetic log file",
    )
    parser.add_argument(
        "--out-csv",
        default="Data/golden_sets/normal_http_baseline.csv",
        help="Destination CSV for the filtered baseline",
    )
    parser.add_argument(
        "--clean-log",
        default="Data/golden_sets/normal_http_baseline.log",
        help="Optional log file containing only the baseline entries",
    )
    args = parser.parse_args()

    raw_path = Path(args.raw_log)
    out_csv = Path(args.out_csv)

    synthesize_http_logs(raw_path, args.count)
    clean_log = Path(args.clean_log) if args.clean_log else None
    build_baseline(raw_path, out_csv, clean_log)


if __name__ == "__main__":
    main()
