from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix


def load_predictions(path: Path) -> Tuple[List[int], List[int], List[str]]:
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)

    if not isinstance(payload, dict) or "files" not in payload:
        raise ValueError("Predictions file must be a JSON report produced by evaluate_trained_model.py")

    y_pred: List[int] = []
    row_indices: List[int] = []
    sources: List[str] = []

    for file_entry in payload.get("files", []):
        hits = file_entry.get("rule_based_hits", [])
        hit_map = {hit.get("log", {}).get("_row_index"): hit for hit in hits}
        total_rows = file_entry.get("counts", {}).get("total")
        if total_rows is None:
            raise ValueError("Predictions JSON missing counts.total")

        for idx in range(total_rows):
            hit = hit_map.get(idx)
            y_pred.append(1 if hit else 0)
            row_indices.append(idx)
            sources.append(hit.get("source", "none") if hit else "none")

    return y_pred, row_indices, sources


def load_golden(path: Path) -> Dict[int, int]:
    with open(path, "r", encoding="utf-8") as fh:
        entries = json.load(fh)

    golden_map: Dict[int, int] = {}
    for entry in entries:
        idx = entry.get("_row_index")
        label = entry.get("label", 1)
        if idx is None:
            raise ValueError("Golden set entries must include '_row_index'")
        golden_map[int(idx)] = 1 if label else 0
    return golden_map


def build_labels(row_indices: List[int], golden_map: Dict[int, int]) -> List[int]:
    y_true: List[int] = []
    for idx in row_indices:
        y_true.append(golden_map.get(idx, 0))
    return y_true


def report_metrics(title: str, y_true: List[int], y_pred: List[int]):
    print(f"\n=== {title} ===")
    print(classification_report(y_true, y_pred, digits=3, zero_division=0))
    print("Confusion Matrix:")
    print(confusion_matrix(y_true, y_pred))


def main():
    parser = argparse.ArgumentParser(description="Validate hybrid detector output against golden set.")
    parser.add_argument("--predictions_file", required=True, help="Path to the JSON output of evaluate_trained_model.py")
    parser.add_argument("--golden_set_file", required=True, help="Path to the manually verified golden set JSON")
    args = parser.parse_args()

    pred_path = Path(args.predictions_file)
    golden_path = Path(args.golden_set_file)

    y_pred, row_indices, sources = load_predictions(pred_path)
    golden_map = load_golden(golden_path)
    y_true = build_labels(row_indices, golden_map)

    report_metrics("Hybrid Detector", y_true, y_pred)

    for engine in ("rule", "ml"):
        engine_mask = [src == engine for src in sources]
        engine_pred = [pred if mask else 0 for pred, mask in zip(y_pred, engine_mask)]
        report_metrics(f"Engine: {engine.upper()}", y_true, engine_pred)


if __name__ == "__main__":
    main()
