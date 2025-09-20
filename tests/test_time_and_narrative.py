from pathlib import Path
import pandas as pd
from Scripts.analyze_log_pipeline import _infer_time_range, build_intel_report


def test_infer_time_range_epoch_seconds():
    # Epoch seconds ~ 2005-11-09 12:01:01
    df = pd.DataFrame({"Timestamp": [1131566461, 1131566521]})
    start, end = _infer_time_range(df)
    assert start is not None and start.startswith("2005-11-09")
    assert end is not None and end.startswith("2005-11-09")


def test_intel_report_zero_threats_narrative(tmp_path: Path):
    df = pd.DataFrame({
        "Timestamp": [1131566461] * 3,
        "Content": ["info", "ok", "done"],
    })
    md = build_intel_report(df, "Reader", 0, "", tmp_path / "in.csv", cfg={}, title=None, gt_df=None, analysis_seconds=0.01)
    assert "No high-confidence threats were identified" in md
    assert "> No high-risk entities detected" in md
