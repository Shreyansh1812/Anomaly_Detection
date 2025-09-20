from pathlib import Path
from Scripts.generate_report import default_output_for


def test_default_output_for_builds_reports_path(tmp_path: Path):
    # Simulate path like Data/raw_logs/HDFS_2k.log_structured.csv
    data_dir = tmp_path / "Data" / "raw_logs"
    data_dir.mkdir(parents=True)
    f = data_dir / "HDFS_2k.log_structured.csv"
    f.write_text("x", encoding="utf-8")
    out = default_output_for(f, reports_dir=tmp_path / "Reports")
    assert out.name == "HDFS_2k_report_intel.md"
    assert out.parent.name == "Reports"
