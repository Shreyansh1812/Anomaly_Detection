from pathlib import Path
import pandas as pd

from Scripts.analyze_log_pipeline import build_report


def test_build_report_includes_sections(tmp_path: Path):
    df = pd.DataFrame({
        "method": ["GET", "POST", "GET"],
        "path": ["/", "/admin", "/health"],
        "status": [200, 403, 200],
        "bytes": [100, 200, 300],
        "user_agent": ["Mozilla", "sqlmap", "curl"],
    })
    cfg = {
        "reporting": {"top_n_paths": 5, "top_n_large_paths": 5, "top_n_user_agents": 5},
        "thresholds": {"large_response_bytes": 150},
        "patterns": {},
    }
    md = build_report(df, "ReaderX", 3, "msg", Path("/input.log"), cfg, title="T")
    assert "## Parsing Summary" in md
    assert "## Security Signals" in md
    assert "Top malicious user-agents" in md


def test_build_report_handles_missing_columns(tmp_path: Path):
    df = pd.DataFrame({"message": ["ok"]})
    cfg = {"reporting": {}, "thresholds": {}, "patterns": {}}
    md = build_report(df, "ReaderX", 1, "ok", Path("/i"), cfg)
    assert "Parsing Summary" in md
