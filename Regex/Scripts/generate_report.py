"""Compatibility shim for generate_report after restructuring.
Imports the relocated script from 'Analysis - Regex/Scripts'.
"""
from pathlib import Path
import sys as _sys

_ROOT = Path(__file__).resolve().parents[1]
_NEW = _ROOT / "Analysis - Regex" / "Scripts"
if str(_NEW) not in _sys.path:
    _sys.path.insert(0, str(_NEW))

from generate_report import *  # type: ignore
import argparse
from pathlib import Path
import sys
from typing import Optional

# Make imports work whether run as a module or directly
THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    # Prefer direct sibling import when running inside Scripts/
    from analyze_log_pipeline import run_pipeline, load_config
except ModuleNotFoundError:  # fallback if Scripts is a package
    from Scripts.analyze_log_pipeline import run_pipeline, load_config


def default_output_for(input_path: Path, reports_dir: Optional[Path] = None) -> Path:
    # Default to top-level Reports folder under current working directory
    reports = reports_dir or Path.cwd() / "Reports"
    reports.mkdir(parents=True, exist_ok=True)
    stem = input_path.stem.replace(".log_structured", "").replace(".log", "")
    return reports / f"{stem}_report_intel.md"


def prompt_for_path(prompt: str) -> Path:
    try:
        raw = input(prompt).strip().strip('"')
    except EOFError:
        raw = ""
    if not raw:
        print("No path provided. Exiting.")
        sys.exit(1)
    p = Path(raw).expanduser().resolve()
    if not p.exists():
        print(f"Input not found: {p}")
        sys.exit(1)
    return p


def main():
    ap = argparse.ArgumentParser(description="Interactive end-to-end report generator (regex-only)")
    ap.add_argument("--input", help="Path to input log/CSV (prompted if omitted)")
    ap.add_argument("--output", help="Output report .md (default: Reports/<name>_report_intel.md)")
    ap.add_argument("--template", choices=["intel", "standard"], default="intel", help="Report template (default: intel)")
    args = ap.parse_args()

    in_path = Path(args.input).resolve() if args.input else prompt_for_path("Please Enter the path o f the file .. ")
    out_path = Path(args.output).resolve() if args.output else default_output_for(in_path)

    # Load config.yaml if present in CWD; else defaults
    cfg_path = Path.cwd() / "config.yaml"
    cfg = load_config(cfg_path if cfg_path.exists() else None)

    try:
        print(f"[+] Input: {in_path}")
        print(f"[+] Output: {out_path}")
        report_path = run_pipeline(in_path, out_path, title=None, cfg=cfg, verbose=True, ground_truth_path=None, template=args.template)
        print(f"Report written: {report_path}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
