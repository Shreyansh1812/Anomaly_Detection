# Regex Pipeline

End-to-end regex-only anomaly detection pipeline with actionable intel reporting.

## Quick start

Run the interactive report generator:

```powershell
python .\Scripts\generate_report.py
```

Or run directly with flags:

```powershell
python .\Scripts\analyze_log_pipeline.py --input "Data\raw_logs\HDFS_2k.log_structured.csv" --output "Reports\hdfs_report_intel.md" --template intel
```

Reports are written under `Regex/Reports/` by default.

## Tests

```powershell
pytest -q
```

## Lint

```powershell
ruff check .
```
# LogGuardian (Regex-only)

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Shreyansh1812/Anomaly_Detection/blob/feature/regex-analysis-only/Notebooks/Colab_Run_Report.ipynb)

Rule-based security analysis for log files. This branch focuses solely on pattern-based detection (no ML).

## Features
- Detects SQL injection, XSS, command injection, path traversal, sensitive endpoint access, brute-force attempts, high-frequency IPs, suspicious parameters, and malicious user agents.
- Generates a Markdown report summarizing distributions and security signals.
- Configurable thresholds and patterns via `config.yaml`.

## Installation

```bash
pip install -r requirements.txt
```

For development (tests, lint):
```bash
pip install -r requirements-dev.txt
```

## Usage

```bash
python .\Scripts\analyze_log_pipeline.py --input "Data\\raw_logs\\HDFS_2k.log_structured.csv"
```

With custom config and overrides:
```bash
python .\Scripts\analyze_log_pipeline.py --input ".\Data\raw.log" --config ".\config.yaml" --top-n 20 --verbose
```

### One-click Colab Runner

Use the Colab notebook to upload a structured CSV and generate the “intel” report in your browser (no local setup). Click the badge above or this link:

https://colab.research.google.com/github/Shreyansh1812/Anomaly_Detection/blob/feature/regex-analysis-only/Notebooks/Colab_Run_Report.ipynb

## Configuration (config.yaml)
- reporting:
  - top_n_paths, top_n_large_paths, top_n_user_agents
- thresholds:
  - large_response_bytes, exfil_bytes_per_minute
  - bruteforce: failure_statuses, window_minutes, attempts_threshold
  - high_freq: requests_per_minute_threshold
- patterns:
  - sensitive_paths, malicious_user_agents, login_paths

## Patterns Detected
- SQLi, XSS, Command Injection
- Path Traversal, Sensitive File Access
- Brute-force login attempts
- High request frequency per IP (per-minute)
- Suspicious parameters (quotes/base64), Malicious User-Agents

## Sample Report (excerpt)

```markdown
## Security Signals
- Suspicious Endpoints: 3
- SQLI: 2
- Path Traversal: 1
- Top suspicious paths:
  - /admin: 5
  - /etc/passwd: 1
- Top malicious user-agents:
  - sqlmap: 2
  - zaproxy: 1
```
