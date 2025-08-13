# LogGuardian

This repo is organized into two tracks:

- `Regex/` — rule-based pipeline (no ML) with an interactive CLI, tests, and CI.
- `ML/` — machine learning experiments, notebooks, and models (kept separate).

For usage of the regex pipeline, see `Regex/README.md`.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Shreyansh1812/Anomaly_Detection/blob/feature/regex-analysis-only/Notebooks/Colab_Run_Report.ipynb)

Rule-based security analysis for log files.

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
