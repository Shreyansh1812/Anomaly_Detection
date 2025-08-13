import pandas as pd
from src.error_patterns import WebSecurityAnalyzer


def test_happy_path_detections():
    df = pd.DataFrame(
        {
            "ip": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
            "method": ["GET", "DELETE", "GET", "GET"],
            "path": [
                "/index.php?id=1 UNION SELECT 1",  # SQLi
                "/admin",  # sensitive
                "/..%2e%2fetc/passwd",  # traversal
                "/search?q=%27%22--",  # suspicious params
            ],
            "status": [200, 403, 200, 200],
            "bytes": [200, 6000000, 100, 100],
            "user_agent": ["sqlmap", "Mozilla", "curl", "zaproxy"],
            "referer": ["-", "http://evil.tld", "-", "-"]
        }
    )
    ws = WebSecurityAnalyzer(large_bytes_threshold=1024)
    res = ws.analyze_access_df(df)
    c = res["counters"]
    assert c["sqli"] >= 1
    assert c["suspicious_endpoints"] >= 1
    assert c["path_traversal"] >= 1
    assert c["suspicious_params_chars"] >= 1
    assert c["malicious_user_agent"] >= 2  # sqlmap + zaproxy
    assert c["large_responses"] >= 1


def test_edge_cases_missing_columns_and_empty_df():
    empty = pd.DataFrame()
    ws = WebSecurityAnalyzer()
    res = ws.analyze_access_df(empty)
    assert res.get("note") == 'No HTTP-like columns present'

    # Missing method/path; request present
    df = pd.DataFrame({"request": ["GET /login HTTP/1.1"], "status": [401]})
    res = ws.analyze_access_df(df)
    assert "counters" in res


def test_bruteforce_stateful_logic():
    # 12 failed logins from same IP across timestamps
    df = pd.DataFrame(
        {
            "ip": ["9.9.9.9"] * 12,
            "request": ["POST /login HTTP/1.1"] * 12,
            "status": [401] * 12,
            "timestamp": pd.date_range("2023-01-01", periods=12, freq="min").astype(str),
        }
    )
    ws = WebSecurityAnalyzer(bruteforce_threshold=10)
    res = ws.analyze_access_df(df)
    assert res["counters"]["bruteforce_events"] == 12
    assert res["counters"]["bruteforce_offenders"] >= 1
    assert res["details"]["bruteforce_ips"].get("9.9.9.9", 0) >= 10
