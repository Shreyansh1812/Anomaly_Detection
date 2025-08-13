import pandas as pd
from Scripts.analyze_log_pipeline import _extract_top_attackers

def test_linux_auth_ip_extraction_reconciles_counts():
    # Build a small DF resembling Linux auth failures with rhost in Content
    rows = []
    for i in range(46):
        rows.append({
            'LineId': i+1,
            'Content': f"authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4"
        })
    df = pd.DataFrame(rows)
    # Simulate that detector flagged all rows (indices 0..45)
    pred_idx = list(range(46))
    top_ips, _ = _extract_top_attackers(df, pred_idx, top_n=5, msg_col='Content')
    assert top_ips == {'218.188.2.4': 46}
