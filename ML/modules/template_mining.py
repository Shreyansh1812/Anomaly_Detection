"""
Log Template Mining using Drain3
- Extracts templates and parameters from unstructured log messages
"""
from typing import List, Dict, Any
import pandas as pd
try:
    from drain3 import TemplateMiner
except ImportError:
    TemplateMiner = None

class LogTemplateMiner:
    def __init__(self):
        if TemplateMiner is None:
            raise ImportError("Drain3 is not installed. Run 'pip install drain3' to use template mining.")
        self.miner = TemplateMiner()

    def extract_templates(self, messages: List[str]) -> pd.DataFrame:
        """Returns DataFrame with columns: message, template_id, template, params"""
        results = []
        for msg in messages:
            res = self.miner.add_log_message(msg)
            results.append({
                "message": msg,
                "template_id": res['cluster_id'],
                "template": res['template_mined'],
                "params": res.get('params', [])
            })
        return pd.DataFrame(results)
