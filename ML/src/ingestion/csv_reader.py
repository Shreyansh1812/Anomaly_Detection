"""Thin wrapper to expose CSVLogReader under the ingestion package.
This preserves current behavior while enabling a cleaner package layout.
"""
from typing import Optional
import pandas as pd

# Forward to existing implementation to avoid behavior changes
from log_ingestion import CSVLogReader as _CSVLogReader  # type: ignore


class CSVLogReader(_CSVLogReader):
    """Alias of existing CSVLogReader for package consistency."""
    pass
