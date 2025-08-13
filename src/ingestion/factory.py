"""Re-export factory from existing log_processing to keep imports stable."""
from log_processing import LogReaderFactory  # type: ignore

__all__ = ["LogReaderFactory"]
