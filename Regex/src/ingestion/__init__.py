"""Ingestion package: readers, adapters, and factory for log inputs."""
# Re-export common ingestion symbols for convenience
try:
    from .csv_reader import CSVLogReader  # noqa: F401
except Exception:
    pass
try:
    from .text_reader import TextLogParser, LogDirectoryProcessor  # noqa: F401
except Exception:
    pass
try:
    from .factory import LogReaderFactory  # noqa: F401
except Exception:
    pass
try:
    from .adapters import CSVLogReaderAdapter, TextLogReaderAdapter  # noqa: F401
except Exception:
    pass
