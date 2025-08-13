"""Thin wrapper to expose TextLogParser and LogDirectoryProcessor under ingestion package."""
from log_parser import TextLogParser, LogDirectoryProcessor  # type: ignore

__all__ = ["TextLogParser", "LogDirectoryProcessor"]
