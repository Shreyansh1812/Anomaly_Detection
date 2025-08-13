"""
Core interfaces (ABC) for log readers.
Moved from src/log_processing.py to core for cleaner architecture.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator
import pandas as pd

from .standard_log import StandardLog


class LogReader(ABC):
    """Abstract base class for log readers providing a unified API."""

    @abstractmethod
    def read(self) -> pd.DataFrame:
        """Return logs as a pandas DataFrame."""
        raise NotImplementedError

    @abstractmethod
    def to_standard_logs(self) -> Iterator[StandardLog]:
        """Yield logs normalized to StandardLog objects."""
        raise NotImplementedError

    @abstractmethod
    def can_handle(self, file_path: str) -> bool:
        """Return True if the reader can handle the given file path."""
        raise NotImplementedError


__all__ = ["LogReader"]
