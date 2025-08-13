"""CSV log ingestion utilities used by the unified LogReader adapters.

This module provides a lightweight CSVLogReader consumed by
CSVLogReaderAdapter in src/log_processing.py. It focuses on robust CSV
loading with sensible defaults and a couple of fallbacks for encoding and
delimiter detection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional
import pandas as pd


class CSVLogReader:
	"""Lightweight CSV reader that returns a pandas DataFrame.

	Parameters
	----------
	file_path : str | Path
		Path to the CSV file to read.
	format_type : Optional[str]
		Optional logical format hint (e.g., BGL, HDFS). Currently unused but
		accepted for compatibility with the adapter.
	"""

	def __init__(self, file_path: str | Path, format_type: Optional[str] = None) -> None:
		self.file_path = str(file_path)
		self.format_type = format_type

	def read(self) -> pd.DataFrame:
		"""Read the CSV into a DataFrame with robust fallbacks.

		Tries utf-8 then latin-1 encoding. Falls back to Python engine with
		automatic delimiter detection if standard reads fail.
		"""
		# Primary attempts with common encodings
		for enc in ("utf-8", "latin-1"):
			try:
				return pd.read_csv(
					self.file_path,
					encoding=enc,
					on_bad_lines="skip",
					low_memory=False,
				)
			except Exception:
				continue

		# Fallback: attempt delimiter sniffing via Python engine
		try:
			return pd.read_csv(
				self.file_path,
				sep=None,
				engine="python",
				on_bad_lines="skip",
				low_memory=False,
			)
		except Exception as e:
			# Re-raise with file context for easier debugging
			raise RuntimeError(f"Failed to read CSV: {self.file_path}: {e}")


__all__ = ["CSVLogReader"]

