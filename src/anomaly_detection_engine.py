"""Rule-based, multi-feature log anomaly detector.

The detector upgrades the legacy "ERROR-only" filter by layering
multiple detection strategies:

1. Severity detection (ERROR/FATAL levels)
2. Content keyword detection (SQLi, traversal, etc.)
3. Statistical latency detection (duration thresholds)
4. Sliding-window frequency detection for failed-logins per IP

Usage:
    detector = LogAnomalyDetector()
    anomalies = detector.detect(parsed_logs)

Where ``parsed_logs`` is an iterable of dictionaries containing
``timestamp``, ``log_level``, ``module`` and ``message`` keys.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import re
from typing import Any, Deque, DefaultDict, Dict, Iterable, List, Optional

_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
)

_DURATION_PATTERNS = (
    re.compile(r"duration_ms\s*[:=]\s*(?P<value>\d+)", re.IGNORECASE),
    re.compile(r"duration\s*[:=]\s*(?P<value>\d+)\s*ms", re.IGNORECASE),
    re.compile(r"query\s*time\s*(?:exceeded|=)\s*(?P<value>\d+)\s*ms", re.IGNORECASE),
    re.compile(r"latency\s*(?:is|=|:)\s*(?P<value>\d+)\s*ms", re.IGNORECASE),
)

_FAILED_LOGIN_PATTERNS = (
    re.compile(r"failed\s+login", re.IGNORECASE),
    re.compile(r"failed\s+password", re.IGNORECASE),
    re.compile(r"authentication\s+failure", re.IGNORECASE),
)

_IP_REGEX = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


@dataclass
class DetectionConfig:
    severity_levels: tuple = ("ERROR", "FATAL")
    suspicious_keywords: tuple = (
        "directory traversal",
        "sql injection",
        "xss",
        "/etc/passwd",
        "potential attack",
    )
    duration_threshold_ms: int = 5000
    failed_login_threshold: int = 5
    failed_login_window: timedelta = field(default_factory=lambda: timedelta(seconds=60))


class LogAnomalyDetector:
    """Multi-feature anomaly detector built on simple dictionaries."""

    def __init__(self, config: Optional[DetectionConfig] = None) -> None:
        self.config = config or DetectionConfig()
        self._failed_login_history: DefaultDict[str, Deque[datetime]] = defaultdict(deque)

    def reset_state(self) -> None:
        self._failed_login_history.clear()

    def detect(self, logs: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return a list of anomaly records with detection reasons."""
        self.reset_state()
        # Sort logs by timestamp to make the frequency detector reliable
        sorted_logs = sorted(logs, key=lambda log: self._parse_timestamp(log.get("timestamp")))
        anomalies: List[Dict[str, Any]] = []
        for entry in sorted_logs:
            ts = self._parse_timestamp(entry.get("timestamp"))
            reasons: List[str] = []

            if self._is_severity_anomaly(entry):
                reasons.append("severity")

            if self._is_content_anomaly(entry):
                reasons.append("suspicious_content")

            if self._is_statistical_anomaly(entry):
                reasons.append("slow_operation")

            if self._is_frequency_anomaly(entry, ts):
                reasons.append("failed_login_burst")

            if reasons:
                anomalies.append(
                    {
                        "log": entry,
                        "reasons": reasons,
                        "timestamp": ts.isoformat() if ts else entry.get("timestamp"),
                    }
                )
        return anomalies

    # --- Detection Helpers -------------------------------------------------
    def _is_severity_anomaly(self, entry: Dict[str, Any]) -> bool:
        level = str(entry.get("log_level", "")).upper()
        return bool(level and level in self.config.severity_levels)

    def _is_content_anomaly(self, entry: Dict[str, Any]) -> bool:
        message = str(entry.get("message", ""))
        msg_lower = message.lower()
        return any(keyword in msg_lower for keyword in self.config.suspicious_keywords)

    def _is_statistical_anomaly(self, entry: Dict[str, Any]) -> bool:
        message = str(entry.get("message", ""))
        for pattern in _DURATION_PATTERNS:
            match = pattern.search(message)
            if match:
                try:
                    value = int(match.group("value"))
                    if value >= self.config.duration_threshold_ms:
                        return True
                except (TypeError, ValueError):
                    continue
        return False

    def _is_frequency_anomaly(self, entry: Dict[str, Any], timestamp: Optional[datetime]) -> bool:
        if timestamp is None:
            return False
        message = str(entry.get("message", ""))
        if not any(pat.search(message) for pat in _FAILED_LOGIN_PATTERNS):
            return False
        ip = self._extract_ip(entry)
        if not ip:
            return False

        history = self._failed_login_history[ip]
        window_start = timestamp - self.config.failed_login_window
        while history and history[0] < window_start:
            history.popleft()
        history.append(timestamp)
        return len(history) >= self.config.failed_login_threshold

    # --- Utilities ---------------------------------------------------------
    def _parse_timestamp(self, value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value
        if not value:
            return None
        text = str(value).strip()
        for fmt in _TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
        # Attempt ISO parse with colon milliseconds trimmed
        try:
            if "," in text:
                return datetime.fromisoformat(text.replace(",", "."))
        except ValueError:
            pass
        return None

    def _extract_ip(self, entry: Dict[str, Any]) -> Optional[str]:
        ip = entry.get("ip") or entry.get("client_ip")
        if isinstance(ip, str) and ip:
            return ip
        message = str(entry.get("message", ""))
        match = _IP_REGEX.search(message)
        return match.group(0) if match else None


__all__ = ["LogAnomalyDetector", "DetectionConfig"]
