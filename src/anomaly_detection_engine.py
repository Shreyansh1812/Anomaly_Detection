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
from typing import Any, Deque, DefaultDict, Dict, Iterable, List, Optional, Set

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

_HTTP_REQUEST_REGEX = re.compile(
    r"\b(GET|POST|PUT|DELETE|CONNECT|PATCH|OPTIONS)\s+([^\s\"]+)",
    re.IGNORECASE,
)

_DANGEROUS_HTTP_METHODS = {"PUT", "POST", "DELETE", "CONNECT"}
_STATIC_FILE_EXTENSIONS = (".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico")


@dataclass
class DetectionConfig:
    severity_levels: tuple = ("ERROR", "FATAL")
    suspicious_keywords: tuple = (
        "directory traversal",
        "sql injection",
        "xss",
        "/etc/passwd",
        "potential attack",
        "nikto",
        "nmap",
        "sqlmap",
        "zap",
        "arachni",
    )
    duration_threshold_ms: int = 5000
    failed_login_threshold: int = 5
    http_failed_login_threshold: int = 2
    auth_failed_login_threshold: int = 2
    failed_login_window: timedelta = field(default_factory=lambda: timedelta(seconds=60))


class LogAnomalyDetector:
    """Multi-feature anomaly detector built on simple dictionaries."""

    def __init__(self, config: Optional[DetectionConfig] = None) -> None:
        self.config = config or DetectionConfig()
        self._failed_login_history: DefaultDict[
            str, DefaultDict[str, Deque[tuple[datetime, int]]]
        ] = defaultdict(lambda: defaultdict(deque))

    def reset_state(self) -> None:
        self._failed_login_history.clear()

    def detect(self, logs: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return a list of anomaly records with detection reasons."""
        self.reset_state()
        # Sort logs by timestamp to make the frequency detector reliable
        sorted_logs = sorted(
            logs,
            key=lambda log: self._parse_timestamp(log.get("timestamp")) or datetime.min,
        )
        failed_login_indices = self._collect_failed_login_indices(sorted_logs)
        anomalies: List[Dict[str, Any]] = []
        for idx, entry in enumerate(sorted_logs):
            ts = self._parse_timestamp(entry.get("timestamp"))
            reasons: List[str] = []

            if self._is_severity_anomaly(entry):
                reasons.append("severity")

            if self._is_content_anomaly(entry):
                reasons.append("suspicious_content")

            if self._is_statistical_anomaly(entry):
                reasons.append("slow_operation")

            if idx in failed_login_indices:
                reasons.append("failed_login_burst")

            if self._is_anomalous_http_method(entry):
                reasons.append("anomalous_http_method")

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

    def _collect_failed_login_indices(self, logs: List[Dict[str, Any]]) -> Set[int]:
        flagged: Set[int] = set()
        history: DefaultDict[str, DefaultDict[str, Deque[tuple[datetime, int]]]] = self._failed_login_history
        history.clear()
        for idx, entry in enumerate(logs):
            ts = self._parse_timestamp(entry.get("timestamp"))
            if ts is None:
                continue
            message = str(entry.get("message", ""))
            category = self._classify_failed_login(entry, message)
            if not category:
                continue
            ip = self._extract_ip(entry)
            if not ip:
                continue
            threshold = self._threshold_for_failed_login(category)
            if threshold <= 0:
                continue
            dq = history[ip][category]
            dq.append((ts, idx))
            window_start = ts - self.config.failed_login_window
            while dq and dq[0][0] < window_start:
                dq.popleft()
            if len(dq) >= threshold:
                flagged.update(hit_idx for _, hit_idx in dq)
        return flagged

    def _classify_failed_login(self, entry: Dict[str, Any], message: str) -> Optional[str]:
        if any(pat.search(message) for pat in _FAILED_LOGIN_PATTERNS):
            return "auth"
        module = str(entry.get("module", "")).upper()
        status_code = self._extract_status_code(entry)
        if module == "HTTP_ACCESS" and status_code == 401:
            return "http"
        return None

    def _threshold_for_failed_login(self, category: str) -> int:
        if category == "http":
            return self.config.http_failed_login_threshold or self.config.failed_login_threshold
        if category == "auth":
            return self.config.auth_failed_login_threshold or self.config.failed_login_threshold
        return self.config.failed_login_threshold

    def _extract_status_code(self, entry: Dict[str, Any]) -> Optional[int]:
        for key in ("http_status", "status", "status_code"):
            value = entry.get(key)
            if value is None:
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        message = str(entry.get("message", ""))
        match = re.search(r"status=(\d{3})", message)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
        return None

    def _is_anomalous_http_method(self, entry: Dict[str, Any]) -> bool:
        module = str(entry.get("module", "")).upper()
        if module != "HTTP_ACCESS":
            return False
        method, path = self._extract_http_method_and_path(entry)
        if not method or not path:
            return False
        method = method.upper()
        normalized_path = path.lower().split("?", 1)[0]
        return method in _DANGEROUS_HTTP_METHODS and any(
            normalized_path.endswith(ext) for ext in _STATIC_FILE_EXTENSIONS
        )

    def _extract_http_method_and_path(self, entry: Dict[str, Any]) -> tuple[str, str]:
        method = str(entry.get("http_method") or entry.get("method") or "").upper()
        path = str(entry.get("path") or "")
        if method and path:
            return method, path
        message = str(entry.get("message", ""))
        match = _HTTP_REQUEST_REGEX.search(message)
        if not method and match:
            method = match.group(1).upper()
        if not path and match:
            path = match.group(2)
        return method, path

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
