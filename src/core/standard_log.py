"""StandardLog model: unified representation of a log entry.
Moved from src/log_processing.py to core for cleaner architecture.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional, List, Dict, Any


class StandardLog:
    """
    A unified representation of a log entry, regardless of its original format.

    Attributes
    ----------
    timestamp : Optional[datetime]
        When the log event occurred
    level : Optional[str]
        Log level (INFO, WARNING, ERROR, etc.)
    message : str
        The main content of the log entry
    source : Optional[str]
        Component or service that generated the log
    log_id : Optional[str]
        Unique identifier for the log entry
    raw_content : str
        The original unparsed log entry
    metadata : Dict[str, Any]
        Additional format-specific information
    parsed : bool
        Whether the log was successfully parsed
    tags : List[str]
        List of tags associated with this log
    """

    def __init__(
        self,
        message: str,
        raw_content: str,
        timestamp: Optional[datetime] = None,
        level: Optional[str] = None,
        source: Optional[str] = None,
        log_id: Optional[str] = None,
        parsed: bool = True,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.raw_content = raw_content
        self.timestamp = timestamp
        self.level = level
        self.source = source
        self.log_id = log_id
        self.parsed = parsed
        self.tags = tags or []
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the StandardLog to a dictionary.
        """
        result: Dict[str, Any] = {
            "message": self.message,
            "parsed": self.parsed,
            "tags": self.tags.copy(),
            "metadata": self.metadata.copy(),
        }
        if self.timestamp:
            result["timestamp"] = self.timestamp.isoformat()
        if self.level:
            result["level"] = self.level
        if self.source:
            result["source"] = self.source
        if self.log_id:
            result["log_id"] = self.log_id
        # raw_content intentionally omitted by default
        return result

    def to_json(self) -> str:
        """Convert the StandardLog to a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StandardLog":
        """Create a StandardLog from a dictionary."""
        # Normalize timestamp if provided
        if "timestamp" in data and data["timestamp"]:
            if isinstance(data["timestamp"], str):
                try:
                    data["timestamp"] = datetime.fromisoformat(
                        data["timestamp"].replace("Z", "+00:00")
                    )
                except ValueError:
                    try:
                        from dateutil import parser  # type: ignore

                        data["timestamp"] = parser.parse(data["timestamp"])
                    except Exception:
                        pass
        if "message" not in data:
            data["message"] = ""
        if "raw_content" not in data:
            data["raw_content"] = data.get("message", "")
        return cls(
            message=data["message"],
            raw_content=data["raw_content"],
            timestamp=data.get("timestamp"),
            level=data.get("level"),
            source=data.get("source"),
            log_id=data.get("log_id"),
            parsed=data.get("parsed", True),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "StandardLog":
        """Create a StandardLog from a JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def add_tag(self, tag: str) -> None:
        """Add a tag to the log entry."""
        if tag not in self.tags:
            self.tags.append(tag)

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the log entry."""
        self.metadata[key] = value

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get metadata value with default if missing."""
        return self.metadata.get(key, default)


__all__ = ["StandardLog"]
