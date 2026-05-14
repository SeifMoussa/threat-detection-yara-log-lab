"""Structured alert objects produced by the fallback detection engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MAX_EXCERPT_LENGTH = 120


@dataclass(frozen=True)
class Alert:
    """Serializable detection alert."""

    rule_id: str
    rule_name: str
    severity: str
    source_path: str
    source_type: str
    matched_field: str | None
    matched_value: str
    message: str
    tags: tuple[str, ...]
    suppressed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable alert dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "source_path": self.source_path,
            "source_type": self.source_type,
            "matched_field": self.matched_field,
            "matched_value": self.matched_value,
            "message": self.message,
            "tags": list(self.tags),
            "suppressed": self.suppressed,
            "metadata": self.metadata,
        }


def safe_excerpt(value: object, max_length: int = MAX_EXCERPT_LENGTH) -> str:
    """Return a short single-line excerpt for alert output."""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."
