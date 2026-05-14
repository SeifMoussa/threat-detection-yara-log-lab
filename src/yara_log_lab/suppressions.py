"""Suppression loading and application for known false positives."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from yara_log_lab.alerts import Alert


class SuppressionValidationError(ValueError):
    """Raised when a suppression file is invalid."""


@dataclass(frozen=True)
class Suppression:
    """A simple false-positive suppression rule."""

    id: str
    rule_id: str
    reason: str
    source_path_contains: str | None = None
    matched_value_contains: str | None = None


def load_suppressions(path: str | Path) -> list[Suppression]:
    """Load suppressions from a JSON file."""
    suppression_path = Path(path)
    try:
        payload = json.loads(suppression_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SuppressionValidationError(
            f"Could not read suppression file {suppression_path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise SuppressionValidationError(
            f"Invalid JSON in suppression file {suppression_path}: {exc}"
        ) from exc

    raw_suppressions = payload.get("suppressions") if isinstance(payload, dict) else None
    if not isinstance(raw_suppressions, list):
        raise SuppressionValidationError("Suppression file must contain a 'suppressions' list")

    return [_validate_suppression(raw) for raw in raw_suppressions]


def apply_suppressions(alerts: list[Alert], suppressions: list[Suppression]) -> list[Alert]:
    """Mark matching alerts as suppressed and attach suppression metadata."""
    suppressed_alerts: list[Alert] = []
    for alert in alerts:
        suppression = _matching_suppression(alert, suppressions)
        if suppression is None:
            suppressed_alerts.append(alert)
            continue
        metadata = {
            **alert.metadata,
            "suppression_id": suppression.id,
            "suppression_reason": suppression.reason,
        }
        suppressed_alerts.append(replace(alert, suppressed=True, metadata=metadata))
    return suppressed_alerts


def _matching_suppression(alert: Alert, suppressions: list[Suppression]) -> Suppression | None:
    for suppression in suppressions:
        if alert.rule_id != suppression.rule_id:
            continue
        if (
            suppression.source_path_contains is not None
            and suppression.source_path_contains not in alert.source_path
        ):
            continue
        if (
            suppression.matched_value_contains is not None
            and suppression.matched_value_contains not in alert.matched_value
        ):
            continue
        return suppression
    return None


def _validate_suppression(raw: Any) -> Suppression:
    if not isinstance(raw, dict):
        raise SuppressionValidationError("Each suppression must be an object")
    suppression_id = _required_string(raw, "id")
    rule_id = _required_string(raw, "rule_id")
    reason = _required_string(raw, "reason")
    source_path_contains = _optional_string(raw, "source_path_contains")
    matched_value_contains = _optional_string(raw, "matched_value_contains")
    return Suppression(
        id=suppression_id,
        rule_id=rule_id,
        reason=reason,
        source_path_contains=source_path_contains,
        matched_value_contains=matched_value_contains,
    )


def _required_string(raw: dict[str, Any], field_name: str) -> str:
    value = raw.get(field_name)
    if not isinstance(value, str) or not value:
        raise SuppressionValidationError(f"Suppression field '{field_name}' is required")
    return value


def _optional_string(raw: dict[str, Any], field_name: str) -> str | None:
    value = raw.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise SuppressionValidationError(
            f"Suppression field '{field_name}' must be a non-empty string"
        )
    return value
