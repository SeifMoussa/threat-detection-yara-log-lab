"""Fallback JSON rule loading and schema validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SUPPORTED_RULE_TYPES = {"contains", "regex", "field_equals", "threshold"}
SUPPORTED_SEVERITIES = {"low", "medium", "high"}
SUPPORTED_TARGETS = {"log_field", "file_content"}

REQUIRED_FIELDS = {
    "id",
    "name",
    "description",
    "severity",
    "tags",
    "rule_type",
    "target",
    "false_positive_notes",
    "sample_references",
    "enabled",
}


class RuleValidationError(ValueError):
    """Raised when a fallback rule does not match the expected schema."""


@dataclass(frozen=True)
class Rule:
    """Validated fallback rule definition."""

    id: str
    name: str
    description: str
    severity: str
    tags: tuple[str, ...]
    rule_type: str
    target: str
    false_positive_notes: str
    sample_references: tuple[str, ...]
    enabled: bool
    pattern: str | None = None
    condition: dict[str, Any] | None = None
    field: str | None = None
    source_path: Path | None = None


def load_rules_from_file(path: str | Path) -> list[Rule]:
    """Load and validate fallback rules from one JSON file."""
    rule_path = Path(path)
    try:
        payload = json.loads(rule_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuleValidationError(f"Invalid JSON in rule file {rule_path}: {exc}") from exc

    raw_rules = _extract_rules(payload, rule_path)
    return [validate_rule(raw_rule, source_path=rule_path) for raw_rule in raw_rules]


def load_rules_from_directory(path: str | Path) -> list[Rule]:
    """Load and validate all fallback JSON rules in a directory."""
    rule_dir = Path(path)
    if not rule_dir.is_dir():
        raise RuleValidationError(f"Rule directory does not exist: {rule_dir}")

    rules: list[Rule] = []
    for rule_file in sorted(rule_dir.glob("*.json")):
        rules.extend(load_rules_from_file(rule_file))
    return rules


def validate_rule(raw_rule: dict[str, Any], source_path: Path | None = None) -> Rule:
    """Validate one fallback rule and return a structured object."""
    if not isinstance(raw_rule, dict):
        raise RuleValidationError("Each rule must be a JSON object")

    missing = sorted(REQUIRED_FIELDS - raw_rule.keys())
    if missing:
        raise RuleValidationError(f"Rule is missing required fields: {', '.join(missing)}")

    rule_type = _require_string(raw_rule, "rule_type")
    if rule_type not in SUPPORTED_RULE_TYPES:
        raise RuleValidationError(f"Unsupported rule_type: {rule_type}")

    severity = _require_string(raw_rule, "severity")
    if severity not in SUPPORTED_SEVERITIES:
        raise RuleValidationError(f"Unsupported severity: {severity}")

    target = _require_string(raw_rule, "target")
    if target not in SUPPORTED_TARGETS:
        raise RuleValidationError(f"Unsupported target: {target}")

    tags = _require_string_list(raw_rule, "tags")
    sample_references = _require_string_list(raw_rule, "sample_references")

    enabled = raw_rule["enabled"]
    if not isinstance(enabled, bool):
        raise RuleValidationError("Rule field 'enabled' must be a boolean")

    pattern = raw_rule.get("pattern")
    condition = raw_rule.get("condition")
    field = raw_rule.get("field")

    if rule_type in {"contains", "regex", "field_equals"}:
        if not isinstance(pattern, str) or not pattern:
            raise RuleValidationError(f"Rule type '{rule_type}' requires a non-empty pattern")

    if rule_type == "threshold":
        if not isinstance(condition, dict) or not condition:
            raise RuleValidationError("Rule type 'threshold' requires a non-empty condition object")

    if target == "log_field" and (not isinstance(field, str) or not field):
        raise RuleValidationError("Rules targeting 'log_field' require a non-empty field")

    if pattern is not None and not isinstance(pattern, str):
        raise RuleValidationError("Rule field 'pattern' must be a string when provided")

    if condition is not None and not isinstance(condition, dict):
        raise RuleValidationError("Rule field 'condition' must be an object when provided")

    if field is not None and not isinstance(field, str):
        raise RuleValidationError("Rule field 'field' must be a string when provided")

    return Rule(
        id=_require_string(raw_rule, "id"),
        name=_require_string(raw_rule, "name"),
        description=_require_string(raw_rule, "description"),
        severity=severity,
        tags=tuple(tags),
        rule_type=rule_type,
        target=target,
        false_positive_notes=_require_string(raw_rule, "false_positive_notes"),
        sample_references=tuple(sample_references),
        enabled=enabled,
        pattern=pattern,
        condition=condition,
        field=field,
        source_path=source_path,
    )


def _extract_rules(payload: Any, source_path: Path) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
        return payload["rules"]
    if isinstance(payload, list):
        return payload
    raise RuleValidationError(f"Rule file {source_path} must contain a 'rules' list")


def _require_string(raw_rule: dict[str, Any], field_name: str) -> str:
    value = raw_rule[field_name]
    if not isinstance(value, str) or not value:
        raise RuleValidationError(f"Rule field '{field_name}' must be a non-empty string")
    return value


def _require_string_list(raw_rule: dict[str, Any], field_name: str) -> list[str]:
    value = raw_rule[field_name]
    if not isinstance(value, list) or not value:
        raise RuleValidationError(f"Rule field '{field_name}' must be a non-empty list")
    if not all(isinstance(item, str) and item for item in value):
        raise RuleValidationError(f"Rule field '{field_name}' must contain only non-empty strings")
    return value
