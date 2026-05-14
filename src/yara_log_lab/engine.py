"""Safe fallback detection engine for local synthetic samples."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from yara_log_lab.alerts import Alert, safe_excerpt
from yara_log_lab.log_loader import LogLoadError, load_log_file
from yara_log_lab.rule_loader import Rule

SUPPORTED_INPUT_EXTENSIONS = {".jsonl", ".csv", ".txt", ".log"}
LOG_EXTENSIONS = {".jsonl", ".csv"}
TEXT_EXTENSIONS = {".txt", ".log"}


class DetectionError(ValueError):
    """Raised when detection cannot complete safely."""


class UnsupportedInputError(DetectionError):
    """Raised when an input path or extension is unsupported."""


def scan_log_records(records: Iterable[dict[str, Any]], rules: Iterable[Rule]) -> list[Alert]:
    """Scan normalized log records with enabled log-field rules."""
    record_list = list(records)
    alerts: list[Alert] = []
    for rule in rules:
        if not rule.enabled or rule.target != "log_field":
            continue
        if rule.rule_type == "threshold":
            alerts.extend(_scan_threshold(record_list, rule))
            continue
        for record in record_list:
            alert = _scan_log_record(record, rule)
            if alert is not None:
                alerts.append(alert)
    return alerts


def scan_file_text(path: str | Path, text: str, rules: Iterable[Rule]) -> list[Alert]:
    """Scan one local text file with enabled file-content rules."""
    source_path = str(Path(path))
    alerts: list[Alert] = []
    for rule in rules:
        if not rule.enabled or rule.target != "file_content":
            continue
        if rule.rule_type == "contains":
            matched = rule.pattern is not None and rule.pattern in text
        elif rule.rule_type == "regex":
            matched = _regex_search(rule.pattern, text)
        elif rule.rule_type == "field_equals":
            matched = rule.pattern == text
        else:
            continue
        if matched:
            alerts.append(
                _build_alert(
                    rule=rule,
                    source_path=source_path,
                    source_type="file",
                    matched_field=None,
                    matched_value=text,
                    message=f"Rule {rule.id} matched file content",
                    metadata={},
                )
            )
    return alerts


def scan_path(path: str | Path, rules: Iterable[Rule]) -> list[Alert]:
    """Scan one explicit local file or one non-recursive directory."""
    input_path = Path(path)
    if not input_path.exists():
        raise UnsupportedInputError(f"Input path does not exist: {input_path}")
    if input_path.is_dir():
        alerts: list[Alert] = []
        for child in sorted(input_path.iterdir()):
            if child.is_file() and child.suffix.lower() in SUPPORTED_INPUT_EXTENSIONS:
                alerts.extend(scan_path(child, rules))
        return alerts
    if not input_path.is_file():
        raise UnsupportedInputError(f"Input path is not a regular file: {input_path}")

    suffix = input_path.suffix.lower()
    if suffix not in SUPPORTED_INPUT_EXTENSIONS:
        raise UnsupportedInputError(f"Unsupported input extension for {input_path}")
    if suffix in LOG_EXTENSIONS:
        try:
            return scan_log_records(load_log_file(input_path), rules)
        except LogLoadError as exc:
            raise DetectionError(str(exc)) from exc
    if suffix in TEXT_EXTENSIONS:
        try:
            text = input_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise DetectionError(f"Could not read text input {input_path}: {exc}") from exc
        return scan_file_text(input_path, text, rules)

    raise UnsupportedInputError(f"Unsupported input extension for {input_path}")


def scan_many(paths: Iterable[str | Path], rules: Iterable[Rule]) -> list[Alert]:
    """Scan multiple explicit local paths."""
    rule_list = list(rules)
    alerts: list[Alert] = []
    for path in paths:
        alerts.extend(scan_path(path, rule_list))
    return alerts


def _scan_log_record(record: dict[str, Any], rule: Rule) -> Alert | None:
    field_name = rule.field
    if field_name is None:
        return None
    value = record.get(field_name)
    if value is None:
        return None

    text_value = str(value)
    if rule.rule_type == "contains":
        matched = rule.pattern is not None and rule.pattern in text_value
    elif rule.rule_type == "regex":
        matched = _regex_search(rule.pattern, text_value)
    elif rule.rule_type == "field_equals":
        matched = rule.pattern == text_value
    else:
        return None

    if not matched:
        return None

    return _build_alert(
        rule=rule,
        source_path=str(record.get("_source_path", "")),
        source_type="log",
        matched_field=field_name,
        matched_value=text_value,
        message=f"Rule {rule.id} matched log field '{field_name}'",
        metadata=_record_metadata(record),
    )


def _scan_threshold(records: list[dict[str, Any]], rule: Rule) -> list[Alert]:
    condition = rule.condition or {}
    field = _condition_string(condition, "field")
    expected_value = condition.get("equals", condition.get("value"))
    count_gte = condition.get("count_gte")
    group_by = condition.get("group_by", [])

    if not field or expected_value is None or not isinstance(count_gte, int):
        raise DetectionError(f"Threshold rule {rule.id} has an unsupported condition")
    if not isinstance(group_by, list) or not all(isinstance(item, str) for item in group_by):
        raise DetectionError(f"Threshold rule {rule.id} has invalid group_by fields")

    grouped: dict[tuple[object, ...], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record.get(field) != expected_value:
            continue
        key = tuple(record.get(group_field, "") for group_field in group_by)
        grouped[key].append(record)

    alerts: list[Alert] = []
    for key, matches in grouped.items():
        if len(matches) < count_gte:
            continue
        first_match = matches[0]
        group_metadata = dict(zip(group_by, key, strict=False))
        group_metadata["count"] = len(matches)
        if "window_minutes" in condition:
            group_metadata["window_minutes"] = condition["window_minutes"]
        alerts.append(
            _build_alert(
                rule=rule,
                source_path=str(first_match.get("_source_path", "")),
                source_type="log",
                matched_field=field,
                matched_value=expected_value,
                message=f"Rule {rule.id} matched threshold count {len(matches)}",
                metadata={**_record_metadata(first_match), **group_metadata},
            )
        )
    return alerts


def _regex_search(pattern: str | None, text: str) -> bool:
    if pattern is None:
        return False
    try:
        return re.search(pattern, text) is not None
    except re.error as exc:
        raise DetectionError(f"Invalid regex pattern: {exc}") from exc


def _build_alert(
    rule: Rule,
    source_path: str,
    source_type: str,
    matched_field: str | None,
    matched_value: object,
    message: str,
    metadata: dict[str, Any],
) -> Alert:
    return Alert(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        source_path=source_path,
        source_type=source_type,
        matched_field=matched_field,
        matched_value=safe_excerpt(matched_value),
        message=message,
        tags=rule.tags,
        metadata=metadata,
    )


def _record_metadata(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key.startswith("_source_") or key in {"timestamp", "host", "user", "source_ip"}
    }


def _condition_string(condition: dict[str, Any], key: str) -> str | None:
    value = condition.get(key)
    return value if isinstance(value, str) and value else None
