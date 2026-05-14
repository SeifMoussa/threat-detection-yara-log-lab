"""Tests for Phase 2 fallback rule schema validation."""

from pathlib import Path

import pytest

from yara_log_lab.rule_loader import (
    RuleValidationError,
    load_rules_from_directory,
    validate_rule,
)

ROOT = Path(__file__).resolve().parents[1]


def test_load_fallback_rules_from_directory() -> None:
    rules = load_rules_from_directory(ROOT / "rules/fallback")

    assert {rule.id for rule in rules} == {"AUTH-001", "CMD-001", "FILE-001", "IND-001"}
    assert all(rule.enabled for rule in rules)


def test_every_fallback_rule_has_sample_references_and_false_positive_notes() -> None:
    rules = load_rules_from_directory(ROOT / "rules/fallback")

    for rule in rules:
        assert rule.sample_references
        assert rule.false_positive_notes


def test_validate_rule_rejects_missing_required_field() -> None:
    with pytest.raises(RuleValidationError, match="missing required fields"):
        validate_rule({"id": "BROKEN-001"})


def test_validate_rule_rejects_invalid_severity() -> None:
    raw_rule = _valid_rule()
    raw_rule["severity"] = "critical"

    with pytest.raises(RuleValidationError, match="Unsupported severity"):
        validate_rule(raw_rule)


def test_validate_rule_rejects_invalid_rule_type() -> None:
    raw_rule = _valid_rule()
    raw_rule["rule_type"] = "unsupported"

    with pytest.raises(RuleValidationError, match="Unsupported rule_type"):
        validate_rule(raw_rule)


def test_validate_threshold_rule_requires_condition() -> None:
    raw_rule = _valid_rule()
    raw_rule["rule_type"] = "threshold"
    raw_rule.pop("pattern")

    with pytest.raises(RuleValidationError, match="requires a non-empty condition"):
        validate_rule(raw_rule)


def _valid_rule() -> dict[str, object]:
    return {
        "id": "TEST-001",
        "name": "Test Rule",
        "description": "Synthetic test rule.",
        "severity": "low",
        "tags": ["synthetic"],
        "rule_type": "contains",
        "target": "log_field",
        "field": "message",
        "pattern": "SYNTHETIC_TEST_MARKER",
        "false_positive_notes": "Synthetic test false-positive note.",
        "sample_references": ["samples/logs/benign/auth_benign.jsonl"],
        "enabled": True,
    }
