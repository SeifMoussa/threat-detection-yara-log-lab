"""Rule quality checks for fallback detection rules."""

from __future__ import annotations

import re
from pathlib import Path

from yara_log_lab.rule_loader import load_rules_from_directory

ROOT = Path(__file__).resolve().parents[1]
RULE_ID_PATTERN = re.compile(r"^(AUTH|CMD|FILE|IND)-\d{3}$")


def test_every_fallback_rule_has_required_quality_fields() -> None:
    rules = load_rules_from_directory(ROOT / "rules/fallback")

    for rule in rules:
        assert rule.id
        assert rule.name
        assert rule.description
        assert rule.severity in {"low", "medium", "high"}
        assert rule.tags
        assert rule.rule_type in {"contains", "regex", "field_equals", "threshold"}
        assert rule.target in {"log_field", "file_content"}
        assert rule.false_positive_notes
        assert rule.sample_references
        assert isinstance(rule.enabled, bool)


def test_rule_ids_are_unique_and_consistent() -> None:
    rules = load_rules_from_directory(ROOT / "rules/fallback")
    rule_ids = [rule.id for rule in rules]

    assert len(rule_ids) == len(set(rule_ids))
    assert all(RULE_ID_PATTERN.match(rule_id) for rule_id in rule_ids)


def test_enabled_rules_have_positive_sample_references() -> None:
    rules = load_rules_from_directory(ROOT / "rules/fallback")

    for rule in rules:
        if not rule.enabled:
            continue
        assert any("suspicious" in reference for reference in rule.sample_references)


def test_rules_document_negative_or_false_positive_context() -> None:
    rules = load_rules_from_directory(ROOT / "rules/fallback")

    for rule in rules:
        note = rule.false_positive_notes.lower()
        assert "training" in note or "documentation" in note or "false" in note
