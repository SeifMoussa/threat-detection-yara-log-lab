"""Tests for the fallback detection engine."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from yara_log_lab.engine import DetectionError, UnsupportedInputError, scan_file_text, scan_path
from yara_log_lab.log_loader import load_csv, load_jsonl
from yara_log_lab.rule_loader import Rule, load_rules_from_directory

ROOT = Path(__file__).resolve().parents[1]


def test_contains_rule_matches_log_field() -> None:
    rules = _rules()
    alerts = scan_path(ROOT / "samples/logs/suspicious/process_suspicious.csv", rules)

    assert any(alert.rule_id == "CMD-001" for alert in alerts)


def test_regex_rule_matches_log_field() -> None:
    rules = _rules()
    alerts = scan_path(ROOT / "samples/logs/suspicious/process_suspicious.csv", rules)

    assert any(alert.rule_id == "IND-001" for alert in alerts)


def test_field_equals_rule_matching() -> None:
    records = load_jsonl(ROOT / "samples/logs/benign/auth_benign.jsonl")
    rule = replace(
        _rules_by_id()["AUTH-001"],
        id="TEST-EQUALS-001",
        name="Login Success Exact Match",
        severity="low",
        rule_type="field_equals",
        field="event_type",
        pattern="login_success",
        condition=None,
    )

    from yara_log_lab.engine import scan_log_records

    alerts = scan_log_records(records, [rule])

    assert len(alerts) == 2
    assert all(alert.matched_field == "event_type" for alert in alerts)


def test_threshold_rule_matching() -> None:
    alerts = scan_path(ROOT / "samples/logs/suspicious/auth_suspicious.jsonl", _rules())

    threshold_alerts = [alert for alert in alerts if alert.rule_id == "AUTH-001"]
    assert len(threshold_alerts) == 1
    assert threshold_alerts[0].metadata["count"] == 5


def test_disabled_rules_are_skipped() -> None:
    rule = replace(_rules_by_id()["CMD-001"], enabled=False)

    alerts = scan_path(ROOT / "samples/logs/suspicious/process_suspicious.csv", [rule])

    assert alerts == []


def test_benign_samples_do_not_produce_high_severity_alerts() -> None:
    auth_alerts = scan_path(ROOT / "samples/logs/benign/auth_benign.jsonl", _rules())
    process_alerts = scan_path(ROOT / "samples/logs/benign/process_benign.csv", _rules())

    assert not any(alert.severity == "high" for alert in [*auth_alerts, *process_alerts])


def test_suspicious_samples_produce_expected_alerts() -> None:
    auth_alerts = scan_path(ROOT / "samples/logs/suspicious/auth_suspicious.jsonl", _rules())
    process_alerts = scan_path(ROOT / "samples/logs/suspicious/process_suspicious.csv", _rules())

    assert {alert.rule_id for alert in [*auth_alerts, *process_alerts]} == {
        "AUTH-001",
        "CMD-001",
        "IND-001",
    }


def test_false_positive_samples_produce_expected_known_matches() -> None:
    auth_alerts = scan_path(
        ROOT / "samples/logs/false_positive/auth_false_positive.jsonl", _rules()
    )
    process_alerts = scan_path(
        ROOT / "samples/logs/false_positive/process_false_positive.csv", _rules()
    )

    assert {alert.rule_id for alert in [*auth_alerts, *process_alerts]} == {
        "AUTH-001",
        "CMD-001",
        "IND-001",
    }


def test_text_file_content_matching() -> None:
    alerts = scan_path(ROOT / "samples/files/suspicious/fake_indicator_note.txt", _rules())

    assert {alert.rule_id for alert in alerts} == {"FILE-001"}
    assert all(alert.source_type == "file" for alert in alerts)


def test_scan_file_text_supports_regex_file_rule() -> None:
    rule = replace(
        _rules_by_id()["FILE-001"],
        id="TEST-FILE-REGEX-001",
        rule_type="regex",
        pattern=r"SYNTHETIC_SUSPICIOUS_FILE_MARKER",
    )

    alerts = scan_file_text("synthetic.txt", "SYNTHETIC_SUSPICIOUS_FILE_MARKER", [rule])

    assert len(alerts) == 1


def test_unsupported_file_extension_rejected() -> None:
    with pytest.raises(UnsupportedInputError, match="Unsupported input extension"):
        scan_path(ROOT / "tests/fixtures/unsupported_input.bin", _rules())


def test_invalid_regex_rejected_safely() -> None:
    records = load_csv(ROOT / "samples/logs/suspicious/process_suspicious.csv")
    rule = replace(_rules_by_id()["IND-001"], pattern="[")

    from yara_log_lab.engine import scan_log_records

    with pytest.raises(DetectionError, match="Invalid regex pattern"):
        scan_log_records(records, [rule])


def _rules() -> list[Rule]:
    return load_rules_from_directory(ROOT / "rules/fallback")


def _rules_by_id() -> dict[str, Rule]:
    return {rule.id: rule for rule in _rules()}
