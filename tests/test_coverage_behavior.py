"""Additional behavior tests for meaningful coverage gaps."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from yara_log_lab.alerts import Alert
from yara_log_lab.cli import main
from yara_log_lab.engine import (
    DetectionError,
    UnsupportedInputError,
    scan_file_text,
    scan_log_records,
    scan_path,
)
from yara_log_lab.log_loader import LogLoadError, load_csv, load_jsonl
from yara_log_lab.reporting import build_report, render_markdown_report, write_report
from yara_log_lab.rule_loader import Rule, RuleValidationError, load_rules_from_file, validate_rule
from yara_log_lab.suppressions import (
    Suppression,
    SuppressionValidationError,
    apply_suppressions,
    load_suppressions,
)

ROOT = Path(__file__).resolve().parents[1]


def test_module_entrypoint_help_runs() -> None:
    assert main([]) == 0


def test_cli_text_scan_prints_no_alerts_for_benign_sample(capsys) -> None:
    exit_code = main(
        [
            "scan",
            "--rules",
            str(ROOT / "rules/fallback"),
            "--input",
            str(ROOT / "samples/logs/benign/auth_benign.jsonl"),
            "--format",
            "text",
        ]
    )

    assert exit_code == 0
    assert "No alerts" in capsys.readouterr().out


def test_cli_invalid_suppression_file_returns_clean_error(capsys) -> None:
    exit_code = main(
        [
            "scan",
            "--rules",
            str(ROOT / "rules/fallback"),
            "--input",
            str(ROOT / "samples/logs/false_positive/auth_false_positive.jsonl"),
            "--suppressions",
            str(ROOT / "tests/fixtures/invalid_suppressions.json"),
        ]
    )

    assert exit_code == 2
    assert "Suppression field" in capsys.readouterr().err


def test_scan_path_rejects_missing_path() -> None:
    with pytest.raises(UnsupportedInputError, match="does not exist"):
        scan_path(ROOT / "samples/logs/missing.jsonl", [])


def test_scan_directory_processes_supported_files_non_recursively() -> None:
    alerts = scan_path(ROOT / "samples/logs/suspicious", _rules())

    assert {alert.rule_id for alert in alerts} == {"AUTH-001", "CMD-001", "IND-001"}


def test_scan_log_loader_error_becomes_detection_error() -> None:
    with pytest.raises(DetectionError, match="Invalid JSON"):
        scan_path(ROOT / "tests/fixtures/invalid_log.jsonl", _rules())


def test_file_content_field_equals_rule_matches_exact_text() -> None:
    rule = replace(
        _rules_by_id()["FILE-001"],
        id="TEST-FILE-EQUALS-001",
        rule_type="field_equals",
        pattern="exact synthetic text",
    )

    alerts = scan_file_text("sample.txt", "exact synthetic text", [rule])

    assert len(alerts) == 1
    assert alerts[0].source_type == "file"


def test_threshold_rule_rejects_invalid_condition_shape() -> None:
    rule = replace(_rules_by_id()["AUTH-001"], condition={"field": "event_type"})

    with pytest.raises(DetectionError, match="unsupported condition"):
        scan_log_records([], [rule])


def test_threshold_rule_rejects_invalid_group_by() -> None:
    rule = replace(
        _rules_by_id()["AUTH-001"],
        condition={
            "field": "event_type",
            "equals": "failed_login",
            "count_gte": 2,
            "group_by": "user",
        },
    )

    with pytest.raises(DetectionError, match="invalid group_by"):
        scan_log_records([], [rule])


def test_threshold_rule_below_count_does_not_alert() -> None:
    records = [
        {"event_type": "failed_login", "user": "u1", "source_ip": "192.0.2.9"},
        {"event_type": "failed_login", "user": "u1", "source_ip": "192.0.2.9"},
    ]

    alerts = scan_log_records(records, [_rules_by_id()["AUTH-001"]])

    assert alerts == []


def test_load_jsonl_missing_file_fails_clearly() -> None:
    with pytest.raises(LogLoadError, match="Could not read JSONL"):
        load_jsonl(ROOT / "samples/logs/benign/missing.jsonl")


def test_load_jsonl_rejects_non_object_line() -> None:
    with pytest.raises(LogLoadError, match="must be an object"):
        load_jsonl(ROOT / "tests/fixtures/jsonl_array.jsonl")


def test_load_csv_missing_file_fails_clearly() -> None:
    with pytest.raises(LogLoadError, match="Could not read CSV"):
        load_csv(ROOT / "samples/logs/benign/missing.csv")


def test_rule_loader_rejects_invalid_json_file() -> None:
    with pytest.raises(RuleValidationError, match="Invalid JSON"):
        load_rules_from_file(ROOT / "tests/fixtures/invalid_json_rule.json")


def test_rule_loader_accepts_top_level_list_payload() -> None:
    rules = load_rules_from_file(ROOT / "tests/fixtures/list_payload_rule.json")

    assert rules[0].id == "TEST-002"


def test_rule_validation_rejects_additional_invalid_shapes() -> None:
    cases = [
        ("Each rule must be a JSON object", ["not-object"]),
        ("Unsupported target", {**_valid_rule(), "target": "bad"}),
        ("enabled", {**_valid_rule(), "enabled": "true"}),
        ("non-empty pattern", {**_valid_rule(), "pattern": ""}),
        ("condition", {**_valid_rule(), "rule_type": "threshold", "condition": "bad"}),
        ("non-empty field", {**_valid_rule(), "field": ""}),
        ("pattern", {**_valid_rule(), "pattern": 123}),
        ("condition", {**_valid_rule(), "condition": "bad"}),
        ("field", {**_valid_rule(), "field": 123}),
        ("tags", {**_valid_rule(), "tags": []}),
        ("sample_references", {**_valid_rule(), "sample_references": [""]}),
    ]

    for message, raw_rule in cases:
        with pytest.raises(RuleValidationError, match=message):
            validate_rule(raw_rule)


def test_suppression_loader_rejects_missing_and_invalid_files() -> None:
    cases = [
        (ROOT / "tests/fixtures/missing_suppressions.json", "Could not read"),
        (ROOT / "tests/fixtures/invalid_json_suppressions.json", "Invalid JSON"),
        (ROOT / "tests/fixtures/no_suppressions_key.json", "suppressions"),
    ]

    for path, message in cases:
        with pytest.raises(SuppressionValidationError, match=message):
            load_suppressions(path)


def test_suppression_loader_rejects_invalid_item_shapes() -> None:
    with pytest.raises(SuppressionValidationError, match="Each suppression"):
        load_suppressions(ROOT / "tests/fixtures/non_object_suppressions.json")
    with pytest.raises(SuppressionValidationError, match="source_path_contains"):
        load_suppressions(ROOT / "tests/fixtures/invalid_optional_suppressions.json")


def test_suppression_conditions_must_all_match() -> None:
    alert = Alert(
        rule_id="CMD-001",
        rule_name="Command",
        severity="medium",
        source_path="samples/logs/false_positive/process_false_positive.csv",
        source_type="log",
        matched_field="command_line",
        matched_value="SYNTHETIC_SUSPICIOUS_COMMAND_MARKER",
        message="matched",
        tags=("synthetic",),
    )
    suppressions = [
        Suppression(
            id="SUP-NO-SOURCE",
            rule_id="CMD-001",
            source_path_contains="does-not-match",
            reason="source mismatch",
        ),
        Suppression(
            id="SUP-NO-VALUE",
            rule_id="CMD-001",
            matched_value_contains="different-marker",
            reason="value mismatch",
        ),
    ]

    assert apply_suppressions([alert], suppressions)[0].suppressed is False


def test_markdown_report_hides_suppressed_details_by_default() -> None:
    alert = Alert(
        rule_id="AUTH-001",
        rule_name="Auth",
        severity="high",
        source_path="samples/logs/false_positive/auth_false_positive.jsonl",
        source_type="log",
        matched_field="event_type",
        matched_value="failed_login",
        message="matched",
        tags=("auth",),
        suppressed=True,
        metadata={"suppression_reason": "hidden reason"},
    )
    report = build_report([alert], _rules(), ["sample.jsonl"])

    markdown = render_markdown_report(report)

    assert "Suppressed alert details are hidden" in markdown
    assert "hidden reason" not in markdown


def test_write_report_creates_parent_directories() -> None:
    output_path = ROOT / "reports/examples/nested/test_write_report.md"
    try:
        write_report(output_path, "synthetic report")
        assert output_path.read_text(encoding="utf-8") == "synthetic report"
    finally:
        output_path.unlink(missing_ok=True)
        output_path.parent.rmdir()


def _rules() -> list[Rule]:
    from yara_log_lab.rule_loader import load_rules_from_directory

    return load_rules_from_directory(ROOT / "rules/fallback")


def _rules_by_id() -> dict[str, Rule]:
    return {rule.id: rule for rule in _rules()}


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
        "false_positive_notes": "Synthetic false-positive note.",
        "sample_references": ["samples/logs/suspicious/auth_suspicious.jsonl"],
        "enabled": True,
    }
