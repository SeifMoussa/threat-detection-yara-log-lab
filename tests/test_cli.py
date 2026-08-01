"""Tests for CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

from yara_log_lab.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_cli_validate_rules_succeeds(capsys) -> None:
    exit_code = main(["validate-rules", "--rules", str(ROOT / "rules/fallback")])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Validated 4 fallback rules" in output


def test_cli_list_rules_succeeds(capsys) -> None:
    exit_code = main(["list-rules", "--rules", str(ROOT / "rules/fallback")])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "AUTH-001" in output
    assert "CMD-001" in output


def test_cli_scan_json_output_is_valid_json(capsys) -> None:
    exit_code = main(
        [
            "scan",
            "--rules",
            str(ROOT / "rules/fallback"),
            "--input",
            str(ROOT / "samples/logs/suspicious/auth_suspicious.jsonl"),
            "--format",
            "json",
        ]
    )

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert exit_code == 0
    assert payload[0]["rule_id"] == "AUTH-001"


def test_cli_scan_text_output_is_readable(capsys) -> None:
    exit_code = main(
        [
            "scan",
            "--rules",
            str(ROOT / "rules/fallback"),
            "--input",
            str(ROOT / "samples/logs/suspicious/process_suspicious.csv"),
            "--format",
            "text",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "MEDIUM CMD-001" in output
    assert "source=" in output


def test_cli_scan_combines_fallback_and_yara_alerts_by_default(capsys) -> None:
    exit_code = main(
        [
            "scan",
            "--rules",
            str(ROOT / "rules/fallback"),
            "--yara-rules",
            str(ROOT / "rules/yara"),
            "--input",
            str(ROOT / "samples/files/suspicious/fake_indicator_note.txt"),
            "--format",
            "json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert {alert["rule_id"] for alert in payload} == {"FILE-001", "YARA-001", "YARA-002"}


def test_cli_scan_reports_missing_yara_rules_directory_clearly(capsys) -> None:
    exit_code = main(
        [
            "scan",
            "--rules",
            str(ROOT / "rules/fallback"),
            "--yara-rules",
            str(ROOT / "rules/does-not-exist"),
            "--input",
            str(ROOT / "samples/files/benign/readme_note.txt"),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "YARA rule directory does not exist" in captured.err


def test_cli_scan_invalid_input_exits_nonzero(capsys) -> None:
    exit_code = main(
        [
            "scan",
            "--rules",
            str(ROOT / "rules/fallback"),
            "--input",
            str(ROOT / "tests/fixtures/unsupported_input.bin"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Unsupported input extension" in captured.err


def test_cli_scan_hides_suppressed_alerts_by_default(capsys) -> None:
    exit_code = main(
        [
            "scan",
            "--rules",
            str(ROOT / "rules/fallback"),
            "--input",
            str(ROOT / "samples/logs/false_positive/auth_false_positive.jsonl"),
            "--suppressions",
            str(ROOT / "suppressions/example_suppressions.json"),
            "--format",
            "json",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert json.loads(output) == []


def test_cli_scan_can_include_suppressed_alerts(capsys) -> None:
    exit_code = main(
        [
            "scan",
            "--rules",
            str(ROOT / "rules/fallback"),
            "--input",
            str(ROOT / "samples/logs/false_positive/auth_false_positive.jsonl"),
            "--suppressions",
            str(ROOT / "suppressions/example_suppressions.json"),
            "--format",
            "json",
            "--include-suppressed",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload[0]["suppressed"] is True
    assert payload[0]["metadata"]["suppression_id"] == "SUP-001"


def test_cli_report_writes_markdown_file(capsys) -> None:
    output_path = ROOT / "reports/examples/test_cli_auth_report.md"
    output_path.unlink(missing_ok=True)

    try:
        exit_code = main(
            [
                "report",
                "--rules",
                str(ROOT / "rules/fallback"),
                "--input",
                str(ROOT / "samples/logs/suspicious/auth_suspicious.jsonl"),
                "--output",
                str(output_path),
            ]
        )

        output = capsys.readouterr().out
        content = output_path.read_text(encoding="utf-8")
        assert exit_code == 0
        assert "Wrote markdown report" in output
        assert "## Summary" in content
        assert "AUTH-001" in content
    finally:
        output_path.unlink(missing_ok=True)


def test_cli_report_writes_json_file(capsys) -> None:
    output_path = ROOT / "reports/examples/test_cli_auth_report.json"
    output_path.unlink(missing_ok=True)

    try:
        exit_code = main(
            [
                "report",
                "--rules",
                str(ROOT / "rules/fallback"),
                "--input",
                str(ROOT / "samples/logs/suspicious/auth_suspicious.jsonl"),
                "--output",
                str(output_path),
                "--format",
                "json",
            ]
        )

        output = capsys.readouterr().out
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert exit_code == 0
        assert "Wrote json report" in output
        assert payload["summary"]["total_alerts"] == 1
        assert payload["alerts"][0]["rule_id"] == "AUTH-001"
    finally:
        output_path.unlink(missing_ok=True)
