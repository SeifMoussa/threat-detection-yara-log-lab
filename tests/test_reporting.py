"""Tests for report generation."""

from __future__ import annotations

import json
from pathlib import Path

from yara_log_lab.engine import scan_path
from yara_log_lab.reporting import build_report, render_json_report, render_markdown_report
from yara_log_lab.rule_loader import load_rules_from_directory
from yara_log_lab.suppressions import apply_suppressions, load_suppressions

ROOT = Path(__file__).resolve().parents[1]


def test_markdown_report_generation_includes_required_sections() -> None:
    report = _suspicious_auth_report()
    markdown = render_markdown_report(report)

    assert "# YARA-Style Log Lab Detection Report" in markdown
    assert "Safety disclaimer" in markdown
    assert "## Rule Summary" in markdown
    assert "## Alert Details" in markdown
    assert "AUTH-001" in markdown


def test_json_report_generation_includes_summary_and_alerts() -> None:
    report = _suspicious_auth_report()
    payload = json.loads(render_json_report(report))

    assert payload["summary"]["total_alerts"] == 1
    assert payload["summary"]["unsuppressed_count"] == 1
    assert payload["severity_counts"]["high"] == 1
    assert payload["alerts"][0]["rule_id"] == "AUTH-001"
    assert payload["rules_used"]


def test_report_counts_suppressed_and_unsuppressed_alerts() -> None:
    rules = _rules()
    alerts = scan_path(ROOT / "samples/logs/false_positive/auth_false_positive.jsonl", rules)
    suppressions = load_suppressions(ROOT / "suppressions/example_suppressions.json")
    suppressed_alerts = apply_suppressions(alerts, suppressions)
    report = build_report(
        alerts=suppressed_alerts,
        rules=rules,
        input_paths=["samples/logs/false_positive/auth_false_positive.jsonl"],
    )

    assert report.suppressed_count == 1
    assert report.unsuppressed_count == 0
    assert report.severity_counts["high"] == 1
    assert json.loads(render_json_report(report))["alerts"] == []


def test_suppressed_report_includes_reason_when_requested() -> None:
    rules = _rules()
    alerts = scan_path(ROOT / "samples/logs/false_positive/auth_false_positive.jsonl", rules)
    suppressions = load_suppressions(ROOT / "suppressions/example_suppressions.json")
    report = build_report(
        alerts=apply_suppressions(alerts, suppressions),
        rules=rules,
        input_paths=["samples/logs/false_positive/auth_false_positive.jsonl"],
        include_suppressed=True,
    )

    markdown = render_markdown_report(report)
    payload = json.loads(render_json_report(report))

    assert "Expected synthetic training-lab failed-login false positive" in markdown
    assert payload["alerts"][0]["suppressed"] is True
    assert payload["alerts"][0]["metadata"]["suppression_id"] == "SUP-001"


def test_report_uses_short_safe_excerpts() -> None:
    rules = _rules()
    alerts = scan_path(ROOT / "samples/files/suspicious/fake_indicator_note.txt", rules)
    report = build_report(
        alerts=alerts,
        rules=rules,
        input_paths=["samples/files/suspicious/fake_indicator_note.txt"],
    )
    payload = json.loads(render_json_report(report))

    assert len(payload["alerts"][0]["matched_value"]) <= 120


def _suspicious_auth_report():
    rules = _rules()
    alerts = scan_path(ROOT / "samples/logs/suspicious/auth_suspicious.jsonl", rules)
    return build_report(
        alerts=alerts,
        rules=rules,
        input_paths=["samples/logs/suspicious/auth_suspicious.jsonl"],
    )


def _rules():
    return load_rules_from_directory(ROOT / "rules/fallback")
