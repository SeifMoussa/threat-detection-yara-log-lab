"""Tests for suppression handling."""

from pathlib import Path

import pytest

from yara_log_lab.engine import scan_path
from yara_log_lab.rule_loader import load_rules_from_directory
from yara_log_lab.suppressions import (
    SuppressionValidationError,
    apply_suppressions,
    load_suppressions,
)

ROOT = Path(__file__).resolve().parents[1]


def test_false_positive_auth_alert_suppressed() -> None:
    rules = load_rules_from_directory(ROOT / "rules/fallback")
    alerts = scan_path(ROOT / "samples/logs/false_positive/auth_false_positive.jsonl", rules)

    assert [alert.rule_id for alert in alerts] == ["AUTH-001"]

    suppressions = load_suppressions(ROOT / "suppressions/example_suppressions.json")
    suppressed_alerts = apply_suppressions(alerts, suppressions)

    assert len(suppressed_alerts) == 1
    assert suppressed_alerts[0].suppressed is True
    assert suppressed_alerts[0].metadata["suppression_id"] == "SUP-001"
    assert "training-lab" in suppressed_alerts[0].metadata["suppression_reason"]


def test_false_positive_process_alerts_suppressed_selectively() -> None:
    rules = load_rules_from_directory(ROOT / "rules/fallback")
    alerts = scan_path(ROOT / "samples/logs/false_positive/process_false_positive.csv", rules)
    suppressions = load_suppressions(ROOT / "suppressions/example_suppressions.json")

    suppressed_alerts = apply_suppressions(alerts, suppressions)

    suppressed_by_rule = {alert.rule_id: alert.suppressed for alert in suppressed_alerts}
    assert suppressed_by_rule["CMD-001"] is True
    assert suppressed_by_rule["IND-001"] is False


def test_invalid_suppression_file_fails_clearly() -> None:
    with pytest.raises(SuppressionValidationError, match="required"):
        load_suppressions(ROOT / "tests/fixtures/invalid_suppressions.json")
