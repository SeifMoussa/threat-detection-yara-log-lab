"""Tests for real YARA rule execution against local sample fixtures."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from yara_log_lab.engine import scan_path
from yara_log_lab.yara_engine import YARA_AVAILABLE, YaraRuleError, load_yara_rules

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python is a listed dependency")


def test_yara_rules_compile_from_the_project_rule_directory() -> None:
    rule_set = load_yara_rules(ROOT / "rules/yara")

    assert rule_set is not None
    assert rule_set.rule_count >= 1


def test_yara_rules_fire_on_suspicious_sample() -> None:
    rule_set = load_yara_rules(ROOT / "rules/yara")

    alerts = scan_path(
        ROOT / "samples/files/suspicious/fake_indicator_note.txt", rules=[], yara_rule_set=rule_set
    )

    rule_ids = {alert.rule_id for alert in alerts}
    assert rule_ids == {"YARA-001", "YARA-002"}
    assert all(alert.metadata.get("engine") == "yara" for alert in alerts)


def test_yara_rules_stay_silent_on_benign_sample() -> None:
    rule_set = load_yara_rules(ROOT / "rules/yara")

    alerts = scan_path(
        ROOT / "samples/files/benign/readme_note.txt", rules=[], yara_rule_set=rule_set
    )

    assert alerts == []


def test_yara_rule_metadata_is_labeled_synthetic() -> None:
    rule_set = load_yara_rules(ROOT / "rules/yara")

    alerts = scan_path(
        ROOT / "samples/files/suspicious/fake_indicator_note.txt", rules=[], yara_rule_set=rule_set
    )

    for alert in alerts:
        assert "synthetic" in alert.metadata["description"].lower()
        assert "not a real threat signature" in alert.metadata["description"].lower()


def test_load_yara_rules_returns_none_for_empty_directory() -> None:
    with tempfile.TemporaryDirectory() as empty_dir:
        assert load_yara_rules(empty_dir) is None


def test_load_yara_rules_fails_clearly_for_missing_directory() -> None:
    with pytest.raises(YaraRuleError, match="does not exist"):
        load_yara_rules(ROOT / "rules/does-not-exist")


def test_load_yara_rules_fails_clearly_for_invalid_rule_syntax() -> None:
    with tempfile.TemporaryDirectory() as rule_dir:
        bad_rule = Path(rule_dir) / "broken.yar"
        bad_rule.write_text("rule Broken { condition: this is not valid }", encoding="utf-8")

        with pytest.raises(YaraRuleError, match="Could not compile"):
            load_yara_rules(rule_dir)
