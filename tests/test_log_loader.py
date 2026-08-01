"""Tests for synthetic log loading."""

from pathlib import Path

import pytest

from yara_log_lab.log_loader import LogLoadError, load_csv, load_jsonl, load_log_file

ROOT = Path(__file__).resolve().parents[1]


def test_load_jsonl_auth_sample() -> None:
    records = load_jsonl(ROOT / "samples/logs/benign/auth_benign.jsonl")

    assert len(records) == 3
    assert records[0]["event_type"] == "login_success"
    assert records[0]["synthetic"] is True
    assert records[0]["_source_line"] == 1
    assert records[0]["_source_path"].endswith("auth_benign.jsonl")


def test_load_csv_process_sample() -> None:
    records = load_csv(ROOT / "samples/logs/suspicious/process_suspicious.csv")

    assert len(records) == 2
    assert records[0]["process_name"] == "lab-simulated-runner.exe"
    assert records[0]["synthetic"] == "true"
    assert records[0]["_source_row"] == 2
    assert records[0]["_source_path"].endswith("process_suspicious.csv")


def test_load_log_file_rejects_unknown_extension() -> None:
    with pytest.raises(LogLoadError, match="Unsupported log file extension"):
        load_log_file(ROOT / "tests/fixtures/unsupported_log.txt")


def test_load_jsonl_rejects_invalid_json() -> None:
    with pytest.raises(LogLoadError, match="Invalid JSON"):
        load_jsonl(ROOT / "tests/fixtures/invalid_log.jsonl")
