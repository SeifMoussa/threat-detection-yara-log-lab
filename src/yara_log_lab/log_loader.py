"""Safe JSONL and CSV log loaders for synthetic local samples."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


class LogLoadError(ValueError):
    """Raised when a log sample cannot be loaded cleanly."""


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Load a JSONL log file into normalized dictionaries."""
    log_path = Path(path)
    records: list[dict[str, Any]] = []

    try:
        lines = log_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LogLoadError(f"Could not read JSONL log file {log_path}: {exc}") from exc

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LogLoadError(f"Invalid JSON on line {line_number} in {log_path}: {exc}") from exc
        if not isinstance(record, dict):
            raise LogLoadError(f"JSONL line {line_number} in {log_path} must be an object")
        records.append(_with_source_metadata(record, log_path, line_number, None))

    return records


def load_csv(path: str | Path) -> list[dict[str, Any]]:
    """Load a CSV log file into normalized dictionaries."""
    log_path = Path(path)
    try:
        with log_path.open("r", encoding="utf-8", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            if not reader.fieldnames:
                raise LogLoadError(f"CSV log file has no header: {log_path}")
            return [
                _with_source_metadata(dict(row), log_path, None, row_number)
                for row_number, row in enumerate(reader, start=2)
            ]
    except OSError as exc:
        raise LogLoadError(f"Could not read CSV log file {log_path}: {exc}") from exc


def load_log_file(path: str | Path) -> list[dict[str, Any]]:
    """Load a supported log file based on extension."""
    log_path = Path(path)
    suffix = log_path.suffix.lower()
    if suffix == ".jsonl":
        return load_jsonl(log_path)
    if suffix == ".csv":
        return load_csv(log_path)
    raise LogLoadError(f"Unsupported log file extension for {log_path}")


def _with_source_metadata(
    record: dict[str, Any],
    source_path: Path,
    source_line: int | None,
    source_row: int | None,
) -> dict[str, Any]:
    normalized = dict(record)
    normalized["_source_path"] = str(source_path)
    if source_line is not None:
        normalized["_source_line"] = source_line
    if source_row is not None:
        normalized["_source_row"] = source_row
    return normalized
