# Testing Guide

## Install

```bash
python -m pip install -e ".[dev]"
```

## Core Checks

Run the test suite:

```bash
python -m pytest
```

Run linting:

```bash
python -m ruff check .
```

Run formatting check:

```bash
python -m ruff format --check .
```

Run documentation checks:

```bash
python scripts/check-docs.py
```

## Rule Validation

```bash
python -m yara_log_lab validate-rules --rules rules/fallback
```

## CLI Scan Examples

```bash
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --format json
```

```bash
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/suspicious/process_suspicious.csv --format text
```

```bash
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/false_positive/auth_false_positive.jsonl --suppressions suppressions/example_suppressions.json --format json --include-suppressed
```

## Report Examples

```bash
python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/auth_suspicious_report.md
```

```bash
python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/auth_suspicious_report.json --format json
```

## Current Test Coverage

At the end of Phase 5, the suite had 53 tests. Phase 6 adds documentation consistency tests.

Coverage areas:

- scaffold/import checks
- JSONL and CSV log loaders
- fallback rule loader
- sample safety validation
- detection engine matching
- CLI commands
- suppressions
- rule quality
- Markdown and JSON reporting
- documentation consistency

## Not Covered Yet

- GitHub Actions CI has not run on GitHub yet.
- CodeQL has not run on GitHub yet.
- optional YARA adapter
- production telemetry collection
- strict time-window threshold logic

## CI Workflows

Phase 7 adds local workflow files for:

- `tests`: ruff, format check, pytest with coverage
- `docs`: `python scripts/check-docs.py`
- `cli-smoke`: help, rule validation, rule listing, scan, and report generation

These workflow files are configured but not yet verified on GitHub.
