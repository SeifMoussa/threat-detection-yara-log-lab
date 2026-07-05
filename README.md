# Threat Detection with YARA-Style Rules + Log Analysis Lab

[![CI](https://github.com/SeifMoussa/threat-detection-yara-log-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/SeifMoussa/threat-detection-yara-log-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SeifMoussa/threat-detection-yara-log-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/SeifMoussa/threat-detection-yara-log-lab/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Defensive-only local lab. This project analyzes harmless synthetic samples that live in this repository. It does not analyze malware, collect real logs, handle real credentials, scan third-party systems, or provide production SOC, EDR, or SIEM capability.

## Summary

This project is a blue-team portfolio lab for detection engineering practice. It uses a safe Python fallback rule engine with YARA-style ideas: rule metadata, string and regex matching, threshold logic, alert triage fields, false-positive suppressions, and generated reports.

Real YARA support is intentionally not required. A YARA adapter may be added later as an optional integration, but the current project is designed to run on Windows and CI-friendly environments without a YARA dependency.

## Why This Lab Is Different From My Other Security Labs

This project is about writing, validating, and testing detection rules against known fixtures. The cloud/IaC lab reviews configuration, the host lab compares endpoint state and host events, the packet lab summarizes network conversations, and the alert-triage lab organizes findings after detection. Here, JSON fallback rules apply `contains`, `regex`, `field_equals`, and grouped `threshold` logic to synthetic files and JSONL/CSV logs. Rule metadata, sample references, false-positive notes, explicit suppressions, and report output make the detection decision reviewable instead of hiding it behind a score.

## Target Job Relevance

The lab is relevant to:

- SOC Analyst
- Blue Team Analyst
- Detection Engineer
- Threat Hunter

## What This Demonstrates

- Designing detection rules with metadata and severity
- Loading JSONL and CSV log samples
- Scanning local text samples
- Producing structured alerts
- Validating false positives
- Applying explicit suppressions
- Generating Markdown and JSON reports
- Testing detection behavior and sample safety
- Keeping a security project safe for public review

## Features

- Portable Python fallback detection engine
- Rule types: `contains`, `regex`, `field_equals`, `threshold`
- JSON fallback rule format
- JSONL, CSV, TXT, and LOG input support
- Structured alert model
- Suppression support for known false positives
- CLI commands for scanning, listing rules, validating rules, and generating reports
- Markdown and JSON report output
- Synthetic sample safety tests
- Rule quality tests

## Tech Stack

- Python 3.12
- argparse CLI
- pytest
- ruff
- JSON fallback rules
- JSONL/CSV/text synthetic samples
- Markdown and JSON reports

## Safety Statement

All samples are synthetic and harmless. Suspicious-looking strings are fake markers created only to test detection behavior. Sample data uses reserved domains such as `.test` and documentation IP ranges only.

Prohibited content includes malware, working attack code, real credentials, real production logs, real stolen data, real indicators, and third-party scanning.

## Rule Format Summary

Fallback rules are JSON files under `rules/fallback/`. Each rule includes:

- `id`
- `name`
- `description`
- `severity`
- `tags`
- `rule_type`
- `target`
- `pattern` or `condition`
- `false_positive_notes`
- `sample_references`
- `enabled`

See [docs/rule-writing.md](docs/rule-writing.md).

## Install

```bash
python -m pip install -e ".[dev]"
```

## CLI Usage

Validate rules:

```bash
python -m yara_log_lab validate-rules --rules rules/fallback
```

List rules:

```bash
python -m yara_log_lab list-rules --rules rules/fallback
```

Scan and print JSON:

```bash
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --format json
```

Scan and print text:

```bash
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/suspicious/process_suspicious.csv --format text
```

Scan with suppressions:

```bash
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/false_positive/auth_false_positive.jsonl --suppressions suppressions/example_suppressions.json --format json --include-suppressed
```

Generate a Markdown report:

```bash
python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/auth_suspicious_report.md
```

Generate a JSON report:

```bash
python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/auth_suspicious_report.json --format json
```

## Example Reports

Generated reports from synthetic samples:

- [auth_suspicious_report.md](reports/examples/auth_suspicious_report.md)
- [auth_false_positive_suppressed_report.md](reports/examples/auth_false_positive_suppressed_report.md)
- [auth_suspicious_report.json](reports/examples/auth_suspicious_report.json)
- [sample_summary.json](reports/examples/sample_summary.json)

These files are real generated outputs from the local synthetic samples, not mock screenshots.

## Test Commands

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
```

## Current Verification Status

Current local release-readiness status:

- `pytest`: 88 passed
- coverage: 96.07%, above the configured 90% threshold
- `ruff check`: passed
- `ruff format --check`: passed
- `scripts/check-docs.py`: passed
- `validate-rules`: passed
- CLI scan commands: passed
- CLI report commands: passed
- GitHub Actions and CodeQL: configured, pending first GitHub run

GitHub Actions CI and CodeQL workflow files are configured in the repository but not yet verified on GitHub because this project has not been published in this workflow.

## Project Structure

```text
src/yara_log_lab/          Python package
rules/fallback/            JSON fallback rules
rules/yara/                Placeholder for optional later YARA work
samples/logs/              Synthetic JSONL and CSV logs
samples/files/             Synthetic text samples
suppressions/              JSON suppression examples
reports/examples/          Generated example reports
tests/                     pytest test suite
docs/                      Project documentation
.github/workflows/         CI and CodeQL workflow definitions
```

## Known Limitations

- The current engine implements YARA-style ideas in portable Python and JSON; it does not execute native YARA rules.
- All files and logs are synthetic fixtures. The repository contains no malware collection, production logs, credentials, or live indicators.
- Threshold matching is intentionally simple and operates on the records in one local scan, not a distributed event stream.
- Directory scanning is non-recursive by design.
- There is no live SOC pipeline, enterprise SIEM/EDR integration, external scanning, or automated response.
- Reports are local lab artifacts, not production detection assurance.
- CI and CodeQL are configured but not yet verified on GitHub.

## What I Would Improve Next

I would add an optional native YARA adapter behind the existing rule interface and test it against harmless generated byte fixtures. For log rules, I would add explicit time-window ordering, schema versioning, and per-rule test cases that pair a positive fixture with a near-miss and a suppressed case. A SIEM export adapter could emit the existing alert schema, but collection and response would remain outside this lab.

## How to Verify It Works

Install the development extras, run the quality gates, validate and list the fallback rules, then scan both a threshold-based authentication sample and a file-content fixture:

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m pytest
python -m pytest --cov=yara_log_lab --cov-report=term-missing --cov-fail-under=90
python scripts/check-docs.py
python -m yara_log_lab validate-rules --rules rules/fallback
python -m yara_log_lab list-rules --rules rules/fallback
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --format json
python -m yara_log_lab scan --rules rules/fallback --input samples/files/suspicious/fake_indicator_note.txt --format text
```

These commands verify deterministic behavior against the repository's synthetic fixtures. They do not validate a live SOC pipeline, a malware corpus, or native YARA execution.

## License

MIT License. See [LICENSE](LICENSE).
