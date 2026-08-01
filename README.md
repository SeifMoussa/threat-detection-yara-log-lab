# Threat Detection with YARA-Style Rules + Log Analysis Lab

[![CI](https://github.com/SeifMoussa/threat-detection-yara-log-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/SeifMoussa/threat-detection-yara-log-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SeifMoussa/threat-detection-yara-log-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/SeifMoussa/threat-detection-yara-log-lab/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Defensive-only local lab. This project analyzes harmless synthetic samples that live in this repository. It does not analyze malware, collect real logs, handle real credentials, scan third-party systems, or provide production SOC, EDR, or SIEM capability.

## Summary

This is a blue-team portfolio lab built around detection engineering practice: writing rules, running them against known-good and known-bad fixtures, and being honest about what fired and why. It combines two engines. A Python fallback engine applies JSON rules using YARA-style ideas (string/regex matching, threshold logic, alert triage fields), and a small set of real `.yar` rules run through `yara-python` against the same local text samples. False-positive suppressions and generated reports sit on top of both.

## Why This Lab Is Different From My Other Security Labs

This one is about writing, validating, and testing detection rules against known fixtures, rather than reviewing state or summarizing traffic. The cloud/IaC lab reviews configuration, the host lab compares endpoint state and host events, the packet lab summarizes network conversations, and the alert-triage lab organizes findings after detection. Here, both the JSON fallback rules (`contains`, `regex`, `field_equals`, grouped `threshold`) and the real YARA rules run against the same synthetic files and JSONL/CSV logs, and every alert carries rule metadata, sample references, false-positive notes, and (where suppressed) an explicit reason — so the detection decision is reviewable, not hidden behind a score.

## Target Job Relevance

The lab is relevant to:

- SOC Analyst
- Blue Team Analyst
- Detection Engineer
- Threat Hunter

## What This Demonstrates

- Designing detection rules with metadata and severity
- Writing and compiling real YARA rules, not just YARA-flavored JSON
- Loading JSONL and CSV log samples
- Scanning local text samples with both engines
- Producing structured alerts
- Validating false positives
- Applying explicit suppressions
- Generating Markdown and JSON reports
- Testing detection behavior and sample safety
- Keeping a security project safe for public review

## Features

- Portable Python fallback detection engine
- Real YARA rule execution via `yara-python`, wired into the same file-content scan path
- Rule types: `contains`, `regex`, `field_equals`, `threshold`
- JSON fallback rule format plus native `.yar` rule files under `rules/yara/`
- JSONL, CSV, TXT, and LOG input support
- Structured alert model shared by both engines
- Suppression support for known false positives
- CLI commands for scanning, listing rules, validating rules, and generating reports
- Markdown and JSON report output
- Synthetic sample safety tests
- Rule quality tests

## Tech Stack

- Python 3.12
- `yara-python`
- argparse CLI
- pytest
- ruff
- JSON fallback rules and native `.yar` rules
- JSONL/CSV/text synthetic samples
- Markdown and JSON reports

## Safety Statement

All samples are synthetic and harmless. Suspicious-looking strings are fake markers created only to test detection behavior. Sample data uses reserved domains such as `.test` and documentation IP ranges only. The `.yar` rules in this repo target those same fake markers — they're lab fixtures, not threat intel.

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

YARA rules are native `.yar` files under `rules/yara/`, compiled and matched with `yara-python`. Each rule carries a `meta` block (`id`, `description`, `severity`, `false_positive_notes`) so alerts from both engines read the same way.

See [docs/rule-writing.md](docs/rule-writing.md).

## Install

```bash
python -m pip install -e ".[dev]"
```

`yara-python` ships prebuilt wheels for Windows, macOS, and Linux on supported Python versions, so this installs without a local build toolchain.

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

Scan a file with both the fallback rules and the real YARA rules (the `--yara-rules` flag defaults to `rules/yara`, so this is the normal path for file-content input):

```bash
python -m yara_log_lab scan --rules rules/fallback --yara-rules rules/yara --input samples/files/suspicious/fake_indicator_note.txt --format json
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

- `pytest`: passing (see [TESTING_REPORT.md](TESTING_REPORT.md) for the latest run)
- coverage: above the configured 90% threshold
- `ruff check`: passed
- `ruff format --check`: passed
- `scripts/check-docs.py`: passed
- `validate-rules`: passed
- CLI scan commands, including the YARA-backed file scan: passed
- CLI report commands: passed
- GitHub Actions and CodeQL: configured, pending first GitHub run

GitHub Actions CI and CodeQL workflow files are configured in the repository but not yet verified on GitHub because this project has not been published in this workflow.

## Project Structure

```text
src/yara_log_lab/          Python package
rules/fallback/            JSON fallback rules
rules/yara/                Real .yar rules, compiled and matched with yara-python
samples/logs/              Synthetic JSONL and CSV logs
samples/files/             Synthetic text samples
suppressions/              JSON suppression examples
reports/examples/          Generated example reports
tests/                     pytest test suite
docs/                      Project documentation
.github/workflows/         CI and CodeQL workflow definitions
```

## Known Limitations

- All files and logs are synthetic fixtures. The repository contains no malware collection, production logs, credentials, or live indicators.
- The YARA rule set is intentionally small — it proves the wiring end-to-end against the existing sample fixtures rather than covering broad threat categories.
- Threshold matching is intentionally simple and operates on the records in one local scan, not a distributed event stream.
- Directory scanning is non-recursive by design.
- There is no live SOC pipeline, enterprise SIEM/EDR integration, external scanning, or automated response.
- Reports are local lab artifacts, not production detection assurance.
- CI and CodeQL are configured but not yet verified on GitHub.

## What I Would Improve Next

I'd grow the YARA rule set to cover more of the existing log-side patterns (translating some of the fallback command/indicator rules into real `.yar` string and condition logic), and add a recursive directory-scan mode now that two engines run per file. For log rules, I'd add explicit time-window ordering, schema versioning, and per-rule test cases that pair a positive fixture with a near-miss and a suppressed case. A SIEM export adapter could emit the existing alert schema, but collection and response would stay outside this lab.

## How to Verify It Works

Install the development extras, run the quality gates, validate and list the fallback rules, then scan a threshold-based authentication sample, a JSON fallback file-content fixture, and the same fixture through the real YARA rules:

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
python -m yara_log_lab scan --rules rules/fallback --yara-rules rules/yara --input samples/files/suspicious/fake_indicator_note.txt --format json
```

These commands verify deterministic behavior against the repository's synthetic fixtures. They do not validate a live SOC pipeline or a real malware corpus.

## License

MIT License. See [LICENSE](LICENSE).
