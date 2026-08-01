# Testing Report

## Current Status

Local verification is complete, including real YARA rule execution. GitHub Actions and CodeQL remain configured but not yet verified on GitHub.

## Latest Local Checks

```bash
python -m pytest
python -m pytest --cov=yara_log_lab --cov-report=term-missing --cov-fail-under=90
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
python -m py_compile scripts/check-docs.py
python -m yara_log_lab --help
python -m yara_log_lab validate-rules --rules rules/fallback
python -m yara_log_lab list-rules --rules rules/fallback
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --format json
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/false_positive/auth_false_positive.jsonl --format json
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/false_positive/auth_false_positive.jsonl --suppressions suppressions/example_suppressions.json --format json --include-suppressed
python -m yara_log_lab scan --rules rules/fallback --yara-rules rules/yara --input samples/files/suspicious/fake_indicator_note.txt --format json
python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/auth_suspicious_report.md
python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/auth_suspicious_report.json --format json
python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/ci_auth_suspicious_report.md
```

Results: 97 tests pass locally, with 96.21% statement coverage against a 90% gate. Ruff lint, ruff format, and `scripts/check-docs.py` all pass cleanly, and every CLI command above runs end to end, including the YARA-backed scan and report paths.

## Notes

Ruff formatting has occasionally needed a pass after larger CLI or engine edits; running `python -m ruff format .` locally before committing has kept the check green.

Documentation checks live in `scripts/check-docs.py` so they can run identically in CI and locally, without a YAML parsing dependency the project doesn't otherwise need.

Final QA tests cover required repository paths, `.gitignore` hygiene, and generated report safety wording, so a missing file or an unsafe claim in a report fails the suite instead of slipping through review.

The coverage gate sits at 90%, comfortably below the actual measured coverage, to leave room for edge cases without becoming a rubber stamp.
