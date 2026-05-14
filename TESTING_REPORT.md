# Testing Report

## Current Status

Phase 9 prepares release and publishing materials after final local QA.

## Latest Local Checks

Phase 9 local release-prep verification completed successfully. GitHub Actions and CodeQL remain configured but not yet verified on GitHub.

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
python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/auth_suspicious_report.md
python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/auth_suspicious_report.json --format json
python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/ci_auth_suspicious_report.md
```

Results:

- `python -m pytest`: 67 passed
- `python -m pytest --cov=yara_log_lab --cov-report=term-missing --cov-fail-under=90`: 88 passed, 96.07% coverage
- `python -m ruff check .`: all checks passed
- `python -m ruff format --check .`: 22 files already formatted
- `python scripts/check-docs.py`: documentation checks passed
- `python -m py_compile scripts/check-docs.py`: passed
- `python -m yara_log_lab --help`: displayed CLI help successfully
- `python -m yara_log_lab validate-rules --rules rules/fallback`: validated 4 fallback rules
- `python -m yara_log_lab list-rules --rules rules/fallback`: listed 4 fallback rules
- `python -m yara_log_lab scan --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --format json`: emitted a JSON alert array
- `python -m yara_log_lab scan --rules rules/fallback --input samples/logs/false_positive/auth_false_positive.jsonl --format json`: emitted an unsuppressed expected false-positive alert
- `python -m yara_log_lab scan --rules rules/fallback --input samples/logs/false_positive/auth_false_positive.jsonl --suppressions suppressions/example_suppressions.json --format json --include-suppressed`: emitted the expected false-positive alert with `suppressed=true`
- `python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/auth_suspicious_report.md`: wrote Markdown report
- `python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/auth_suspicious_report.json --format json`: wrote JSON report
- `python -m yara_log_lab report --rules rules/fallback --input samples/logs/suspicious/auth_suspicious.jsonl --output reports/examples/ci_auth_suspicious_report.md`: wrote local CI-smoke Markdown report
- Unsupported `.bin` input returned a concise nonzero error.
- Invalid rule fixture returned a concise nonzero validation error.

## Notes

During Phase 5, ruff required formatting for the updated CLI file. Running `python -m ruff format .` fixed it, and the final checks passed.

During Phase 7, reusable docs checks were moved into `scripts/check-docs.py` for local and CI use. Workflow YAML was validated with basic structure checks because PyYAML is not required by the project.

During Phase 8, final QA tests were added for required repository paths, `.gitignore` hygiene coverage, and generated report safety wording.

After the coverage review, meaningful behavior tests raised coverage to 96.07%, and the coverage gate was raised to 90%.

During Phase 9, release preparation materials were added in `RELEASE.md`, including publishing commands, v0.1.0 release notes draft, post-push checks, and portfolio copy.
