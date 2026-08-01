# Changelog

All notable changes to this project will be documented here.

## [Unreleased]

### Added

- Real YARA rule execution via `yara-python`, wired into file-content scanning alongside the existing JSON fallback rules.
- Two YARA rules under `rules/yara/` covering the synthetic file markers already used by the suspicious sample fixtures.
- `--yara-rules` CLI option on `scan` and `report`, defaulting to `rules/yara`.
- GitHub Actions CI workflow, CodeQL scanning, and Dependabot configuration.
- Documentation consistency and repository hygiene test suites.
- Markdown and JSON report generation, with example reports checked into `reports/examples/`.
- False-positive suppression workflow (`suppressions/`, `--suppressions`, `--include-suppressed`).
- Rule quality validation tests and strengthened sample/documentation safety checks.
- Fallback detection engine supporting `contains`, `regex`, `field_equals`, and `threshold` rule types.
- CLI commands: `scan`, `validate-rules`, `list-rules`, `report`.
- Synthetic JSONL, CSV, and text sample data, plus the initial JSON fallback rule set.
- Rule schema validation helpers and JSONL/CSV log loaders.
- Initial repository scaffold.

### Changed

- Coverage gate raised to 90% after behavior-focused tests pushed coverage past 96%.
