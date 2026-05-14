"""Documentation consistency checks for Phase 6."""

from __future__ import annotations

import re
from pathlib import Path

from yara_log_lab.cli import build_parser

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCS = [
    ROOT / "docs/safety.md",
    ROOT / "docs/detection-methodology.md",
    ROOT / "docs/rule-writing.md",
    ROOT / "docs/false-positives.md",
    ROOT / "docs/testing-guide.md",
    ROOT / "docs/release-checklist.md",
]
EXAMPLE_REPORTS = [
    ROOT / "reports/examples/auth_suspicious_report.md",
    ROOT / "reports/examples/auth_false_positive_suppressed_report.md",
    ROOT / "reports/examples/auth_suspicious_report.json",
    ROOT / "reports/examples/sample_summary.json",
]
IMPLEMENTED_COMMANDS = {"scan", "validate-rules", "list-rules", "report"}


def test_required_docs_exist() -> None:
    for doc_path in REQUIRED_DOCS:
        assert doc_path.is_file(), f"Missing required doc: {doc_path}"


def test_readme_local_links_exist() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", readme):
        if link.startswith(("http://", "https://", "#")):
            continue
        assert (ROOT / link).exists(), f"Broken README link: {link}"


def test_docs_do_not_claim_ci_or_codeql_exists_yet() -> None:
    text = _documentation_text().lower()

    forbidden_claims = [
        "github actions passed",
        "ci passed",
        "codeql passed",
    ]
    for claim in forbidden_claims:
        assert claim not in text
    assert "not yet verified on github" in text


def test_docs_do_not_claim_production_security_platform_capability() -> None:
    text = _documentation_text().lower()

    forbidden_claims = [
        "production soc capability",
        "production edr capability",
        "production siem capability",
        "production-grade soc",
        "production-grade edr",
        "production-grade siem",
    ]
    for claim in forbidden_claims:
        assert claim not in text


def test_documented_cli_commands_are_implemented() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    documented_commands = set(re.findall(r"python -m yara_log_lab ([a-z-]+)", readme))

    assert documented_commands
    assert documented_commands <= IMPLEMENTED_COMMANDS

    parser_help = build_parser().format_help()
    for command in documented_commands:
        assert command in parser_help


def test_example_report_files_exist() -> None:
    for report_path in EXAMPLE_REPORTS:
        assert report_path.is_file(), f"Missing example report: {report_path}"


def test_docs_avoid_unsafe_claims_and_content() -> None:
    text = _documentation_text().lower()
    forbidden_phrases = [
        "real credentials are included",
        "real production logs are included",
        "third-party scanning is supported",
        "working attack code is included",
    ]
    for phrase in forbidden_phrases:
        assert phrase not in text


def _documentation_text() -> str:
    paths = [ROOT / "README.md", *REQUIRED_DOCS]
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)
