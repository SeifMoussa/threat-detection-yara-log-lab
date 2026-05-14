"""Repository documentation consistency checks."""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

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
RESERVED_DOMAINS = {"example.com", "example.org", "example.net"}
DOC_ALLOWED_DOMAINS = {"github.com"}
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def main() -> int:
    checks = [
        check_required_docs,
        check_readme_links,
        check_example_reports,
        check_current_state_claims,
        check_cli_commands,
        check_safety_content,
        check_reports_are_synthetic,
    ]
    failures: list[str] = []
    for check in checks:
        try:
            check()
        except AssertionError as exc:
            failures.append(f"{check.__name__}: {exc}")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("Documentation checks passed.")
    return 0


def check_required_docs() -> None:
    for doc_path in REQUIRED_DOCS:
        assert doc_path.is_file(), f"missing required doc {doc_path.relative_to(ROOT)}"


def check_readme_links() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", readme):
        if link.startswith(("http://", "https://", "#")):
            continue
        assert (ROOT / link).exists(), f"broken README link {link}"


def check_example_reports() -> None:
    for report_path in EXAMPLE_REPORTS:
        assert report_path.is_file(), f"missing example report {report_path.relative_to(ROOT)}"


def check_current_state_claims() -> None:
    text = documentation_text().lower()
    forbidden_claims = [
        "github actions passed",
        "ci passed on github",
        "codeql passed on github",
        "production soc capability",
        "production edr capability",
        "production siem capability",
        "production-grade soc",
        "production-grade edr",
        "production-grade siem",
    ]
    for claim in forbidden_claims:
        assert claim not in text, f"unsupported current-state claim: {claim}"
    assert "not yet verified on github" in text


def check_cli_commands() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    documented_commands = set(re.findall(r"python -m yara_log_lab ([a-z-]+)", readme))
    assert documented_commands, "README does not document CLI commands"
    assert documented_commands <= IMPLEMENTED_COMMANDS, documented_commands - IMPLEMENTED_COMMANDS


def check_safety_content() -> None:
    for path in [ROOT / "README.md", *REQUIRED_DOCS, *sample_files()]:
        text = path.read_text(encoding="utf-8")
        lower_text = text.lower()
        forbidden_positive_claims = [
            "real credentials are included",
            "real production logs are included",
            "real indicators are included",
            "third-party scanning is supported",
            "offensive guidance is included",
            "working attack code is included",
        ]
        for claim in forbidden_positive_claims:
            assert claim not in lower_text, f"unsafe claim in {path.relative_to(ROOT)}"
        check_domains(path, text, allow_doc_domains=path.suffix == ".md")
        check_public_ips(path, text)
        check_secret_patterns(path, text)


def check_reports_are_synthetic() -> None:
    for report_path in EXAMPLE_REPORTS:
        text = report_path.read_text(encoding="utf-8")
        assert "synthetic" in text.lower(), f"report lacks synthetic marker {report_path.name}"
        if report_path.suffix == ".json":
            json.loads(text)


def check_domains(path: Path, text: str, allow_doc_domains: bool = False) -> None:
    for match in re.finditer(r"\b([A-Za-z0-9-]+\.(?:com|org|net|test))\b", text):
        domain = match.group(1).lower()
        if allow_doc_domains and domain in DOC_ALLOWED_DOMAINS:
            continue
        assert domain.endswith(".test") or domain in RESERVED_DOMAINS, (
            f"unreserved domain {domain} in {path.relative_to(ROOT)}"
        )


def check_public_ips(path: Path, text: str) -> None:
    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        ip_address = ipaddress.ip_address(match.group(0))
        assert any(ip_address in network for network in DOCUMENTATION_NETWORKS), (
            f"public IP {ip_address} in {path.relative_to(ROOT)}"
        )


def check_secret_patterns(path: Path, text: str) -> None:
    patterns = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(
            r"(?i)(password|passwd|secret|token|api_key)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{8,}"
        ),
    ]
    for pattern in patterns:
        assert not pattern.search(text), f"secret-like pattern in {path.relative_to(ROOT)}"


def documentation_text() -> str:
    paths = [ROOT / "README.md", *REQUIRED_DOCS]
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def sample_files() -> list[Path]:
    files: list[Path] = []
    for pattern in ("*.txt", "*.csv", "*.jsonl", "*.json"):
        files.extend((ROOT / "samples").rglob(pattern))
    return files


if __name__ == "__main__":
    raise SystemExit(main())
