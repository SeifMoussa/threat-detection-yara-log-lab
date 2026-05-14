"""Basic workflow configuration checks for Phase 7."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ci_workflow_has_required_jobs_and_commands() -> None:
    ci_text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for job_name in ("tests:", "docs:", "cli-smoke:"):
        assert job_name in ci_text
    for command in (
        "python -m ruff check .",
        "python -m ruff format --check .",
        "python -m pytest --cov=yara_log_lab",
        "python scripts/check-docs.py",
        "python -m yara_log_lab validate-rules --rules rules/fallback",
        "python -m yara_log_lab report --rules rules/fallback",
    ):
        assert command in ci_text
    assert 'python-version: "3.12"' in ci_text
    assert "yara" not in ci_text.lower().replace("yara_log_lab", "")


def test_codeql_workflow_analyzes_python() -> None:
    codeql_text = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")

    assert "languages: python" in codeql_text
    assert "security-and-quality" in codeql_text
    assert "workflow_dispatch:" in codeql_text
    assert "cron:" in codeql_text


def test_dependabot_is_weekly_for_pip_and_actions() -> None:
    dependabot_text = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")

    assert "package-ecosystem: pip" in dependabot_text
    assert "package-ecosystem: github-actions" in dependabot_text
    assert dependabot_text.count("interval: weekly") == 2
    assert "interval: daily" not in dependabot_text
