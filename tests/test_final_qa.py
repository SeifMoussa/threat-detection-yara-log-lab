"""Final QA checks for required structure and repository hygiene."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_PATHS = [
    "README.md",
    "LICENSE",
    ".gitignore",
    ".editorconfig",
    ".env.example",
    "pyproject.toml",
    "Makefile",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "TESTING_REPORT.md",
    "PROJECT_COMPLETION_CHECKLIST.md",
    "src/yara_log_lab",
    "rules/fallback",
    "rules/yara",
    "samples/logs",
    "samples/files",
    "suppressions",
    "reports/examples",
    "docs",
    "tests",
    "scripts",
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    ".github/dependabot.yml",
]


def test_required_repository_paths_exist() -> None:
    for relative_path in REQUIRED_PATHS:
        assert (ROOT / relative_path).exists(), f"Missing required path: {relative_path}"


def test_no_real_environment_file_committed() -> None:
    assert not (ROOT / ".env").exists()


def test_gitignore_covers_common_local_artifacts() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (
        ".env",
        ".venv/",
        ".pytest_cache/",
        ".ruff_cache/",
        "__pycache__/",
        ".coverage",
        "coverage.xml",
    ):
        assert pattern in gitignore


def test_example_reports_mention_synthetic_local_data() -> None:
    for report_path in (ROOT / "reports/examples").glob("*report.md"):
        text = report_path.read_text(encoding="utf-8").lower()
        assert "synthetic" in text
        assert "local" in text
