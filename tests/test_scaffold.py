"""Phase 1 scaffold tests."""

from yara_log_lab import __version__
from yara_log_lab.cli import main


def test_package_version_exists() -> None:
    assert __version__ == "0.1.0"


def test_cli_placeholder_runs() -> None:
    assert main([]) == 0
