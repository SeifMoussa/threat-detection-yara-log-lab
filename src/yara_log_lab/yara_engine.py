"""Real YARA rule execution for local file-content scanning."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yara
except ImportError:  # pragma: no cover - yara-python is a listed dependency
    yara = None  # type: ignore[assignment]

from yara_log_lab.alerts import Alert, safe_excerpt

YARA_AVAILABLE = yara is not None


class YaraRuleError(ValueError):
    """Raised when local .yar rules cannot be loaded or compiled."""


@dataclass(frozen=True)
class YaraRuleSet:
    """Compiled local YARA rules ready to scan file content."""

    compiled: Any
    source_dir: Path
    rule_count: int


def load_yara_rules(rules_dir: str | Path) -> YaraRuleSet | None:
    """Compile local .yar rule files from a directory.

    Returns None when the directory has no .yar files, so callers can treat
    "no YARA rules configured" as a normal, silent case rather than an error.
    Raises YaraRuleError for a missing directory or a rule that fails to
    compile, so a misconfigured path fails loudly instead of scanning nothing.
    """
    if not YARA_AVAILABLE:
        raise YaraRuleError(
            "yara-python is not installed; install project dependencies with "
            "'python -m pip install -e \".[dev]\"' to enable YARA scanning"
        )

    rule_dir = Path(rules_dir)
    if not rule_dir.is_dir():
        raise YaraRuleError(f"YARA rule directory does not exist: {rule_dir}")

    yar_files = {path.stem: str(path) for path in sorted(rule_dir.glob("*.yar"))}
    if not yar_files:
        return None

    try:
        compiled = yara.compile(filepaths=yar_files)
    except yara.Error as exc:
        raise YaraRuleError(f"Could not compile YARA rules in {rule_dir}: {exc}") from exc

    return YaraRuleSet(compiled=compiled, source_dir=rule_dir, rule_count=len(yar_files))


def scan_text_with_yara(path: str | Path, text: str, rule_set: YaraRuleSet | None) -> list[Alert]:
    """Scan local text content with compiled YARA rules, if any are configured."""
    if rule_set is None:
        return []

    source_path = str(Path(path))
    matches = rule_set.compiled.match(data=text.encode("utf-8", errors="ignore"))

    alerts: list[Alert] = []
    for match in matches:
        meta = match.meta or {}
        severity = str(meta.get("severity", "low"))
        alerts.append(
            Alert(
                rule_id=str(meta.get("id", match.rule)),
                rule_name=match.rule,
                severity=severity,
                source_path=source_path,
                source_type="file",
                matched_field=None,
                matched_value=safe_excerpt(text),
                message=f"YARA rule {match.rule} matched file content",
                tags=tuple(match.tags),
                metadata={
                    "engine": "yara",
                    "description": str(meta.get("description", "")),
                },
            )
        )
    return alerts
