"""Markdown and JSON report generation for local synthetic scans."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from yara_log_lab.alerts import Alert, safe_excerpt
from yara_log_lab.rule_loader import Rule

SAFETY_DISCLAIMER = (
    "Safety disclaimer: this report was generated from local synthetic lab data only. "
    "It does not contain malware samples, real credentials, real stolen data, attack "
    "guidance, or third-party scanning results. This educational lab does not claim "
    "production SOC, EDR, or SIEM capability."
)


@dataclass(frozen=True)
class Report:
    """Structured report content."""

    title: str
    generated_at: str
    input_paths: tuple[str, ...]
    rules_used: tuple[Rule, ...]
    alerts: tuple[Alert, ...]
    include_suppressed: bool = False

    @property
    def displayed_alerts(self) -> tuple[Alert, ...]:
        """Alerts included in detail output."""
        if self.include_suppressed:
            return self.alerts
        return tuple(alert for alert in self.alerts if not alert.suppressed)

    @property
    def suppressed_count(self) -> int:
        """Number of suppressed alerts."""
        return sum(1 for alert in self.alerts if alert.suppressed)

    @property
    def unsuppressed_count(self) -> int:
        """Number of unsuppressed alerts."""
        return sum(1 for alert in self.alerts if not alert.suppressed)

    @property
    def severity_counts(self) -> dict[str, int]:
        """Severity counts across all alerts."""
        counts = Counter(alert.severity for alert in self.alerts)
        return {severity: counts.get(severity, 0) for severity in ("high", "medium", "low")}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable report dictionary."""
        return {
            "title": self.title,
            "generated_at": self.generated_at,
            "safety_disclaimer": SAFETY_DISCLAIMER,
            "summary": {
                "total_alerts": len(self.alerts),
                "unsuppressed_count": self.unsuppressed_count,
                "suppressed_count": self.suppressed_count,
            },
            "severity_counts": self.severity_counts,
            "input_paths": list(self.input_paths),
            "rules_used": [_rule_to_dict(rule) for rule in self.rules_used],
            "alerts": [alert.to_dict() for alert in self.displayed_alerts],
        }


def build_report(
    alerts: list[Alert],
    rules: list[Rule],
    input_paths: list[str],
    include_suppressed: bool = False,
    title: str = "YARA-Style Log Lab Detection Report",
) -> Report:
    """Build structured report content."""
    return Report(
        title=title,
        generated_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        input_paths=tuple(input_paths),
        rules_used=tuple(rules),
        alerts=tuple(alerts),
        include_suppressed=include_suppressed,
    )


def render_markdown_report(report: Report) -> str:
    """Render a report as Markdown."""
    lines = [
        f"# {report.title}",
        "",
        f"Generated at: `{report.generated_at}`",
        "",
        "## Safety",
        "",
        SAFETY_DISCLAIMER,
        "",
        "## Inputs",
        "",
    ]
    lines.extend(f"- `{path}`" for path in report.input_paths)
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Total alerts: {len(report.alerts)}",
            f"- Unsuppressed alerts: {report.unsuppressed_count}",
            f"- Suppressed alerts: {report.suppressed_count}",
            f"- High severity: {report.severity_counts['high']}",
            f"- Medium severity: {report.severity_counts['medium']}",
            f"- Low severity: {report.severity_counts['low']}",
            "",
            "## Rule Summary",
            "",
            "| Rule ID | Severity | Enabled | Name | Tags |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for rule in report.rules_used:
        lines.append(
            "| "
            f"{_md(rule.id)} | {_md(rule.severity)} | {str(rule.enabled).lower()} | "
            f"{_md(rule.name)} | {_md(', '.join(rule.tags))} |"
        )

    lines.extend(
        [
            "",
            "## Alert Details",
            "",
            "| Rule ID | Severity | Source | Field | Matched Value | Suppressed | Message |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    if report.displayed_alerts:
        for alert in report.displayed_alerts:
            lines.append(
                "| "
                f"{_md(alert.rule_id)} | {_md(alert.severity)} | "
                f"{_md(alert.source_path)} | {_md(alert.matched_field or '-')} | "
                f"{_md(alert.matched_value)} | {str(alert.suppressed).lower()} | "
                f"{_md(alert.message)} |"
            )
    else:
        lines.append("| - | - | - | - | - | - | No alert details included |")

    if report.suppressed_count:
        lines.extend(["", "## Suppressed Alerts", ""])
        if report.include_suppressed:
            lines.extend(
                [
                    "| Rule ID | Source | Reason |",
                    "| --- | --- | --- |",
                ]
            )
            for alert in report.alerts:
                if not alert.suppressed:
                    continue
                reason = str(alert.metadata.get("suppression_reason", ""))
                lines.append(f"| {_md(alert.rule_id)} | {_md(alert.source_path)} | {_md(reason)} |")
        else:
            lines.append(
                "Suppressed alert details are hidden. Re-run with `--include-suppressed` "
                "to include suppression reasons."
            )

    lines.extend(
        [
            "",
            "## False-Positive Review Notes",
            "",
            "False-positive handling is rule-driven and explicit. Suppressed alerts remain "
            + "counted in the summary, and suppression reasons are shown when suppressed "
            + "details are included.",
            "",
        ]
    )
    return "\n".join(lines)


def render_json_report(report: Report) -> str:
    """Render a report as formatted JSON."""
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def write_report(path: str | Path, content: str) -> None:
    """Write report content to a local file."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")


def _rule_to_dict(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "severity": rule.severity,
        "tags": list(rule.tags),
        "rule_type": rule.rule_type,
        "target": rule.target,
        "enabled": rule.enabled,
    }


def _md(value: str) -> str:
    return safe_excerpt(value).replace("|", "\\|")
