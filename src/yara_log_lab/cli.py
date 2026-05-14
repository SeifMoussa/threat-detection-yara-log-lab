"""Command-line interface for the YARA-style log analysis lab."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from yara_log_lab.engine import DetectionError, UnsupportedInputError, scan_many
from yara_log_lab.reporting import (
    build_report,
    render_json_report,
    render_markdown_report,
    write_report,
)
from yara_log_lab.rule_loader import RuleValidationError, load_rules_from_directory
from yara_log_lab.suppressions import (
    SuppressionValidationError,
    apply_suppressions,
    load_suppressions,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        prog="yara-log-lab",
        description="Safe defensive lab for YARA-style rules and local log analysis.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="yara-log-lab 0.1.0",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan local synthetic samples")
    scan_parser.add_argument("--rules", default="rules/fallback", help="Fallback rule directory")
    scan_parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="Local input file or non-recursive directory to scan",
    )
    scan_parser.add_argument("--format", choices=("json", "text"), default="text")
    scan_parser.add_argument("--suppressions", help="Optional JSON suppression file")
    scan_parser.add_argument(
        "--include-suppressed",
        action="store_true",
        help="Include suppressed alerts in output",
    )
    scan_parser.set_defaults(handler=_handle_scan)

    report_parser = subparsers.add_parser("report", help="Generate a scan report")
    report_parser.add_argument("--rules", default="rules/fallback", help="Fallback rule directory")
    report_parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="Local input file or non-recursive directory to scan",
    )
    report_parser.add_argument("--output", required=True, help="Report output path")
    report_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    report_parser.add_argument("--suppressions", help="Optional JSON suppression file")
    report_parser.add_argument(
        "--include-suppressed",
        action="store_true",
        help="Include suppressed alert details in the report",
    )
    report_parser.set_defaults(handler=_handle_report)

    validate_parser = subparsers.add_parser("validate-rules", help="Validate fallback rules")
    validate_parser.add_argument(
        "--rules", default="rules/fallback", help="Fallback rule directory"
    )
    validate_parser.set_defaults(handler=_handle_validate_rules)

    list_parser = subparsers.add_parser("list-rules", help="List fallback rules")
    list_parser.add_argument("--rules", default="rules/fallback", help="Fallback rule directory")
    list_parser.set_defaults(handler=_handle_list_rules)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 0
    try:
        return args.handler(args)
    except (
        DetectionError,
        RuleValidationError,
        SuppressionValidationError,
        UnsupportedInputError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _handle_scan(args: argparse.Namespace) -> int:
    rules = load_rules_from_directory(args.rules)
    alerts = scan_many(args.input, rules)
    if args.suppressions:
        suppressions = load_suppressions(args.suppressions)
        alerts = apply_suppressions(alerts, suppressions)
    if not args.include_suppressed:
        alerts = [alert for alert in alerts if not alert.suppressed]
    if args.format == "json":
        print(json.dumps([alert.to_dict() for alert in alerts], indent=2, sort_keys=True))
    else:
        _print_text_alerts(alerts)
    return 0


def _handle_validate_rules(args: argparse.Namespace) -> int:
    rules = load_rules_from_directory(args.rules)
    print(f"Validated {len(rules)} fallback rules from {Path(args.rules)}")
    return 0


def _handle_report(args: argparse.Namespace) -> int:
    rules = load_rules_from_directory(args.rules)
    alerts = scan_many(args.input, rules)
    if args.suppressions:
        suppressions = load_suppressions(args.suppressions)
        alerts = apply_suppressions(alerts, suppressions)
    report = build_report(
        alerts=alerts,
        rules=rules,
        input_paths=args.input,
        include_suppressed=args.include_suppressed,
    )
    content = (
        render_json_report(report) if args.format == "json" else render_markdown_report(report)
    )
    write_report(args.output, content)
    print(f"Wrote {args.format} report to {Path(args.output)}")
    return 0


def _handle_list_rules(args: argparse.Namespace) -> int:
    rules = load_rules_from_directory(args.rules)
    for rule in rules:
        status = "enabled" if rule.enabled else "disabled"
        print(f"{rule.id}\t{rule.severity}\t{status}\t{rule.name}")
    return 0


def _print_text_alerts(alerts: list[object]) -> None:
    if not alerts:
        print("No alerts")
        return
    for alert in alerts:
        print(
            f"{alert.severity.upper()} {alert.rule_id} {alert.rule_name} "
            f"source={alert.source_path} field={alert.matched_field or '-'} "
            f"value={alert.matched_value}"
        )
