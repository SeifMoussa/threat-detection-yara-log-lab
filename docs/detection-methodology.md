# Detection Methodology

The goal is to demonstrate detection-engineering thinking in a safe local lab: define rules, test them against known samples, review false positives, and explain results clearly.

## Engine Design

There are two engines behind file-content scanning, and they both feed the same alert model. A Python fallback engine reads local synthetic logs and text files, applies JSON rules, and emits structured alerts. Alongside it, a small set of real `.yar` rules under `rules/yara/` are compiled and matched with `yara-python` against the same text samples. Log scanning (JSONL/CSV) only goes through the fallback engine — YARA in this lab is scoped to file content.

## Rule Types

`contains`:

- Matches when a pattern appears in a selected log field or file content.

`regex`:

- Uses Python regular expressions.
- Invalid patterns fail with controlled errors.

`field_equals`:

- Matches exact string equality on a selected log field.

`threshold`:

- Groups matching log records and alerts when a count threshold is reached.
- Current threshold logic is simple and does not strictly enforce time windows.

## Severity Model

Supported severities:

- `low`: informational or weak signal
- `medium`: suspicious local pattern worth review
- `high`: stronger synthetic pattern such as a repeated failed-login threshold

Severity is educational metadata. It is not a production risk score.

## Alert Fields

Alerts include:

- rule ID and name
- severity
- source path
- source type
- matched field
- short matched value excerpt
- explanation message
- tags
- suppression status
- metadata such as timestamp, host, user, count, or suppression reason

## Triage Context

The lab keeps triage context close to the alert so reviewers can understand why a rule matched. Examples include grouped threshold counts, source paths, and synthetic host/user fields.

## Suppression Workflow

Known false positives are handled with explicit JSON suppressions. Suppressions match by rule ID and optional source or matched-value conditions. Suppressed alerts are marked, counted, and optionally displayed.

Suppressions are review aids, not proof that an alert is always harmless.

## Report Workflow

Reports are generated from local scan results. Markdown and JSON reports include input paths, alert totals, severity counts, rule summaries, alert details, suppression counts, and a safety disclaimer.

Reports are educational artifacts and do not claim production SOC, EDR, or SIEM capability.

## False-Positive Mindset

Detection quality includes precision. This lab includes false-positive samples so the workflow shows:

- expected matching before suppression
- explicit suppression reason
- retained alert count visibility
- reviewer-friendly documentation

## Intentionally Not Implemented

- production telemetry collection
- live system monitoring
- third-party scanning
- production SIEM integration
- strict time-window threshold logic
- recursive directory scanning
