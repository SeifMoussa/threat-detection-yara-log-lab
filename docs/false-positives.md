# False Positives

False positives are benign events or files that match a detection rule. In this lab, false-positive samples are intentional and synthetic. They demonstrate how a SOC analyst or detection engineer reviews noisy matches without hiding the fact that a rule fired.

## Suppression Format

Suppressions are JSON files. The example file is `suppressions/example_suppressions.json`.

```json
{
  "suppressions": [
    {
      "id": "SUP-001",
      "rule_id": "AUTH-001",
      "source_path_contains": "false_positive",
      "matched_value_contains": "failed_login",
      "reason": "Expected synthetic training-lab false positive"
    }
  ]
}
```

Required fields:

- `id`
- `rule_id`
- `reason`

Optional matching fields:

- `source_path_contains`
- `matched_value_contains`

## CLI Usage

Hide suppressed alerts in normal output:

```bash
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/false_positive/auth_false_positive.jsonl --suppressions suppressions/example_suppressions.json --format json
```

Include suppressed alerts for review:

```bash
python -m yara_log_lab scan --rules rules/fallback --input samples/logs/false_positive/auth_false_positive.jsonl --suppressions suppressions/example_suppressions.json --format json --include-suppressed
```

## Example Workflow

1. Run a scan against a false-positive sample.
2. Confirm that the expected rule fires.
3. Add a narrow suppression with a clear reason.
4. Re-run the scan with suppressions.
5. Review suppressed alerts with `--include-suppressed`.
6. Confirm the report still counts suppressed alerts.

## Report Behavior

Reports always count suppressed alerts in the summary. Suppressed details are hidden by default and shown when `--include-suppressed` is used.

## Review Guidance

Suppressions must be reviewed, not blindly trusted. A suppression should be narrow, documented, and tied to a known synthetic benign context.
