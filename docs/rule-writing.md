# Rule Writing

Fallback rules are JSON files under `rules/fallback/`. They use YARA-style concepts while staying portable and dependency-light.

## File Shape

Each file contains a top-level `rules` list:

```json
{
  "rules": [
    {
      "id": "CMD-001",
      "name": "Synthetic Suspicious Command Marker",
      "description": "Flags an inert command-line marker used only in synthetic lab samples.",
      "severity": "medium",
      "tags": ["process", "command-line", "synthetic"],
      "rule_type": "contains",
      "target": "log_field",
      "field": "command_line",
      "pattern": "SYNTHETIC_SUSPICIOUS_COMMAND_MARKER",
      "false_positive_notes": "May appear in training material or documentation examples.",
      "sample_references": ["samples/logs/suspicious/process_suspicious.csv"],
      "enabled": true
    }
  ]
}
```

## Required Fields

- `id`
- `name`
- `description`
- `severity`
- `tags`
- `rule_type`
- `target`
- `false_positive_notes`
- `sample_references`
- `enabled`

Rules targeting `log_field` must include `field`.

`contains`, `regex`, and `field_equals` rules must include `pattern`.

`threshold` rules must include `condition`.

## Severity Values

- `low`
- `medium`
- `high`

## Rule Types

`contains`:

```json
{
  "rule_type": "contains",
  "target": "log_field",
  "field": "command_line",
  "pattern": "SYNTHETIC_SUSPICIOUS_COMMAND_MARKER"
}
```

`regex`:

```json
{
  "rule_type": "regex",
  "target": "log_field",
  "field": "command_line",
  "pattern": "\\\\bfake-control\\\\.test\\\\b"
}
```

`field_equals`:

```json
{
  "rule_type": "field_equals",
  "target": "log_field",
  "field": "event_type",
  "pattern": "failed_login"
}
```

`threshold`:

```json
{
  "rule_type": "threshold",
  "target": "log_field",
  "field": "event_type",
  "condition": {
    "field": "event_type",
    "equals": "failed_login",
    "group_by": ["user", "source_ip"],
    "count_gte": 5,
    "window_minutes": 10
  }
}
```

## Target Values

- `log_field`
- `file_content`

## Rule ID Convention

Rule IDs must be unique and follow this pattern:

- `AUTH-001`
- `CMD-001`
- `FILE-001`
- `IND-001`

## Sample References

Every enabled rule must reference at least one positive suspicious sample. References should point to local synthetic files under `samples/`.

## False-Positive Notes

Every rule must include `false_positive_notes`. Good notes explain realistic benign contexts, such as training material, documentation examples, or expected lab exercises.

## Testing Expectation

Each rule should have:

- a positive sample that should match
- a benign or negative sample that should not create severe noise
- a false-positive note when benign matches are plausible
- test coverage for schema and matching behavior

## Writing Real YARA Rules

The `rules/fallback/` JSON rules above are one engine. The other lives in `rules/yara/` as plain `.yar` files, compiled and matched with `yara-python`. They only apply to file-content scans (`--yara-rules`, default `rules/yara`), not to JSONL/CSV log input.

Each rule in this lab carries a `meta` block so its alerts line up with the JSON rules' fields:

```text
rule Synthetic_Suspicious_File_Marker : file synthetic
{
    meta:
        id = "YARA-001"
        description = "Synthetic lab marker, not a real threat signature. ..."
        severity = "low"
        false_positive_notes = "Also appears intentionally in the false_positive fixture."
        author = "Seif Hegazy"

    strings:
        $marker = "SYNTHETIC_SUSPICIOUS_FILE_MARKER" ascii

    condition:
        $marker
}
```

Guidelines for adding a new `.yar` rule here:

- Always set `meta.id`, `meta.description`, and `meta.severity` — the engine reads these directly into the alert.
- Start every `meta.description` with a plain statement that the rule targets a synthetic lab marker, not a real threat pattern, so nobody skimming the repo mistakes it for production threat intel.
- Point the rule at a string that already exists in one of the synthetic fixtures under `samples/files/` rather than inventing new indicator-looking content.
- Add or update a test in `tests/test_yara_rules.py` proving the rule fires on the intended suspicious fixture and stays silent on the benign one.

## Rule ID Namespaces

Fallback rule IDs (`AUTH-`, `CMD-`, `FILE-`, `IND-`) and YARA rule IDs (`YARA-`) are kept in separate namespaces on purpose, so an alert's `rule_id` prefix tells you which engine produced it without checking `metadata.engine`.
