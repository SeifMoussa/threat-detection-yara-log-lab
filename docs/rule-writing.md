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

## Optional Later YARA Adapter

YARA support is not part of the current implementation. A later adapter may translate or run compatible concepts, but normal usage and tests must continue to work without YARA.
