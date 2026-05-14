# YARA-Style Log Lab Detection Report

Generated at: `2026-05-14T18:10:27+00:00`

## Safety

Safety disclaimer: this report was generated from local synthetic lab data only. It does not contain malware samples, real credentials, real stolen data, attack guidance, or third-party scanning results. This educational lab does not claim production SOC, EDR, or SIEM capability.

## Inputs

- `samples/logs/false_positive/auth_false_positive.jsonl`

## Summary

- Total alerts: 1
- Unsuppressed alerts: 0
- Suppressed alerts: 1
- High severity: 1
- Medium severity: 0
- Low severity: 0

## Rule Summary

| Rule ID | Severity | Enabled | Name | Tags |
| --- | --- | --- | --- | --- |
| AUTH-001 | high | true | Synthetic Failed Login Burst | auth, threshold, synthetic |
| IND-001 | medium | true | Known Fake Lab Domain | indicator, domain, synthetic |
| CMD-001 | medium | true | Synthetic Suspicious Command Marker | process, command-line, synthetic |
| FILE-001 | low | true | Synthetic Suspicious File Marker | file, content, synthetic |

## Alert Details

| Rule ID | Severity | Source | Field | Matched Value | Suppressed | Message |
| --- | --- | --- | --- | --- | --- | --- |
| AUTH-001 | high | samples\logs\false_positive\auth_false_positive.jsonl | event_type | failed_login | true | Rule AUTH-001 matched threshold count 5 |

## Suppressed Alerts

| Rule ID | Source | Reason |
| --- | --- | --- |
| AUTH-001 | samples\logs\false_positive\auth_false_positive.jsonl | Expected synthetic training-lab failed-login false positive |

## False-Positive Review Notes

False-positive handling is rule-driven and explicit. Suppressed alerts remain counted in the summary, and suppression reasons are shown when suppressed details are included.
