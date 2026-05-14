# YARA-Style Log Lab Detection Report

Generated at: `2026-05-14T18:33:32+00:00`

## Safety

Safety disclaimer: this report was generated from local synthetic lab data only. It does not contain malware samples, real credentials, real stolen data, attack guidance, or third-party scanning results. This educational lab does not claim production SOC, EDR, or SIEM capability.

## Inputs

- `samples/logs/suspicious/auth_suspicious.jsonl`

## Summary

- Total alerts: 1
- Unsuppressed alerts: 1
- Suppressed alerts: 0
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
| AUTH-001 | high | samples\logs\suspicious\auth_suspicious.jsonl | event_type | failed_login | false | Rule AUTH-001 matched threshold count 5 |

## False-Positive Review Notes

False-positive handling is rule-driven and explicit. Suppressed alerts remain counted in the summary, and suppression reasons are shown when suppressed details are included.
