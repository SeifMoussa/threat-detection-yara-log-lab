# Release Checklist

This checklist tracks local release preparation. Do not create a tag or release until after first-push verification.

## Current State

- [x] Code complete through Phase 8.
- [x] Documentation updated in Phase 6.
- [x] CI configured.
- [x] CodeQL configured.
- [ ] CI not yet verified on GitHub.
- [ ] CodeQL not yet verified on GitHub.
- [x] Final QA completed locally in Phase 8.
- [x] Release preparation materials completed locally in Phase 9.
- [ ] Tag/release creation pending.

## Local Verification

- [x] Tests passing: 88 passed.
- [x] Coverage passing: 96.07%.
- [x] Coverage gate: 90%.
- [x] Ruff check passing.
- [x] Ruff format check passing.
- [x] Docs check passing.
- [x] CLI smoke passing.
- [x] No YARA dependency required.

## Pending First-Push Items

- [ ] Push to `https://github.com/SeifMoussa/threat-detection-yara-log-lab`.
- [ ] Confirm GitHub Actions CI run.
- [ ] Confirm CodeQL run.
- [ ] Confirm README badges render.
- [ ] Confirm repository topics and description.
- [ ] Create tag only after hosted verification.

## Safety Review

- [x] No malware samples.
- [x] No working attack code.
- [x] No real credentials, tokens, API keys, or secrets.
- [x] No real production logs.
- [x] No real threat indicators.
- [x] No third-party scanning.
- [x] Generated reports are real outputs from synthetic samples.
- [x] No fake screenshots.

## Documentation Review

- [x] README accurately states current capabilities.
- [x] Docs state CI and CodeQL are configured but not yet verified on GitHub.
- [x] Docs do not claim production SOC, EDR, or SIEM capability.
- [x] Example report links work.
- [x] Known limitations are documented.
