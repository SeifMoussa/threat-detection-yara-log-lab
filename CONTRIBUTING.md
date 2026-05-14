# Contributing

This project is a defensive, educational SOC lab. Contributions must preserve the safety scope.

## Safety Requirements

Do not contribute:

- Malware
- Exploit code
- Real credentials or secrets
- Real production logs
- Stolen data
- Live scanning logic for third-party systems
- Offensive instructions

Use only harmless synthetic samples.

## Development Checks

Run before submitting changes:

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
```
