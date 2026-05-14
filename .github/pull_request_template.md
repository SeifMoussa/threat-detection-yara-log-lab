## Summary

Describe the change.

## Safety Checklist

- [ ] No malware
- [ ] No exploit code
- [ ] No real credentials, tokens, secrets, or stolen data
- [ ] No real production logs
- [ ] No third-party scanning
- [ ] Synthetic samples only

## Testing

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
```
