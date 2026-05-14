# Safety

This project is defensive-only and lab-only. It is designed for public portfolio review using local synthetic samples.

## Allowed Content

- Synthetic JSONL logs
- Synthetic CSV logs
- Harmless TXT and LOG text samples
- Fake inert detection markers
- Reserved domains such as `.test`, `example.com`, `example.org`, and `example.net`
- Documentation IP ranges when an IP is needed
- Local-only scans against files supplied by the user

## Prohibited Content

- Malware samples
- Working attack code
- Real credentials, tokens, API keys, secrets, or private keys
- Real production logs
- Real stolen data
- Real threat indicators
- Third-party scanning
- Offensive how-to guidance
- Binary samples that resemble harmful artifacts

## Synthetic Marker Policy

Suspicious samples must clearly indicate that they are synthetic. Current examples use markers such as:

- `SYNTHETIC_SUSPICIOUS_COMMAND_MARKER`
- `SYNTHETIC_SUSPICIOUS_FILE_MARKER`
- `synthetic: true`

Suspicious-looking strings must be fake, inert, and present only to test local detection logic.

## Reserved Domain Policy

Samples may use:

- `.test`
- `example.com`
- `example.org`
- `example.net`

Do not add real domains or real service URLs to samples.

## IP Address Policy

Samples should avoid IP addresses unless needed for log realism. If an IP is needed, use documentation ranges only:

- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`

Do not add real public IP addresses.

## Secret Safety

Do not add real or realistic:

- passwords
- tokens
- API keys
- private keys
- account numbers
- financial identifiers
- personal identifiers

## Public GitHub Safety Checklist

Before publishing or release preparation, verify:

- [ ] Samples are synthetic and harmless.
- [ ] Suspicious samples are clearly labeled synthetic.
- [ ] No real credentials or secrets are present.
- [ ] No real logs are present.
- [ ] No real indicators are present.
- [ ] No third-party scanning behavior exists.
- [ ] Generated reports come only from synthetic samples.
- [ ] Documentation does not imply production SOC, EDR, or SIEM capability.
