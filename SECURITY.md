# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0   | :white_check_mark: |


## Security Best Practices

When using this tool:

1. **Authorization**: Always obtain written authorization before scanning any systems
2. **Rate Limiting**: Use appropriate rate limits to avoid DoS conditions
3. **Scope**: Only scan systems explicitly in scope
4. **Data Handling**: Treat scan results as sensitive - they contain vulnerability data
5. **Network Segmentation**: Run from authorized security testing networks only
6. **Logging**: Secure log files - they may contain sensitive information
7. **Webhook Security**: Protect Teams webhook URLs - treat as credentials

## Known Limitations

- Tool relies on Nuclei templates - not all CVEs have templates
- Rate limiting is honored but network conditions vary
- Results should be verified before taking action
- False positives possible - manual validation recommended

## Responsible Use

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Security research with permission
- ✅ Vulnerability management programs
- ✅ Red team operations (authorized)
- ✅ Educational purposes in controlled environments

This tool is NOT intended for:
- ❌ Unauthorized scanning of systems
- ❌ Malicious activity
- ❌ Violation of computer fraud laws
- ❌ Network reconnaissance without permission

## Legal Compliance

Users are responsible for ensuring compliance with:
- Computer Fraud and Abuse Act (CFAA) - US
- Computer Misuse Act - UK
- Local, state, and national laws
- Organizational security policies
- Terms of service of target systems

**By using this tool, you agree to use it legally and ethically.**
