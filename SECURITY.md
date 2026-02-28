# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in vigile-scan, **please report it privately** rather than opening a public issue.

### Preferred: GitHub Private Vulnerability Reporting

Use GitHub's built-in [private vulnerability reporting](https://github.com/Vigile-ai/vigile-cli/security/advisories/new) to submit your report directly. This is the fastest way to reach us.

### Alternative: Email

Send details to **security@vigile.dev** with:

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (if known)

### What to Expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Fix timeline** communicated once the issue is confirmed
- **Credit** in the advisory (unless you prefer to remain anonymous)

We follow coordinated disclosure — we ask that you give us reasonable time to patch before any public disclosure.

## Scope

This policy covers the `vigile-scan` CLI tool (npm: `vigile-scan`). For vulnerabilities in the Vigile platform (API, dashboard, registry), contact security@vigile.dev directly.

## Security Best Practices

When using vigile-scan:

- Always run the latest supported version
- Review scan results before acting on them — the tool reports findings, not guarantees
- Do not pipe scan output into automated remediation without human review
