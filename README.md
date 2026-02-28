# vigile-scan

> The security scanner for AI agent tools. Detect tool poisoning, credential theft, and supply chain attacks in MCP servers and agent skills — before they reach your machine.

[![npm version](https://img.shields.io/npm/v/vigile-scan.svg)](https://www.npmjs.com/package/vigile-scan)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Quick Start

```bash
npx vigile-scan
```

That's it. No install, no config. Vigile discovers your MCP server configurations and agent skill files, scans them against 54 detection rules, and gives you a trust score for each one.

## What It Detects

### MCP Server Threats (22 patterns + 5 inline checks)

| ID | Category | What It Catches |
|----|----------|-----------------|
| TP-001–008 | Tool Poisoning | Prompt overrides, hidden manipulation, cross-tool injection, whitespace hiding, system prompt references, secrecy directives |
| EX-001–007 | Data Exfiltration | SSH key access, AWS credentials, .env files, credential files, suspicious URLs, crypto wallet access, browser data |
| PM-001–004 | Permission Abuse | Code execution (eval/spawn), unrestricted filesystem, network requests, sensitive path access |
| OB-001–004 | Obfuscation | Base64 content, zero-width Unicode, hex-encoded strings, Unicode escapes |
| EV/AR/CM | Inline Checks | Sensitive env vars, security bypass flags, sensitive directory args, auto-install (npx -y), typosquatting |

### Agent Skill Threats (27 patterns)

| ID | Category | What It Catches |
|----|----------|-----------------|
| SK-001–006 | Instruction Injection | Role hijacking, instruction override, hidden markdown instructions, conditional triggers, cross-skill poisoning, invisible Unicode |
| SK-010–014 | Malware Delivery | Remote script piping, reverse shells, suspicious install prerequisites, encoded payloads, typosquatted packages |
| SK-020–023 | Stealth Operations | Silent action directives, output suppression, history/log evasion, deceptive user responses |
| SK-030–033 | Safety Bypass | Confirmation bypass, safety feature disable, force flags, root/sudo escalation |
| SK-040–043 | Persistence Abuse | Startup file modification, memory file tampering, cron jobs, git hook injection |
| SK-050–053 | Data Exfiltration | Credential harvesting, URL-based exfiltration, filesystem enumeration, env var dumping |

## Platforms

Vigile auto-discovers configurations from:

- **Claude Desktop** — `claude_desktop_config.json`
- **Claude Code** — `CLAUDE.md`, `.claude/` skill files
- **Cursor** — `.cursor/rules/*.mdc`, `.cursorrules`
- **GitHub Copilot** — `.github/copilot/**/*.md`, `copilot-instructions.md`
- **Windsurf** — `windsurf.json`, `.windsurfrules`
- **VS Code** — `.vscode/mcp.json`
- **OpenClaw** — `~/.openclaw/openclaw.json`, `openclaw.config.json`

## Usage

```
vigile-scan [options]
```

### Scan Options

| Flag | Description |
|------|-------------|
| (no flags) | Scan all MCP servers on this machine |
| `-s, --skills` | Scan agent skills only (SKILL.md, .mdc rules, CLAUDE.md) |
| `-a, --all` | Scan both MCP servers and agent skills |
| `-j, --json` | Output results as JSON (for CI/CD pipelines) |
| `-v, --verbose` | Show detailed findings and score breakdown |
| `-c, --config <path>` | Path to a custom MCP config file |
| `-o, --output <path>` | Write results to a file |
| `--client <name>` | Only scan a specific client (claude-desktop, cursor, claude-code, windsurf, vscode, openclaw) |
| `--no-upload` | Skip uploading scan results to Vigile API |

### Sentinel Runtime Monitoring (Pro)

| Flag | Description |
|------|-------------|
| `--sentinel` | Enable runtime phone-home detection |
| `--sentinel-server <name>` | Monitor a specific MCP server by name |
| `--sentinel-duration <sec>` | Monitoring duration in seconds (default: 120) |

### Authentication

```bash
# Authenticate with your API key (get one at https://vigile.dev/account)
vigile-scan auth login <vgl_your_api_key>

# Check auth status
vigile-scan auth status

# Log out
vigile-scan auth logout
```

You can also set `VIGILE_TOKEN` as an environment variable for CI/CD.

## Examples

### Scan everything
```bash
npx vigile-scan --all
```

### JSON output for CI/CD
```bash
npx vigile-scan --json --all > vigile-report.json
```

### Scan a specific client
```bash
npx vigile-scan --client cursor
```

### Verbose output with score breakdown
```bash
npx vigile-scan --all --verbose
```

### GitHub Actions

```yaml
- name: Vigile Security Scan
  run: npx vigile-scan --all --json -o vigile-report.json
  env:
    VIGILE_TOKEN: ${{ secrets.VIGILE_TOKEN }}

- name: Fail on critical findings
  run: |
    critical=$(jq '.bySeverity.critical' vigile-report.json)
    if [ "$critical" -gt 0 ]; then exit 1; fi
```

## Trust Scores

Every scanned item gets a trust score from 0–100:

| Score | Level | Meaning |
|-------|-------|---------|
| 80–100 | Trusted | No significant issues found |
| 60–79 | Caution | Minor issues — review recommended |
| 40–59 | Risky | Significant issues — investigate before using |
| 0–39 | Dangerous | Critical issues — do not install |

The score is a weighted composite of five factors: code analysis, dependency health, permission safety, behavioral stability, and transparency.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan complete, no critical or high findings |
| 1 | Critical or high severity findings detected |

This makes `vigile-scan` work natively in CI/CD pipelines — a non-zero exit fails the build.

## Sentinel: Runtime Monitoring

Static scanning catches what's in the code. Sentinel catches what the code actually does on the wire.

When you run `--sentinel`, Vigile intercepts outbound network traffic from your MCP servers and flags:

- **C2 beaconing** — periodic callbacks to unknown servers
- **Credential theft** — API keys, tokens, or secrets sent over the network
- **DNS tunneling** — data exfiltration hidden in DNS queries
- **Unexpected destinations** — connections to IPs/domains outside the expected set

Sentinel is available on Pro ($9.99/mo) and Pro+ ($29.99/mo) plans. Free users can run static scans with no limits.

## Pricing

| Tier | Price | Highlights |
|------|-------|------------|
| Free | $0/forever | Unlimited CLI scans, 50 API scans/month, registry browsing |
| Pro | $9.99/mo | Sentinel monitoring (5 min, 3 servers), 1,000 API scans |
| Pro+ | $29.99/mo | Sentinel (30 min, 10 servers), DNS tunneling & C2 detection, alerts |

## Links

- **Web Scanner & Registry** — [vigile.dev](https://vigile.dev)
- **GitHub** — [github.com/Vigile-ai/vigile-scan](https://github.com/Vigile-ai/vigile-scan)
- **Report Issues** — [github.com/Vigile-ai/vigile-scan/issues](https://github.com/Vigile-ai/vigile-scan/issues)

## License

Apache-2.0
