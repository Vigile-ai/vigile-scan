// ============================================================
// Vigile CLI — Terminal Output Formatter
// ============================================================
// Pretty-prints scan results with color-coded trust scores
// and categorized findings for both MCP servers and skills.

import chalk from 'chalk';
import type {
  ScanResult,
  SkillScanResult,
  ScanSummary,
  Finding,
  TrustLevel,
  Severity,
  SkillFileType,
} from '../types/index.js';
import type { SentinelReport, SentinelThreatLevel } from '../sentinel/index.js';
import { SENTINEL_MARKETING } from '../sentinel/index.js';

const TRUST_COLORS: Record<TrustLevel, (text: string) => string> = {
  trusted: chalk.green,
  caution: chalk.yellow,
  risky: chalk.hex('#FF8C00'), // orange
  dangerous: chalk.red,
};

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

const TRUST_ICONS: Record<TrustLevel, string> = {
  trusted: '✓',
  caution: '⚠',
  risky: '⚠',
  dangerous: '✗',
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '!!!',
  high: '!!',
  medium: '!',
  low: 'i',
  info: '·',
};

const FILE_TYPE_LABELS: Record<SkillFileType, string> = {
  'skill.md': 'SKILL.md',
  'mdc-rule': '.mdc rule',
  'claude.md': 'CLAUDE.md',
  'soul.md': 'SOUL.md',
  'memory.md': 'MEMORY.md',
};

/** Print the Vigile banner */
export function printBanner(): void {
  console.log('');
  console.log(chalk.bold.hex('#2C4A7C')('  ╦  ╦╦╔═╗╦╦  '));
  console.log(chalk.bold.hex('#2C4A7C')('  ╚╗╔╝║║ ╦║║  '));
  console.log(chalk.bold.hex('#2C4A7C')('   ╚╝ ╩╚═╝╩╩═╝'));
  console.log(chalk.gray('  AI Agent Security Scanner'));
  console.log('');
}

/** Print scan results for a single MCP server */
export function printServerResult(result: ScanResult, verbose: boolean): void {
  const color = TRUST_COLORS[result.trustLevel];
  const icon = TRUST_ICONS[result.trustLevel];

  // Server header
  console.log(
    chalk.bold(`  ${icon} `) +
    chalk.bold(result.server.name) +
    chalk.gray(` (${result.server.source})`) +
    '  ' +
    color(`[${result.trustScore}/100 ${result.trustLevel.toUpperCase()}]`)
  );

  // Config path
  console.log(chalk.gray(`    Config: ${result.server.configPath}`));

  // Command
  console.log(
    chalk.gray(`    Command: ${result.server.command} ${result.server.args.join(' ')}`)
  );

  // Findings
  if (result.findings.length === 0) {
    console.log(chalk.green('    No security issues found.'));
  } else {
    console.log(
      chalk.dim(`    ${result.findings.length} finding(s):`)
    );

    for (const finding of result.findings) {
      printFinding(finding, verbose);
    }
  }

  // Score breakdown (verbose only)
  if (verbose) {
    printScoreBreakdown(result.scoreBreakdown);
  }

  console.log('');
}

/** Print scan results for a single skill file */
export function printSkillResult(result: SkillScanResult, verbose: boolean): void {
  const color = TRUST_COLORS[result.trustLevel];
  const icon = TRUST_ICONS[result.trustLevel];
  const typeLabel = FILE_TYPE_LABELS[result.skill.fileType] || result.skill.fileType;

  // Skill header
  console.log(
    chalk.bold(`  ${icon} `) +
    chalk.bold(result.skill.name) +
    chalk.gray(` (${typeLabel} · ${result.skill.source} · ${result.skill.scope})`) +
    '  ' +
    color(`[${result.trustScore}/100 ${result.trustLevel.toUpperCase()}]`)
  );

  // File path
  console.log(chalk.gray(`    Path: ${result.skill.filePath}`));

  // File size
  const sizeKB = (result.skill.size / 1024).toFixed(1);
  console.log(chalk.gray(`    Size: ${sizeKB} KB`));

  // Findings
  if (result.findings.length === 0) {
    console.log(chalk.green('    No security issues found.'));
  } else {
    console.log(
      chalk.dim(`    ${result.findings.length} finding(s):`)
    );

    for (const finding of result.findings) {
      printFinding(finding, verbose);
    }
  }

  // Score breakdown (verbose only)
  if (verbose) {
    printScoreBreakdown(result.scoreBreakdown);
  }

  console.log('');
}

/** Print a single finding */
function printFinding(finding: Finding, verbose: boolean): void {
  const color = SEVERITY_COLORS[finding.severity];
  const icon = SEVERITY_ICONS[finding.severity];

  console.log(
    `      ${color(`[${icon}]`)} ${color(finding.severity.toUpperCase())} ` +
    chalk.white(finding.title) +
    chalk.gray(` (${finding.id})`)
  );

  if (verbose) {
    console.log(chalk.gray(`          ${finding.description}`));
    if (finding.evidence) {
      console.log(chalk.gray(`          Evidence: ${finding.evidence}`));
    }
    console.log(chalk.cyan(`          → ${finding.recommendation}`));
  }
}

/** Print score breakdown */
function printScoreBreakdown(b: { codeAnalysis: number; dependencyHealth: number; permissionSafety: number; behavioralStability: number; transparency: number }): void {
  console.log(chalk.dim('    Score Breakdown:'));
  console.log(chalk.dim(`      Code Analysis:       ${scoreBar(b.codeAnalysis)} ${b.codeAnalysis}/100 (30%)`));
  console.log(chalk.dim(`      Dependency Health:    ${scoreBar(b.dependencyHealth)} ${b.dependencyHealth}/100 (20%)`));
  console.log(chalk.dim(`      Permission Safety:    ${scoreBar(b.permissionSafety)} ${b.permissionSafety}/100 (20%)`));
  console.log(chalk.dim(`      Behavioral Stability: ${scoreBar(b.behavioralStability)} ${b.behavioralStability}/100 (15%)`));
  console.log(chalk.dim(`      Transparency:         ${scoreBar(b.transparency)} ${b.transparency}/100 (15%)`));
}

/** Print the overall scan summary */
export function printSummary(summary: ScanSummary): void {
  console.log(chalk.bold('  ─── Scan Summary ───'));
  console.log('');

  if (summary.totalServers > 0) {
    console.log(`  MCP servers scanned: ${chalk.bold(String(summary.totalServers))}`);
  }
  if (summary.totalSkills > 0) {
    console.log(`  Skill files scanned: ${chalk.bold(String(summary.totalSkills))}`);
  }

  const totalScanned = summary.totalServers + summary.totalSkills;
  if (totalScanned > 0 && summary.totalServers > 0 && summary.totalSkills > 0) {
    console.log(`  Total scanned:       ${chalk.bold(String(totalScanned))}`);
  }

  console.log(
    `  ${chalk.green(`${TRUST_ICONS.trusted} Trusted: ${summary.byTrustLevel.trusted}`)}  ` +
    `${chalk.yellow(`${TRUST_ICONS.caution} Caution: ${summary.byTrustLevel.caution}`)}  ` +
    `${chalk.hex('#FF8C00')(`${TRUST_ICONS.risky} Risky: ${summary.byTrustLevel.risky}`)}  ` +
    `${chalk.red(`${TRUST_ICONS.dangerous} Dangerous: ${summary.byTrustLevel.dangerous}`)}`
  );

  const totalFindings = Object.values(summary.bySeverity).reduce((a, b) => a + b, 0);
  if (totalFindings > 0) {
    console.log('');
    console.log(`  Total findings: ${chalk.bold(String(totalFindings))}`);
    if (summary.bySeverity.critical > 0)
      console.log(chalk.bgRed.white.bold(`    ${summary.bySeverity.critical} CRITICAL`));
    if (summary.bySeverity.high > 0)
      console.log(chalk.red.bold(`    ${summary.bySeverity.high} HIGH`));
    if (summary.bySeverity.medium > 0)
      console.log(chalk.yellow(`    ${summary.bySeverity.medium} MEDIUM`));
    if (summary.bySeverity.low > 0)
      console.log(chalk.blue(`    ${summary.bySeverity.low} LOW`));
    if (summary.bySeverity.info > 0)
      console.log(chalk.gray(`    ${summary.bySeverity.info} INFO`));
  }

  console.log('');
  console.log(chalk.gray(`  Scanned at ${summary.timestamp}`));
  console.log(chalk.gray(`  Vigile v${summary.version} — https://vigile.dev`));
  console.log('');
}

/** Print "no servers found" message */
export function printNoServersFound(): void {
  console.log(chalk.yellow('  No MCP server configurations found on this machine.'));
  console.log('');
  console.log(chalk.gray('  Vigile checks the following locations:'));
  console.log(chalk.gray('    • Claude Desktop config'));
  console.log(chalk.gray('    • Cursor MCP config'));
  console.log(chalk.gray('    • Claude Code config (.claude.json / .mcp.json)'));
  console.log(chalk.gray('    • Windsurf MCP config'));
  console.log(chalk.gray('    • VS Code MCP config (.vscode/mcp.json)'));
  console.log('');
  console.log(chalk.gray('  If you have MCP servers configured elsewhere, use:'));
  console.log(chalk.cyan('    vigile-scan --config /path/to/config.json'));
  console.log('');
  console.log(chalk.gray('  To also scan agent skill files, use:'));
  console.log(chalk.cyan('    vigile-scan --all'));
  console.log('');
}

/** Print "no skills found" message */
export function printNoSkillsFound(): void {
  console.log(chalk.yellow('  No agent skill files found on this machine.'));
  console.log('');
  console.log(chalk.gray('  Vigile scans the following skill locations:'));
  console.log(chalk.gray('    • Claude Code skills (.claude/skills/*/SKILL.md)'));
  console.log(chalk.gray('    • Claude Code commands (.claude/commands/**/*.md)'));
  console.log(chalk.gray('    • GitHub Copilot skills (.github/skills/*/SKILL.md)'));
  console.log(chalk.gray('    • Cursor rules (.cursor/rules/*.mdc, .cursorrules)'));
  console.log(chalk.gray('    • Memory files (CLAUDE.md, SOUL.md, MEMORY.md)'));
  console.log('');
}

/** Print "nothing found" message (neither servers nor skills) */
export function printNothingFound(): void {
  console.log(chalk.yellow('  No MCP servers or agent skill files found.'));
  console.log('');
  console.log(chalk.gray('  Try scanning a specific config:'));
  console.log(chalk.cyan('    vigile-scan --config /path/to/config.json'));
  console.log('');
  console.log(chalk.gray('  Or cd into a project directory that contains skill files:'));
  console.log(chalk.cyan('    cd /path/to/project && vigile-scan --all'));
  console.log('');
}

/** Create a mini score bar */
function scoreBar(score: number): string {
  const filled = Math.round(score / 10);
  const empty = 10 - filled;
  const color =
    score >= 80 ? chalk.green :
    score >= 60 ? chalk.yellow :
    score >= 40 ? chalk.hex('#FF8C00') :
    chalk.red;
  return color('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));
}

// ============================================================
// Sentinel Output
// ============================================================

const SENTINEL_THREAT_COLORS: Record<SentinelThreatLevel, (text: string) => string> = {
  clean: chalk.green,
  suspicious: chalk.yellow,
  malicious: chalk.red,
  critical: chalk.bgRed.white.bold,
};

const SENTINEL_THREAT_ICONS: Record<SentinelThreatLevel, string> = {
  clean: '✓',
  suspicious: '⚠',
  malicious: '✗',
  critical: '!!!',
};

/** Print a Sentinel monitoring report */
export function printSentinelReport(report: SentinelReport): void {
  const color = SENTINEL_THREAT_COLORS[report.threatLevel];
  const icon = SENTINEL_THREAT_ICONS[report.threatLevel];

  console.log('');
  console.log(
    chalk.bold(`  ${icon} `) +
    chalk.bold(`Sentinel: ${report.serverName}`) +
    '  ' +
    color(`[Threat: ${report.threatScore}/100 ${report.threatLevel.toUpperCase()}]`)
  );

  console.log(chalk.gray(`    Monitored: ${report.monitoringDuration.toFixed(0)}s | Events: ${report.totalEvents} | Destinations: ${report.uniqueDestinations.length}`));

  if (report.uniqueDestinations.length > 0) {
    console.log(chalk.gray(`    Destinations:`));
    for (const dest of report.uniqueDestinations.slice(0, 10)) {
      console.log(chalk.gray(`      → ${dest}`));
    }
    if (report.uniqueDestinations.length > 10) {
      console.log(chalk.gray(`      ... and ${report.uniqueDestinations.length - 10} more`));
    }
  }

  if (report.findings.length === 0) {
    console.log(chalk.green('    No suspicious network behavior detected.'));
  } else {
    console.log(chalk.dim(`    ${report.findings.length} finding(s):`));
    for (const finding of report.findings) {
      const fColor = SEVERITY_COLORS[finding.severity];
      const fIcon = SEVERITY_ICONS[finding.severity];
      console.log(
        `      ${fColor(`[${fIcon}]`)} ${fColor(finding.severity.toUpperCase())} ` +
        chalk.white(finding.title) +
        chalk.gray(` (${finding.id})`)
      );
      console.log(chalk.gray(`          ${finding.description}`));
      if (finding.evidence && finding.evidence.length > 0) {
        console.log(chalk.gray(`          Evidence: ${finding.evidence.length} network event(s)`));
      }
      console.log(chalk.cyan(`          → ${finding.recommendation}`));
    }
  }

  console.log(chalk.gray(`    ${report.startedAt} → ${report.endedAt}`));
  console.log('');
}

/** Print the Sentinel upgrade prompt (for free tier) */
export function printSentinelUpgrade(): void {
  console.log('');
  console.log(chalk.bold.hex('#2C4A7C')(`  🛡️  ${SENTINEL_MARKETING.featureName}`));
  console.log(chalk.white(`  ${SENTINEL_MARKETING.tagline}`));
  console.log('');
  for (const cat of SENTINEL_MARKETING.categories) {
    console.log(chalk.white(`    ${cat.icon}  ${chalk.bold(cat.name)}`));
    console.log(chalk.gray(`       ${cat.desc}`));
  }
  console.log('');
  console.log(chalk.yellow(`  ⚡ Sentinel is a Pro feature. Upgrade to unlock runtime monitoring:`));
  console.log(chalk.cyan(`     https://vigile.dev/pricing`));
  console.log('');
  console.log(chalk.gray(`  Pro ($19/mo)       — 5-min sessions, 3 servers`));
  console.log(chalk.gray(`  Team ($99/mo)      — 30-min sessions, 10 servers, real-time alerts`));
  console.log(chalk.gray(`  Enterprise ($999+) — Unlimited, custom rules, SLA`));
  console.log('');
}

// ============================================================
// API Upload & Auth Output
// ============================================================

/** Print auth status info */
export function printAuthStatus(info: {
  authenticated: boolean;
  source?: 'env' | 'config';
  email?: string;
  tier?: string;
  name?: string;
  error?: string;
}): void {
  if (info.authenticated) {
    console.log(chalk.green(`  Authenticated as ${info.email}`));
    console.log(chalk.gray(`    Tier: ${(info.tier || 'free').toUpperCase()}`));
    if (info.name) {
      console.log(chalk.gray(`    Name: ${info.name}`));
    }
    console.log(
      chalk.gray(
        `    Source: ${info.source === 'env' ? 'VIGILE_TOKEN env var' : '~/.vigile/config.json'}`,
      ),
    );
  } else {
    console.log(chalk.yellow('  Not authenticated.'));
    if (info.error) {
      console.log(chalk.red(`    Error: ${info.error}`));
    }
    console.log(chalk.gray('  Run `vigile-scan auth login` or set VIGILE_TOKEN to authenticate.'));
  }
  console.log('');
}

/** Print auth login success */
export function printAuthLoginSuccess(email: string, tier: string): void {
  console.log('');
  console.log(chalk.green('  Authenticated successfully!'));
  console.log(chalk.gray(`    Email: ${email}`));
  console.log(chalk.gray(`    Tier:  ${tier.toUpperCase()}`));
  console.log(chalk.gray('    Token stored in ~/.vigile/config.json'));
  console.log('');
}

/** Print upload success summary */
export function printUploadSuccess(summary: {
  mcpUploaded: number;
  skillsUploaded: number;
  failures: number;
}): void {
  const total = summary.mcpUploaded + summary.skillsUploaded;
  if (total > 0) {
    console.log(chalk.green(`  Uploaded ${total} result(s) to Vigile registry.`));
    if (summary.mcpUploaded > 0) {
      console.log(chalk.gray(`    MCP servers: ${summary.mcpUploaded}`));
    }
    if (summary.skillsUploaded > 0) {
      console.log(chalk.gray(`    Skills: ${summary.skillsUploaded}`));
    }
  }
  if (summary.failures > 0) {
    console.log(chalk.yellow(`  ${summary.failures} upload(s) failed (results saved locally).`));
  }
  console.log('');
}

/** Print upload skip message (when not authenticated or --no-upload) */
export function printUploadSkipped(reason: 'not-authenticated' | 'no-upload-flag'): void {
  if (reason === 'not-authenticated') {
    console.log(
      chalk.gray('  Tip: Run `vigile-scan auth login` to upload results to the Vigile registry.'),
    );
    console.log('');
  }
  // For --no-upload flag, we stay silent (user explicitly opted out)
}
