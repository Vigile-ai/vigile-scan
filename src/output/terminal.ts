// ============================================================
// Vigil CLI — Terminal Output Formatter
// ============================================================
// Pretty-prints scan results with color-coded trust scores
// and categorized findings.

import chalk from 'chalk';
import type { ScanResult, ScanSummary, Finding, TrustLevel, Severity } from '../types/index.js';

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

/** Print the Vigil banner */
export function printBanner(): void {
  console.log('');
  console.log(chalk.bold.hex('#2C4A7C')('  ╦  ╦╦╔═╗╦╦  '));
  console.log(chalk.bold.hex('#2C4A7C')('  ╚╗╔╝║║ ╦║║  '));
  console.log(chalk.bold.hex('#2C4A7C')('   ╚╝ ╩╚═╝╩╩═╝'));
  console.log(chalk.gray('  AI Agent Security Scanner'));
  console.log('');
}

/** Print scan results for a single server */
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
    console.log(chalk.dim('    Score Breakdown:'));
    const b = result.scoreBreakdown;
    console.log(chalk.dim(`      Code Analysis:       ${scoreBar(b.codeAnalysis)} ${b.codeAnalysis}/100 (30%)`));
    console.log(chalk.dim(`      Dependency Health:    ${scoreBar(b.dependencyHealth)} ${b.dependencyHealth}/100 (20%)`));
    console.log(chalk.dim(`      Permission Safety:    ${scoreBar(b.permissionSafety)} ${b.permissionSafety}/100 (20%)`));
    console.log(chalk.dim(`      Behavioral Stability: ${scoreBar(b.behavioralStability)} ${b.behavioralStability}/100 (15%)`));
    console.log(chalk.dim(`      Transparency:         ${scoreBar(b.transparency)} ${b.transparency}/100 (15%)`));
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

/** Print the overall scan summary */
export function printSummary(summary: ScanSummary): void {
  console.log(chalk.bold('  ─── Scan Summary ───'));
  console.log('');
  console.log(`  Servers scanned: ${chalk.bold(String(summary.totalServers))}`);
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
  console.log(chalk.gray(`  Vigil v${summary.version} — https://vigil.ai`));
  console.log('');
}

/** Print "no servers found" message */
export function printNoServersFound(): void {
  console.log(chalk.yellow('  No MCP server configurations found on this machine.'));
  console.log('');
  console.log(chalk.gray('  Vigil checks the following locations:'));
  console.log(chalk.gray('    • Claude Desktop config'));
  console.log(chalk.gray('    • Cursor MCP config'));
  console.log(chalk.gray('    • Claude Code config (.claude.json / .mcp.json)'));
  console.log(chalk.gray('    • Windsurf MCP config'));
  console.log(chalk.gray('    • VS Code MCP config (.vscode/mcp.json)'));
  console.log('');
  console.log(chalk.gray('  If you have MCP servers configured elsewhere, use:'));
  console.log(chalk.cyan('    vigil-scan --config /path/to/config.json'));
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
