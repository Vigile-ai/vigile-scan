// ============================================================
// Vigile CLI — Scanner Engine
// ============================================================
// Analyzes MCP server entries for security issues by examining
// the command, args, env vars, and (where possible) tool
// descriptions against known attack patterns.

import { ALL_PATTERNS } from './patterns.js';
import type { MCPServerEntry, Finding, ScanResult } from '../types/index.js';
import { calculateTrustScore } from '../scoring/trust-score.js';

/**
 * Scan a single MCP server entry for security issues.
 */
export async function scanServer(server: MCPServerEntry): Promise<ScanResult> {
  const findings: Finding[] = [];

  // ── Scan the command and args ──
  const commandStr = `${server.command} ${server.args.join(' ')}`;
  findings.push(...scanText(commandStr, 'command'));

  // ── Scan the server name ──
  findings.push(...scanText(server.name, 'server name'));

  // ── Scan environment variables ──
  if (server.env) {
    for (const [key, value] of Object.entries(server.env)) {
      // Don't flag standard env vars like PATH, NODE_ENV, etc.
      if (isStandardEnvVar(key)) continue;

      // Check for sensitive data in env values
      findings.push(...scanEnvVar(key, value));
    }
  }

  // ── Scan args for suspicious patterns ──
  findings.push(...scanArgs(server.args));

  // ── Analyze command for known risky packages ──
  findings.push(...analyzeCommand(server));

  // Deduplicate findings by ID
  const uniqueFindings = deduplicateFindings(findings);

  // Calculate trust score
  const { score, breakdown } = calculateTrustScore(uniqueFindings, server);

  // Determine trust level
  const trustLevel =
    score >= 80 ? 'trusted' :
    score >= 60 ? 'caution' :
    score >= 40 ? 'risky' :
    'dangerous';

  return {
    server,
    trustScore: score,
    scoreBreakdown: breakdown,
    findings: uniqueFindings,
    trustLevel,
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Scan a text string against all detection patterns.
 */
function scanText(text: string, context: string): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of ALL_PATTERNS) {
    const match = pattern.pattern.exec(text);
    if (match) {
      findings.push({
        id: pattern.id,
        category: pattern.category,
        severity: pattern.severity,
        title: pattern.title,
        description: `${pattern.description} (found in ${context})`,
        evidence: match[0].substring(0, 200),
        recommendation: pattern.recommendation,
      });
    }
  }

  return findings;
}

/**
 * Scan environment variables for sensitive data exposure.
 */
function scanEnvVar(key: string, value: string): Finding[] {
  const findings: Finding[] = [];

  // Check for API keys/tokens being passed in env
  const sensitiveKeyPatterns = [
    /api[_-]?key/i,
    /secret[_-]?key/i,
    /access[_-]?token/i,
    /private[_-]?key/i,
    /password/i,
    /auth[_-]?token/i,
  ];

  for (const pat of sensitiveKeyPatterns) {
    if (pat.test(key)) {
      findings.push({
        id: 'EV-001',
        category: 'data-exfiltration',
        severity: 'medium',
        title: 'Sensitive environment variable',
        description: `The MCP server receives a potentially sensitive environment variable: ${key}. This data is accessible to the server code.`,
        evidence: `${key}=<redacted>`,
        recommendation:
          'Verify this MCP server needs this credential and that you trust it with this access.',
      });
      break;
    }
  }

  // Scan env values against exfiltration patterns too
  findings.push(...scanText(value, `env var ${key}`));

  return findings;
}

/**
 * Scan arguments for suspicious patterns.
 */
function scanArgs(args: string[]): Finding[] {
  const findings: Finding[] = [];
  const argsStr = args.join(' ');

  // Check for suspicious argument patterns
  if (/--allow-all|--no-sandbox|--disable-security/i.test(argsStr)) {
    findings.push({
      id: 'AR-001',
      category: 'permission-abuse',
      severity: 'high',
      title: 'Security bypass flags detected',
      description:
        'The MCP server is started with flags that disable security restrictions.',
      evidence: argsStr.substring(0, 200),
      recommendation:
        'Remove security-bypass flags. These significantly increase risk.',
    });
  }

  // Check for args referencing sensitive paths
  for (const arg of args) {
    if (/\.(ssh|aws|gnupg|config\/gcloud)/.test(arg)) {
      findings.push({
        id: 'AR-002',
        category: 'data-exfiltration',
        severity: 'high',
        title: 'Sensitive directory in arguments',
        description: `An MCP server argument references a sensitive directory: ${arg}`,
        evidence: arg,
        recommendation:
          'Verify this server needs access to this sensitive directory.',
      });
    }
  }

  return findings;
}

/**
 * Analyze the server command for known risky packages.
 */
function analyzeCommand(server: MCPServerEntry): Finding[] {
  const findings: Finding[] = [];
  const fullCommand = `${server.command} ${server.args.join(' ')}`;

  // Check for npx with -y flag (auto-install without confirmation)
  if (server.command === 'npx' && server.args.includes('-y')) {
    findings.push({
      id: 'CM-001',
      category: 'dependency-risk',
      severity: 'low',
      title: 'Auto-install enabled (npx -y)',
      description:
        'This MCP server uses npx with the -y flag, which auto-installs packages without confirmation. This is standard practice but means the package is downloaded and executed automatically.',
      evidence: fullCommand.substring(0, 200),
      recommendation:
        'Verify the package name is correct (watch for typosquatting).',
    });
  }

  // Check for pip/python packages that might be typosquatted
  if (/\b(pip|python|uvx)\b/.test(server.command)) {
    const packageArg = server.args.find(
      (a) => !a.startsWith('-') && !a.startsWith('/') && !a.includes('=')
    );
    if (packageArg) {
      // Basic typosquatting check — flag single-char differences from popular packages
      const popularPackages = [
        'mcp-server-fetch',
        'mcp-server-filesystem',
        'mcp-server-github',
        'mcp-server-sqlite',
        'mcp-server-postgres',
        'mcp-server-slack',
        'mcp-server-memory',
        'mcp-server-puppeteer',
        'mcp-server-brave-search',
        'mcp-server-sequential-thinking',
      ];

      for (const popular of popularPackages) {
        if (
          packageArg !== popular &&
          levenshteinDistance(packageArg, popular) <= 2 &&
          levenshteinDistance(packageArg, popular) > 0
        ) {
          findings.push({
            id: 'CM-002',
            category: 'dependency-risk',
            severity: 'high',
            title: 'Possible typosquatting detected',
            description: `Package "${packageArg}" is very similar to the popular package "${popular}". This could be a typosquatting attack.`,
            evidence: `${packageArg} ≈ ${popular}`,
            recommendation: `Verify you intended to install "${packageArg}" and not "${popular}".`,
          });
        }
      }
    }
  }

  return findings;
}

/** Simple Levenshtein distance for typosquatting detection */
function levenshteinDistance(a: string, b: string): number {
  const matrix = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      matrix[i][j] =
        a[i - 1] === b[j - 1]
          ? matrix[i - 1][j - 1]
          : 1 + Math.min(matrix[i - 1][j], matrix[i][j - 1], matrix[i - 1][j - 1]);
    }
  }

  return matrix[a.length][b.length];
}

/** Check if an env var name is standard/non-sensitive */
function isStandardEnvVar(key: string): boolean {
  const standard = new Set([
    'PATH',
    'HOME',
    'USER',
    'SHELL',
    'LANG',
    'LC_ALL',
    'NODE_ENV',
    'DEBUG',
    'LOG_LEVEL',
    'PORT',
    'HOST',
    'HOSTNAME',
    'TZ',
    'TERM',
    'EDITOR',
    'VISUAL',
    'TMPDIR',
    'TEMP',
    'TMP',
  ]);
  return standard.has(key);
}

/** Remove duplicate findings (same ID) */
function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
}
