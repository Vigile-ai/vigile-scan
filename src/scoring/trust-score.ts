// ============================================================
// Vigil CLI — Trust Score Calculator
// ============================================================
// Calculates a 0-100 trust score based on weighted factors.
// For CLI v1, we focus on what we can analyze locally:
//   - Code Analysis (30%): Findings from pattern scanning
//   - Dependency Health (20%): Package source and age signals
//   - Permission Safety (20%): How much access the tool requests
//   - Behavioral Stability (15%): Command stability signals
//   - Transparency (15%): Open source, known package, etc.

import type { Finding, MCPServerEntry, ScoreBreakdown, Severity } from '../types/index.js';

interface ScoreResult {
  score: number;
  breakdown: ScoreBreakdown;
}

/** Severity weights for score deductions */
const SEVERITY_DEDUCTIONS: Record<Severity, number> = {
  critical: 35,
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

/**
 * Calculate trust score for an MCP server based on scan findings.
 */
export function calculateTrustScore(
  findings: Finding[],
  server: MCPServerEntry
): ScoreResult {
  // Start each factor at 100 and deduct based on findings
  let codeAnalysis = 100;
  let dependencyHealth = 100;
  let permissionSafety = 100;
  let behavioralStability = 100;
  let transparency = 100;

  // ── Deduct from Code Analysis based on poisoning/obfuscation findings ──
  for (const f of findings) {
    if (f.category === 'tool-poisoning' || f.category === 'obfuscation') {
      codeAnalysis -= SEVERITY_DEDUCTIONS[f.severity];
    }
  }
  codeAnalysis = Math.max(0, codeAnalysis);

  // ── Deduct from Dependency Health based on dependency findings ──
  for (const f of findings) {
    if (f.category === 'dependency-risk') {
      dependencyHealth -= SEVERITY_DEDUCTIONS[f.severity];
    }
  }

  // Boost dependency health for well-known package sources
  if (isWellKnownPackage(server)) {
    dependencyHealth = Math.min(100, dependencyHealth + 15);
  }
  dependencyHealth = Math.max(0, dependencyHealth);

  // ── Deduct from Permission Safety based on permission/exfil findings ──
  for (const f of findings) {
    if (
      f.category === 'permission-abuse' ||
      f.category === 'data-exfiltration'
    ) {
      permissionSafety -= SEVERITY_DEDUCTIONS[f.severity];
    }
  }
  permissionSafety = Math.max(0, permissionSafety);

  // ── Behavioral Stability ──
  // In CLI v1, we use command structure as a proxy
  // npx/uvx commands are less stable (can change), local paths are more stable
  if (server.command === 'npx' || server.command === 'uvx') {
    behavioralStability -= 10; // Slight deduction for remote packages
  }
  if (server.command === 'node' || server.command === 'python' || server.command === 'python3') {
    behavioralStability += 5; // Local execution is more predictable
  }
  behavioralStability = Math.max(0, Math.min(100, behavioralStability));

  // ── Transparency ──
  // Check for signals of transparency
  if (isOpenSourcePackage(server)) {
    transparency = Math.min(100, transparency + 10);
  }
  // Deduct for unknown/untraceable sources
  if (!isWellKnownPackage(server) && server.command !== 'node' && server.command !== 'python') {
    transparency -= 20;
  }
  transparency = Math.max(0, Math.min(100, transparency));

  // ── Calculate weighted score ──
  const breakdown: ScoreBreakdown = {
    codeAnalysis,
    dependencyHealth,
    permissionSafety,
    behavioralStability,
    transparency,
  };

  const score = Math.round(
    codeAnalysis * 0.30 +
    dependencyHealth * 0.20 +
    permissionSafety * 0.20 +
    behavioralStability * 0.15 +
    transparency * 0.15
  );

  return { score: Math.max(0, Math.min(100, score)), breakdown };
}

/** Check if the server uses a well-known package */
function isWellKnownPackage(server: MCPServerEntry): boolean {
  const wellKnown = [
    '@modelcontextprotocol/',
    '@anthropic-ai/',
    'mcp-server-',
    '@mcp/',
  ];

  const packageName = server.args[0] || '';
  // Remove -y flag to get actual package name
  const name = server.args.find(a => !a.startsWith('-')) || '';

  return wellKnown.some(
    (prefix) => packageName.startsWith(prefix) || name.startsWith(prefix)
  );
}

/** Check if the server appears to be from an open source package */
function isOpenSourcePackage(server: MCPServerEntry): boolean {
  // npx packages are on npm (public), uvx are on PyPI (public)
  return ['npx', 'uvx', 'pip', 'pipx'].includes(server.command);
}
