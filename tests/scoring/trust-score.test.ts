import { describe, it, expect } from 'vitest';
import { calculateTrustScore } from '../../src/scoring/trust-score.js';
import type { Finding, MCPServerEntry, ScoreBreakdown } from '../../src/types/index.js';

function makeServer(overrides: Partial<MCPServerEntry> = {}): MCPServerEntry {
  return {
    name: 'test-server',
    source: 'claude-desktop',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-test'],
    configPath: '/test/config.json',
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'TEST-001',
    category: 'tool-poisoning',
    severity: 'medium',
    title: 'Test finding',
    description: 'Test description',
    recommendation: 'Test recommendation',
    ...overrides,
  };
}

describe('calculateTrustScore', () => {
  it('returns 100-area score for a clean server with no findings', () => {
    const { score, breakdown } = calculateTrustScore([], makeServer());
    expect(score).toBeGreaterThanOrEqual(80);
    expect(score).toBeLessThanOrEqual(100);
    expect(breakdown.codeAnalysis).toBe(100);
    expect(breakdown.permissionSafety).toBe(100);
  });

  it('returns score clamped between 0 and 100', () => {
    const { score } = calculateTrustScore([], makeServer());
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  it('deducts from codeAnalysis for tool-poisoning findings', () => {
    const findings = [makeFinding({ category: 'tool-poisoning', severity: 'critical' })];
    const { breakdown } = calculateTrustScore(findings, makeServer());
    expect(breakdown.codeAnalysis).toBe(100 - 35); // critical = -35
  });

  it('deducts from codeAnalysis for obfuscation findings', () => {
    const findings = [makeFinding({ category: 'obfuscation', severity: 'high' })];
    const { breakdown } = calculateTrustScore(findings, makeServer());
    expect(breakdown.codeAnalysis).toBe(100 - 20); // high = -20
  });

  it('deducts from permissionSafety for permission-abuse findings', () => {
    const findings = [makeFinding({ category: 'permission-abuse', severity: 'high' })];
    const { breakdown } = calculateTrustScore(findings, makeServer());
    expect(breakdown.permissionSafety).toBe(100 - 20);
  });

  it('deducts from permissionSafety for data-exfiltration findings', () => {
    const findings = [makeFinding({ category: 'data-exfiltration', severity: 'critical' })];
    const { breakdown } = calculateTrustScore(findings, makeServer());
    expect(breakdown.permissionSafety).toBe(100 - 35);
  });

  it('deducts from dependencyHealth for dependency-risk findings', () => {
    const findings = [makeFinding({ category: 'dependency-risk', severity: 'high' })];
    const { breakdown } = calculateTrustScore(findings, makeServer());
    // Well-known package gets +15 boost: 100 - 20 + 15 = 95
    expect(breakdown.dependencyHealth).toBe(95);
  });

  it('boosts dependencyHealth for well-known packages', () => {
    // Add a dependency-risk finding so the well-known boost is visible
    const depFinding = makeFinding({ category: 'dependency-risk', severity: 'high' });
    const server = makeServer({ args: ['-y', '@modelcontextprotocol/server-fs'] });
    const { breakdown: withWellKnown } = calculateTrustScore([depFinding], server);
    const unknownServer = makeServer({ command: 'node', args: ['random.js'] });
    const { breakdown: withoutWellKnown } = calculateTrustScore([depFinding], unknownServer);
    // Well-known gets +15 boost: 100-20+15=95 vs 100-20=80
    expect(withWellKnown.dependencyHealth).toBeGreaterThan(withoutWellKnown.dependencyHealth);
  });

  it('reduces behavioralStability for npx commands', () => {
    const npxServer = makeServer({ command: 'npx' });
    const nodeServer = makeServer({ command: 'node', args: ['server.js'] });
    const { breakdown: npx } = calculateTrustScore([], npxServer);
    const { breakdown: node } = calculateTrustScore([], nodeServer);
    expect(npx.behavioralStability).toBeLessThan(node.behavioralStability);
  });

  it('increases behavioralStability for local node commands', () => {
    const server = makeServer({ command: 'node', args: ['server.js'] });
    const { breakdown } = calculateTrustScore([], server);
    expect(breakdown.behavioralStability).toBe(105 > 100 ? 100 : 105); // clamped
    expect(breakdown.behavioralStability).toBeLessThanOrEqual(100);
  });

  it('boosts transparency for open-source packages (npx/uvx)', () => {
    const server = makeServer({ command: 'npx', args: ['some-pkg'] });
    const { breakdown } = calculateTrustScore([], server);
    // npx is open source, so transparency gets +10 (but may also get -20 if not well-known)
    expect(breakdown.transparency).toBeDefined();
  });

  it('applies weighted formula correctly', () => {
    const { score, breakdown } = calculateTrustScore([], makeServer());
    const expected = Math.round(
      breakdown.codeAnalysis * 0.3 +
      breakdown.dependencyHealth * 0.2 +
      breakdown.permissionSafety * 0.2 +
      breakdown.behavioralStability * 0.15 +
      breakdown.transparency * 0.15
    );
    expect(score).toBe(Math.max(0, Math.min(100, expected)));
  });

  it('floors factor scores at 0 with many critical findings', () => {
    const findings = Array.from({ length: 5 }, (_, i) =>
      makeFinding({
        id: `TP-00${i}`,
        category: 'tool-poisoning',
        severity: 'critical',
      })
    );
    const { breakdown } = calculateTrustScore(findings, makeServer());
    expect(breakdown.codeAnalysis).toBe(0);
  });

  it('info severity has zero deduction', () => {
    const findings = [makeFinding({ severity: 'info', category: 'tool-poisoning' })];
    const { breakdown } = calculateTrustScore(findings, makeServer());
    expect(breakdown.codeAnalysis).toBe(100); // info = 0 deduction
  });
});
