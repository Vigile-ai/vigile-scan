// ============================================================
// Vigile CLI — Skill Scanner Engine
// ============================================================
// Analyzes agent skill files (SKILL.md, .mdc rules, CLAUDE.md,
// etc.) for security issues. Scans file content against both
// skill-specific and base detection patterns.

import { ALL_PATTERNS } from './patterns.js';
import { ALL_SKILL_PATTERNS } from './skill-patterns.js';
import type {
  SkillEntry,
  Finding,
  SkillScanResult,
  ScoreBreakdown,
  Severity,
} from '../types/index.js';

/** Severity weights for score deductions */
const SEVERITY_DEDUCTIONS: Record<Severity, number> = {
  critical: 35,
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

/**
 * Scan a single skill file for security issues.
 */
export async function scanSkill(skill: SkillEntry): Promise<SkillScanResult> {
  const findings: Finding[] = [];

  // ── Scan the full content against skill-specific patterns ──
  findings.push(...scanContent(skill.content, 'skill content', ALL_SKILL_PATTERNS));

  // ── Also scan against base MCP patterns (tool poisoning, exfil, etc.) ──
  findings.push(...scanContent(skill.content, 'skill content', ALL_PATTERNS));

  // ── Analyze structural properties of the skill ──
  findings.push(...analyzeStructure(skill));

  // ── Check for MDC-specific issues (Cursor rules) ──
  if (skill.fileType === 'mdc-rule') {
    findings.push(...analyzeMDCRule(skill));
  }

  // Deduplicate findings by ID
  const uniqueFindings = deduplicateFindings(findings);

  // Calculate trust score
  const { score, breakdown } = calculateSkillTrustScore(uniqueFindings, skill);

  const trustLevel =
    score >= 80 ? 'trusted' :
    score >= 60 ? 'caution' :
    score >= 40 ? 'risky' :
    'dangerous';

  return {
    skill,
    trustScore: score,
    scoreBreakdown: breakdown,
    findings: uniqueFindings,
    trustLevel,
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Scan text content against a set of detection patterns.
 */
function scanContent(
  text: string,
  context: string,
  patterns: Array<{ id: string; category: string; severity: Severity; title: string; pattern: RegExp; description: string; recommendation: string }>
): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of patterns) {
    // Reset regex state for global patterns
    pattern.pattern.lastIndex = 0;
    const match = pattern.pattern.exec(text);
    if (match) {
      findings.push({
        id: pattern.id,
        category: pattern.category as Finding['category'],
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
 * Analyze structural properties of a skill file.
 */
function analyzeStructure(skill: SkillEntry): Finding[] {
  const findings: Finding[] = [];
  const content = skill.content;

  // Check for suspiciously large skill files (potential payload hiding)
  if (skill.size > 50_000) {
    findings.push({
      id: 'SK-060',
      category: 'obfuscation',
      severity: 'medium',
      title: 'Unusually large skill file',
      description: `Skill file is ${Math.round(skill.size / 1024)}KB. Large skill files may contain hidden payloads or obfuscated content.`,
      evidence: `File size: ${skill.size} bytes`,
      recommendation: 'Inspect the full file carefully. Large skill files are unusual.',
    });
  }

  // Check for code blocks with suspicious commands
  const codeBlockPattern = /```(?:bash|sh|shell|zsh)?\n([\s\S]*?)```/g;
  let codeMatch;
  while ((codeMatch = codeBlockPattern.exec(content)) !== null) {
    const codeBlock = codeMatch[1];

    // Check for dangerous commands in code blocks
    if (/rm\s+-rf\s+[\/~]|rm\s+-rf\s+\$\{?HOME/.test(codeBlock)) {
      findings.push({
        id: 'SK-061',
        category: 'permission-abuse',
        severity: 'critical',
        title: 'Destructive command in code block',
        description: 'Skill contains a recursive delete command targeting the home or root directory.',
        evidence: codeBlock.substring(0, 200),
        recommendation: 'Do NOT install. This command would delete critical files.',
      });
    }

    // Check for chmod 777 or overly permissive permissions
    if (/chmod\s+(?:777|a\+rwx|\+rwx)/i.test(codeBlock)) {
      findings.push({
        id: 'SK-062',
        category: 'permission-abuse',
        severity: 'high',
        title: 'World-writable permissions set',
        description: 'Skill sets overly permissive file permissions (777/world-writable).',
        evidence: codeBlock.substring(0, 200),
        recommendation: 'Review why world-writable permissions are needed. This is almost always a security risk.',
      });
    }
  }

  // Check for excessive external URLs
  const urlPattern = /https?:\/\/[^\s)>\]"']+/g;
  const urls = content.match(urlPattern) || [];
  const externalUrls = urls.filter(
    (url) =>
      !url.includes('github.com') &&
      !url.includes('npmjs.com') &&
      !url.includes('docs.') &&
      !url.includes('stackoverflow.com')
  );

  if (externalUrls.length > 5) {
    findings.push({
      id: 'SK-063',
      category: 'data-exfiltration',
      severity: 'low',
      title: 'Many external URLs in skill',
      description: `Skill contains ${externalUrls.length} external URLs. Excessive external URLs may indicate data exfiltration endpoints.`,
      evidence: externalUrls.slice(0, 3).join(', '),
      recommendation: 'Review the external URLs to ensure they are all legitimate.',
    });
  }

  // Check for ratio of invisible to visible characters
  const invisibleChars = content.match(/[\u200B-\u200D\uFEFF\u2060-\u2064\u00AD]/g) || [];
  if (invisibleChars.length > 10) {
    findings.push({
      id: 'SK-064',
      category: 'obfuscation',
      severity: 'high',
      title: 'High concentration of invisible characters',
      description: `Skill contains ${invisibleChars.length} invisible Unicode characters that may hide malicious instructions.`,
      evidence: `${invisibleChars.length} invisible characters detected`,
      recommendation: 'Strip invisible characters and compare the before/after content.',
    });
  }

  return findings;
}

/**
 * Analyze Cursor .mdc rule files for specific issues.
 */
function analyzeMDCRule(skill: SkillEntry): Finding[] {
  const findings: Finding[] = [];
  const content = skill.content;

  // MDC files can have frontmatter with glob patterns for auto-attachment
  const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
  if (frontmatterMatch) {
    const frontmatter = frontmatterMatch[1];

    // Check for overly broad glob patterns (auto-attaches to everything)
    if (/globs?:\s*['"]\*\*\/\*['"]/i.test(frontmatter) || /globs?:\s*\*\*\/\*/i.test(frontmatter)) {
      findings.push({
        id: 'SK-070',
        category: 'permission-abuse',
        severity: 'medium',
        title: 'MDC rule attached to all files',
        description: 'This Cursor rule uses a wildcard glob pattern that auto-attaches it to every file. This means its instructions apply universally.',
        evidence: frontmatter.substring(0, 200),
        recommendation: 'Review why this rule needs to apply to all files. Narrow the glob pattern if possible.',
      });
    }

    // Check for alwaysApply
    if (/alwaysApply:\s*true/i.test(frontmatter)) {
      findings.push({
        id: 'SK-071',
        category: 'permission-abuse',
        severity: 'low',
        title: 'MDC rule always applied',
        description: 'This Cursor rule has alwaysApply: true, meaning it runs on every interaction regardless of context.',
        evidence: 'alwaysApply: true',
        recommendation: 'Consider if this rule truly needs to run on every interaction.',
      });
    }
  }

  return findings;
}

/**
 * Calculate trust score for a skill file based on findings.
 */
function calculateSkillTrustScore(
  findings: Finding[],
  skill: SkillEntry
): { score: number; breakdown: ScoreBreakdown } {
  let codeAnalysis = 100;
  let dependencyHealth = 100;
  let permissionSafety = 100;
  let behavioralStability = 100;
  let transparency = 100;

  for (const f of findings) {
    const deduction = SEVERITY_DEDUCTIONS[f.severity];

    switch (f.category) {
      case 'tool-poisoning':
      case 'instruction-injection':
      case 'obfuscation':
        codeAnalysis -= deduction;
        break;
      case 'malware-delivery':
      case 'dependency-risk':
        dependencyHealth -= deduction;
        break;
      case 'permission-abuse':
      case 'data-exfiltration':
      case 'safety-bypass':
        permissionSafety -= deduction;
        break;
      case 'stealth-operations':
      case 'persistence-abuse':
        behavioralStability -= deduction;
        break;
      case 'rug-pull':
        transparency -= deduction;
        break;
    }
  }

  // Clamp all factors to 0-100
  codeAnalysis = Math.max(0, codeAnalysis);
  dependencyHealth = Math.max(0, dependencyHealth);
  permissionSafety = Math.max(0, permissionSafety);
  behavioralStability = Math.max(0, behavioralStability);
  transparency = Math.max(0, transparency);

  // Skill transparency bonuses
  if (skill.scope === 'project') {
    transparency = Math.min(100, transparency + 10); // Local skills are more transparent
  }
  if (skill.fileType === 'skill.md' || skill.fileType === 'mdc-rule') {
    transparency = Math.min(100, transparency + 5); // Structured skill formats
  }

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

/** Remove duplicate findings (same ID) */
function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
}
