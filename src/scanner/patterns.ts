// ============================================================
// Vigile CLI — Detection Patterns
// ============================================================
// These patterns detect known attack vectors in MCP server
// tool descriptions and configurations. Based on real-world
// attacks documented by Invariant Labs, OWASP MCP Top 10,
// and the broader AI security research community.

import type { Severity, FindingCategory } from '../types/index.js';

export interface DetectionPattern {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  /** Regex pattern to match against */
  pattern: RegExp;
  /** Human-readable description */
  description: string;
  /** What the user should do */
  recommendation: string;
}

// ──────────────────────────────────────────────────────────
// TOOL POISONING PATTERNS
// Detect hidden instructions embedded in tool descriptions
// that manipulate the AI agent's behavior.
// ──────────────────────────────────────────────────────────

export const TOOL_POISONING_PATTERNS: DetectionPattern[] = [
  {
    id: 'TP-001',
    category: 'tool-poisoning',
    severity: 'critical',
    title: 'Prompt override instruction detected',
    pattern: /ignore\s+(all\s+)?previous\s+instructions/i,
    description:
      'Tool description contains instructions to override the AI agent\'s system prompt. This is a classic prompt injection attack.',
    recommendation:
      'Do NOT install this MCP server. This is a known attack pattern.',
  },
  {
    id: 'TP-002',
    category: 'tool-poisoning',
    severity: 'critical',
    title: 'Hidden agent manipulation',
    pattern: /do\s+not\s+tell\s+the\s+user/i,
    description:
      'Tool description instructs the AI agent to hide information from the user — a hallmark of tool poisoning.',
    recommendation:
      'Do NOT install this MCP server. Legitimate tools never instruct agents to hide actions.',
  },
  {
    id: 'TP-003',
    category: 'tool-poisoning',
    severity: 'critical',
    title: 'System prompt override attempt',
    pattern: /you\s+are\s+(now\s+)?(a|an|acting\s+as)/i,
    description:
      'Tool description attempts to redefine the AI agent\'s identity or role.',
    recommendation:
      'Remove this MCP server. Tool descriptions should not redefine agent behavior.',
  },
  {
    id: 'TP-004',
    category: 'tool-poisoning',
    severity: 'high',
    title: 'Cross-tool instruction injection',
    pattern: /(before|after|instead\s+of)\s+(using|calling|invoking)\s+(this|any|other|the)\s+tool/i,
    description:
      'Tool description tries to influence how other tools are called — a cross-origin escalation pattern.',
    recommendation:
      'Review carefully. This tool may be trying to shadow or intercept other tool calls.',
  },
  {
    id: 'TP-005',
    category: 'tool-poisoning',
    severity: 'high',
    title: 'Instruction to call specific tool',
    pattern: /(always|must|should)\s+(first\s+)?(call|use|invoke|run)\s+[\w-]+\s+(tool|function|command)/i,
    description:
      'Tool description mandates calling a specific other tool, which could be used to chain attacks.',
    recommendation:
      'Verify that the referenced tool is legitimate and necessary.',
  },
  {
    id: 'TP-006',
    category: 'tool-poisoning',
    severity: 'high',
    title: 'Hidden text block detected',
    pattern: /\n{5,}.*\n{5,}/s,
    description:
      'Tool description contains large blocks of whitespace that may hide instructions from casual review.',
    recommendation:
      'Inspect the full tool description carefully for hidden content.',
  },
  {
    id: 'TP-007',
    category: 'tool-poisoning',
    severity: 'medium',
    title: 'System prompt reference',
    pattern: /system\s*prompt|system\s*message|system\s*instruction/i,
    description:
      'Tool description references system prompts, which may indicate an attempt to manipulate agent behavior.',
    recommendation:
      'Review the context. Legitimate tools rarely reference system prompts.',
  },
  {
    id: 'TP-008',
    category: 'tool-poisoning',
    severity: 'medium',
    title: 'Instruction to keep secrets',
    pattern: /(keep|this\s+is)\s+(a\s+)?secret|don'?t\s+(mention|reveal|disclose|share)/i,
    description:
      'Tool description instructs the agent to keep information secret from the user.',
    recommendation:
      'Legitimate tools don\'t ask agents to hide information. Review carefully.',
  },
];

// ──────────────────────────────────────────────────────────
// DATA EXFILTRATION PATTERNS
// Detect attempts to steal sensitive data through tool
// descriptions that reference credential files, env vars,
// or suspicious external URLs.
// ──────────────────────────────────────────────────────────

export const EXFILTRATION_PATTERNS: DetectionPattern[] = [
  {
    id: 'EX-001',
    category: 'data-exfiltration',
    severity: 'critical',
    title: 'SSH key access pattern',
    pattern: /\.ssh\/(id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts|config)/i,
    description:
      'Tool references SSH key files. This matches the Invariant Labs attack where SSH keys were exfiltrated from Claude Desktop.',
    recommendation:
      'CRITICAL: Remove immediately. No legitimate MCP tool needs access to SSH keys.',
  },
  {
    id: 'EX-002',
    category: 'data-exfiltration',
    severity: 'critical',
    title: 'AWS credential access',
    pattern: /\.aws\/(credentials|config)|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID/i,
    description:
      'Tool references AWS credential files or environment variables.',
    recommendation:
      'Remove immediately unless this is a verified AWS management tool.',
  },
  {
    id: 'EX-003',
    category: 'data-exfiltration',
    severity: 'critical',
    title: 'Environment file access',
    pattern: /\.(env|env\.local|env\.production|env\.development)\b/i,
    description:
      'Tool references .env files which typically contain API keys and secrets.',
    recommendation:
      'Review why this tool needs access to environment files.',
  },
  {
    id: 'EX-004',
    category: 'data-exfiltration',
    severity: 'high',
    title: 'Credential file access pattern',
    pattern: /(credentials|secrets|tokens|passwords|api[_-]?keys)\.(json|yaml|yml|txt|cfg|ini|conf)/i,
    description:
      'Tool references files commonly used to store credentials.',
    recommendation:
      'Verify this tool has a legitimate reason to access credential files.',
  },
  {
    id: 'EX-005',
    category: 'data-exfiltration',
    severity: 'high',
    title: 'Suspicious external URL',
    pattern: /https?:\/\/(?!(?:github\.com|npmjs\.com|registry\.npmjs\.org|pypi\.org|api\.github\.com))[a-z0-9][-a-z0-9]*\.[a-z]{2,}\/(collect|track|log|beacon|webhook|exfil|receive|data|upload|report)/i,
    description:
      'Tool description contains a URL pointing to a data collection endpoint.',
    recommendation:
      'Investigate the URL. This may be a data exfiltration endpoint.',
  },
  {
    id: 'EX-006',
    category: 'data-exfiltration',
    severity: 'high',
    title: 'Cryptocurrency wallet access',
    pattern: /(\.bitcoin|\.ethereum|wallet\.dat|\.solana|seed\s*phrase|private\s*key|keystore)/i,
    description:
      'Tool references cryptocurrency wallet files or seed phrases. Matches the malicious OpenClaw skills pattern.',
    recommendation:
      'CRITICAL: Remove immediately unless this is a verified crypto tool.',
  },
  {
    id: 'EX-007',
    category: 'data-exfiltration',
    severity: 'medium',
    title: 'Browser data access',
    pattern: /(cookies|local\s*storage|session\s*storage|browser\s*history|bookmarks|saved\s*passwords)/i,
    description:
      'Tool references browser data stores.',
    recommendation:
      'Review why this tool needs access to browser data.',
  },
];

// ──────────────────────────────────────────────────────────
// PERMISSION ABUSE PATTERNS
// Detect tools requesting excessive or suspicious permissions.
// ──────────────────────────────────────────────────────────

export const PERMISSION_PATTERNS: DetectionPattern[] = [
  {
    id: 'PM-001',
    category: 'permission-abuse',
    severity: 'high',
    title: 'Code execution capability',
    pattern: /\b(eval|exec|spawn|child_process|subprocess|os\.system|os\.popen)\b/i,
    description:
      'Tool has code execution capabilities which could be used to run arbitrary commands.',
    recommendation:
      'Ensure this tool\'s code execution is properly sandboxed.',
  },
  {
    id: 'PM-002',
    category: 'permission-abuse',
    severity: 'high',
    title: 'Unrestricted filesystem access',
    pattern: /\b(readFile|writeFile|readdir|rmdir|unlink|fs\.|filesystem|file\s*system)\b.*\b(any|all|entire|root|\/)\b/i,
    description:
      'Tool claims unrestricted filesystem access.',
    recommendation:
      'Tools should have scoped filesystem access, not unrestricted.',
  },
  {
    id: 'PM-003',
    category: 'permission-abuse',
    severity: 'medium',
    title: 'Network request capability',
    pattern: /\b(fetch|axios|http\.request|urllib|requests\.get|requests\.post|curl|wget)\b/i,
    description:
      'Tool makes network requests. Legitimate in many cases, but could be used for data exfiltration.',
    recommendation:
      'Verify the tool\'s network targets are expected and safe.',
  },
  {
    id: 'PM-004',
    category: 'permission-abuse',
    severity: 'medium',
    title: 'Sensitive path access',
    pattern: /\/etc\/(passwd|shadow|hosts|sudoers)|\/root\/|~\/\./,
    description:
      'Tool accesses system-sensitive paths.',
    recommendation:
      'Review why this tool needs access to system files.',
  },
];

// ──────────────────────────────────────────────────────────
// OBFUSCATION PATTERNS
// Detect attempts to hide malicious content through encoding
// or unicode tricks.
// ──────────────────────────────────────────────────────────

export const OBFUSCATION_PATTERNS: DetectionPattern[] = [
  {
    id: 'OB-001',
    category: 'obfuscation',
    severity: 'high',
    title: 'Base64 encoded content',
    pattern: /[A-Za-z0-9+/]{40,}={0,2}/,
    description:
      'Tool description contains what appears to be base64-encoded content, which may hide malicious instructions.',
    recommendation:
      'Decode the base64 content and inspect it before using this tool.',
  },
  {
    id: 'OB-002',
    category: 'obfuscation',
    severity: 'high',
    title: 'Zero-width characters detected',
    pattern: /[\u200B\u200C\u200D\uFEFF\u2060\u2061\u2062\u2063\u2064]/,
    description:
      'Tool description contains invisible zero-width Unicode characters that may hide content.',
    recommendation:
      'Strip zero-width characters and inspect the resulting text.',
  },
  {
    id: 'OB-003',
    category: 'obfuscation',
    severity: 'medium',
    title: 'Hex-encoded string',
    pattern: /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){4,}/,
    description:
      'Tool description contains hex-encoded strings that may hide instructions.',
    recommendation:
      'Decode the hex content and inspect it.',
  },
  {
    id: 'OB-004',
    category: 'obfuscation',
    severity: 'medium',
    title: 'Unicode escape sequences',
    pattern: /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){4,}/,
    description:
      'Tool description contains Unicode escape sequences that may hide content.',
    recommendation:
      'Decode the Unicode escapes and inspect the resulting text.',
  },
];

/** All detection patterns combined */
export const ALL_PATTERNS: DetectionPattern[] = [
  ...TOOL_POISONING_PATTERNS,
  ...EXFILTRATION_PATTERNS,
  ...PERMISSION_PATTERNS,
  ...OBFUSCATION_PATTERNS,
];
