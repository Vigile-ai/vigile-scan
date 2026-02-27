// ============================================================
// Vigile CLI — Type Definitions
// ============================================================

/** Supported IDE/tool that can have MCP configurations */
export type MCPClient =
  | 'claude-desktop'
  | 'cursor'
  | 'claude-code'
  | 'windsurf'
  | 'vscode'
  | 'openclaw';

/** An MCP server entry discovered from a config file */
export interface MCPServerEntry {
  /** Human-readable server name (the key in mcpServers) */
  name: string;
  /** Which IDE/tool this was discovered from */
  source: MCPClient;
  /** Command to start the server (e.g., "npx", "node", "python") */
  command: string;
  /** Arguments passed to the command */
  args: string[];
  /** Environment variables */
  env?: Record<string, string>;
  /** Path to the config file where this was found */
  configPath: string;
}

/** Severity levels for security findings */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Categories of security findings */
export type FindingCategory =
  | 'tool-poisoning'
  | 'permission-abuse'
  | 'data-exfiltration'
  | 'dependency-risk'
  | 'rug-pull'
  | 'obfuscation'
  | 'instruction-injection'
  | 'malware-delivery'
  | 'stealth-operations'
  | 'safety-bypass'
  | 'persistence-abuse'
  // Sentinel (runtime monitoring) categories
  | 'c2-beaconing'
  | 'dns-tunneling'
  | 'covert-channel'
  | 'phone-home';

/** A single security finding from scanning */
export interface Finding {
  /** Unique finding ID (e.g., "TP-001") */
  id: string;
  /** Category of the finding */
  category: FindingCategory;
  /** Severity level */
  severity: Severity;
  /** Short title */
  title: string;
  /** Detailed description of what was found */
  description: string;
  /** The specific evidence (e.g., the suspicious string) */
  evidence?: string;
  /** Recommendation for remediation */
  recommendation: string;
}

/** Results from scanning a single MCP server */
export interface ScanResult {
  /** The server that was scanned */
  server: MCPServerEntry;
  /** Trust score (0-100) */
  trustScore: number;
  /** Score breakdown by factor */
  scoreBreakdown: ScoreBreakdown;
  /** Security findings */
  findings: Finding[];
  /** Trust level label */
  trustLevel: TrustLevel;
  /** Scan timestamp */
  scannedAt: string;
}

/** Trust score breakdown by weighted factor */
export interface ScoreBreakdown {
  /** Code analysis score (0-100, weight: 30%) */
  codeAnalysis: number;
  /** Dependency health score (0-100, weight: 20%) */
  dependencyHealth: number;
  /** Permission safety score (0-100, weight: 20%) */
  permissionSafety: number;
  /** Behavioral stability score (0-100, weight: 15%) */
  behavioralStability: number;
  /** Transparency score (0-100, weight: 15%) */
  transparency: number;
}

/** Trust level derived from score */
export type TrustLevel = 'trusted' | 'caution' | 'risky' | 'dangerous';

/** Overall scan summary */
export interface ScanSummary {
  /** Total servers scanned */
  totalServers: number;
  /** Total skills scanned */
  totalSkills: number;
  /** Servers by trust level */
  byTrustLevel: Record<TrustLevel, number>;
  /** Total findings by severity */
  bySeverity: Record<Severity, number>;
  /** Individual MCP scan results */
  results: ScanResult[];
  /** Individual skill scan results */
  skillResults: SkillScanResult[];
  /** When the scan was performed */
  timestamp: string;
  /** Scanner version */
  version: string;
}

/** CLI options */
export interface ScanOptions {
  /** Output as JSON */
  json?: boolean;
  /** Verbose output */
  verbose?: boolean;
  /** Custom config path */
  config?: string;
  /** Output to file */
  output?: string;
  /** Only scan specific client */
  client?: MCPClient;
  /** Scan skills only (SKILL.md, .mdc, CLAUDE.md, etc.) */
  skills?: boolean;
  /** Scan both MCP servers and skills */
  all?: boolean;
  /** Enable Sentinel runtime monitoring (Pro+ feature) */
  sentinel?: boolean;
  /** Sentinel: specific server to monitor */
  sentinelServer?: string;
  /** Sentinel: monitoring duration in seconds */
  sentinelDuration?: number;
  /** Skip uploading scan results to Vigile API */
  noUpload?: boolean;
}

// ============================================================
// Skill Scanning Types
// ============================================================

/** Sources where agent skills can be discovered */
export type SkillSource =
  | 'claude-code'
  | 'github-copilot'
  | 'cursor'
  | 'memory-file'
  | 'custom';

/** Types of skill files */
export type SkillFileType =
  | 'skill.md'
  | 'mdc-rule'
  | 'claude.md'
  | 'soul.md'
  | 'memory.md';

/** A discovered agent skill file */
export interface SkillEntry {
  /** Skill name (derived from directory or file name) */
  name: string;
  /** Where this skill was discovered */
  source: SkillSource;
  /** Type of skill file */
  fileType: SkillFileType;
  /** Absolute path to the skill file */
  filePath: string;
  /** Raw content of the skill file */
  content: string;
  /** File size in bytes */
  size: number;
  /** Whether the skill is project-local or global */
  scope: 'project' | 'global';
}

/** Results from scanning a single skill file */
export interface SkillScanResult {
  /** The skill that was scanned */
  skill: SkillEntry;
  /** Trust score (0-100) */
  trustScore: number;
  /** Score breakdown by factor */
  scoreBreakdown: ScoreBreakdown;
  /** Security findings */
  findings: Finding[];
  /** Trust level label */
  trustLevel: TrustLevel;
  /** Scan timestamp */
  scannedAt: string;
}

/** Discovery result for skills */
export interface SkillDiscoveryResult {
  skills: SkillEntry[];
  locationsChecked: number;
  locationsFound: number;
  errors: Array<{ source: SkillSource; error: string }>;
}

// ============================================================
// API Upload Types
// ============================================================

/** Summary of API upload results */
export interface UploadSummary {
  /** Number of MCP scan results uploaded */
  mcpUploaded: number;
  /** Number of skill scan results uploaded */
  skillsUploaded: number;
  /** Number of upload failures */
  failures: number;
  /** Error messages from failures */
  errors: string[];
}
