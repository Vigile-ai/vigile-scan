// ============================================================
// Vigil CLI — Type Definitions
// ============================================================

/** Supported IDE/tool that can have MCP configurations */
export type MCPClient =
  | 'claude-desktop'
  | 'cursor'
  | 'claude-code'
  | 'windsurf'
  | 'vscode'
  | 'gemini-cli';

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
  | 'obfuscation';

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
  /** Servers by trust level */
  byTrustLevel: Record<TrustLevel, number>;
  /** Total findings by severity */
  bySeverity: Record<Severity, number>;
  /** Individual scan results */
  results: ScanResult[];
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
}
