// ============================================================
// Vigile CLI — MCP Config Discovery Orchestrator
// ============================================================
// Auto-discovers MCP server configurations across all supported
// AI tools on the user's machine. Supports macOS, Windows, Linux.

import { discoverClaudeDesktop } from './claude-desktop.js';
import { discoverCursor } from './cursor.js';
import { discoverClaudeCode } from './claude-code.js';
import { discoverWindsurf } from './windsurf.js';
import { discoverVSCode } from './vscode.js';
import type { MCPServerEntry, MCPClient } from '../types/index.js';

// Re-export skill discovery for use in CLI
export { discoverAllSkills } from './skills.js';

export interface DiscoveryResult {
  servers: MCPServerEntry[];
  configsChecked: number;
  configsFound: number;
  errors: Array<{ client: MCPClient; error: string }>;
}

/**
 * Discover all MCP server configurations on this machine.
 * Checks all known IDE/tool config locations for the current OS.
 */
export async function discoverAllServers(
  clientFilter?: MCPClient
): Promise<DiscoveryResult> {
  const discoverers: Array<{
    client: MCPClient;
    fn: () => Promise<MCPServerEntry[]>;
  }> = [
    { client: 'claude-desktop', fn: discoverClaudeDesktop },
    { client: 'cursor', fn: discoverCursor },
    { client: 'claude-code', fn: discoverClaudeCode },
    { client: 'windsurf', fn: discoverWindsurf },
    { client: 'vscode', fn: discoverVSCode },
  ];

  // Filter to specific client if requested
  const toRun = clientFilter
    ? discoverers.filter((d) => d.client === clientFilter)
    : discoverers;

  const servers: MCPServerEntry[] = [];
  const errors: Array<{ client: MCPClient; error: string }> = [];
  let configsFound = 0;

  for (const { client, fn } of toRun) {
    try {
      const found = await fn();
      if (found.length > 0) {
        configsFound++;
        servers.push(...found);
      }
    } catch (err) {
      errors.push({
        client,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return {
    servers,
    configsChecked: toRun.length,
    configsFound,
    errors,
  };
}
