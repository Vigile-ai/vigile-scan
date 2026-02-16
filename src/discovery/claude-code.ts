// ============================================================
// Claude Code — MCP Config Discovery
// ============================================================
// Config locations:
//   Global:  ~/.claude.json (mcpServers key)
//   Project: .mcp.json (in cwd)

import { join } from 'path';
import { getHome, tryConfigPaths } from './utils.js';
import type { MCPServerEntry } from '../types/index.js';

export async function discoverClaudeCode(): Promise<MCPServerEntry[]> {
  const home = getHome();

  const paths = [
    join(home, '.claude.json'),
    join(process.cwd(), '.mcp.json'),
  ];

  return tryConfigPaths(paths, 'claude-code');
}
