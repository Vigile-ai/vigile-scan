// ============================================================
// Cursor — MCP Config Discovery
// ============================================================
// Config locations:
//   Global:  ~/.cursor/mcp.json
//   Project: .cursor/mcp.json (in cwd)

import { join } from 'path';
import { getHome, tryConfigPaths } from './utils.js';
import type { MCPServerEntry } from '../types/index.js';

export async function discoverCursor(): Promise<MCPServerEntry[]> {
  const home = getHome();

  const paths = [
    join(home, '.cursor', 'mcp.json'),
    join(process.cwd(), '.cursor', 'mcp.json'),
  ];

  return tryConfigPaths(paths, 'cursor');
}
