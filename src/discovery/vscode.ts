// ============================================================
// VS Code — MCP Config Discovery
// ============================================================
// Config locations:
//   Project: .vscode/mcp.json (in cwd)

import { join } from 'path';
import { tryConfigPaths } from './utils.js';
import type { MCPServerEntry } from '../types/index.js';

export async function discoverVSCode(): Promise<MCPServerEntry[]> {
  const paths = [
    join(process.cwd(), '.vscode', 'mcp.json'),
  ];

  return tryConfigPaths(paths, 'vscode');
}
