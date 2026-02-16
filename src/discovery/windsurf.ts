// ============================================================
// Windsurf — MCP Config Discovery
// ============================================================
// Config locations:
//   macOS/Linux: ~/.codeium/windsurf/mcp_config.json
//   Windows:     %USERPROFILE%\.codeium\windsurf\mcp_config.json

import { join } from 'path';
import { getHome, tryConfigPaths } from './utils.js';
import type { MCPServerEntry } from '../types/index.js';

export async function discoverWindsurf(): Promise<MCPServerEntry[]> {
  const home = getHome();

  const paths = [
    join(home, '.codeium', 'windsurf', 'mcp_config.json'),
  ];

  return tryConfigPaths(paths, 'windsurf');
}
