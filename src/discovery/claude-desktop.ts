// ============================================================
// Claude Desktop — MCP Config Discovery
// ============================================================
// Config locations (as of February 2026):
//   macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json
//   Windows: %APPDATA%\Claude\claude_desktop_config.json
//   Linux:   ~/.config/Claude/claude_desktop_config.json

import { join } from 'path';
import { getHome, getPlatform, getAppData, tryConfigPaths } from './utils.js';
import type { MCPServerEntry } from '../types/index.js';

export async function discoverClaudeDesktop(): Promise<MCPServerEntry[]> {
  const home = getHome();
  const plat = getPlatform();

  const paths: string[] = [];

  switch (plat) {
    case 'darwin':
      paths.push(
        join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
      );
      break;
    case 'win32':
      paths.push(join(getAppData(), 'Claude', 'claude_desktop_config.json'));
      break;
    case 'linux':
      paths.push(join(home, '.config', 'Claude', 'claude_desktop_config.json'));
      break;
  }

  return tryConfigPaths(paths, 'claude-desktop');
}
