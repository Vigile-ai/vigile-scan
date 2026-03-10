// ============================================================
// Claude Code — MCP Config Discovery
// ============================================================
// Config locations:
//   Global:  ~/.claude.json (mcpServers key)
//   Project: .mcp.json (in cwd)
//   Plugins: ~/.claude/plugins/cache/claude-plugins-official/<name>/<version>/.mcp.json

import { join } from 'path';
import { readdirSync, existsSync, Dirent } from 'fs';
import { getHome, tryConfigPaths, parseMCPConfig } from './utils.js';
import type { MCPServerEntry } from '../types/index.js';

export async function discoverClaudeCode(): Promise<MCPServerEntry[]> {
  const home = getHome();
  const allServers: MCPServerEntry[] = [];

  // 1. Traditional config paths (global + project-local)
  const traditionalPaths = [
    join(home, '.claude.json'),
    join(process.cwd(), '.mcp.json'),
  ];
  allServers.push(...await tryConfigPaths(traditionalPaths, 'claude-code'));

  // 2. Claude Code plugin cache — each plugin can bundle its own .mcp.json
  const pluginCacheDir = join(home, '.claude', 'plugins', 'cache', 'claude-plugins-official');
  if (existsSync(pluginCacheDir)) {
    allServers.push(...await discoverPluginMCPConfigs(pluginCacheDir));
  }

  return allServers;
}

/**
 * Scan the Claude Code plugin cache for .mcp.json files.
 * Structure: ~/.claude/plugins/cache/claude-plugins-official/<plugin>/<version>/.mcp.json
 * Some plugins nest deeper (e.g., semgrep/<hash>/plugin/.mcp.json).
 */
async function discoverPluginMCPConfigs(cacheDir: string): Promise<MCPServerEntry[]> {
  const servers: MCPServerEntry[] = [];
  const seen = new Set<string>();

  let pluginDirs: Dirent[];
  try {
    pluginDirs = readdirSync(cacheDir, { withFileTypes: true });
  } catch {
    return [];
  }

  for (const pluginEntry of pluginDirs) {
    if (!pluginEntry.isDirectory()) continue;

    // nosemgrep: path-join-resolve-traversal — inputs are from readdirSync, not user-controlled
    const pluginDir = join(cacheDir, pluginEntry.name);

    let versionDirs: Dirent[];
    try {
      versionDirs = readdirSync(pluginDir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const versionEntry of versionDirs) {
      if (!versionEntry.isDirectory()) continue;

      // nosemgrep: path-join-resolve-traversal — inputs are from readdirSync, not user-controlled
      const versionDir = join(pluginDir, versionEntry.name);

      // Collect candidate .mcp.json paths: direct + one level deeper
      // nosemgrep: path-join-resolve-traversal — inputs are from readdirSync, not user-controlled
      const candidates = [join(versionDir, '.mcp.json')];

      try {
        for (const sub of readdirSync(versionDir, { withFileTypes: true })) {
          if (sub.isDirectory()) {
            // nosemgrep: path-join-resolve-traversal — inputs are from readdirSync, not user-controlled
            candidates.push(join(versionDir, sub.name, '.mcp.json'));
          }
        }
      } catch { /* ignore read errors on subdirs */ }

      for (const candidate of candidates) {
        const found = await parseMCPConfig(candidate, 'claude-code');
        for (const server of found) {
          // Deduplicate: same server name from different cached versions
          if (!seen.has(server.name)) {
            seen.add(server.name);
            servers.push(server);
          }
        }
      }
    }
  }

  return servers;
}
