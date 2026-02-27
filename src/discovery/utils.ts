// ============================================================
// Vigile CLI — Discovery Utilities
// ============================================================

import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { homedir, platform } from 'os';
import type { MCPClient, MCPServerEntry } from '../types/index.js';

/** Get the home directory */
export function getHome(): string {
  return homedir();
}

/** Get the current platform */
export function getPlatform(): 'darwin' | 'win32' | 'linux' {
  return platform() as 'darwin' | 'win32' | 'linux';
}

/** Get Windows APPDATA path */
export function getAppData(): string {
  return process.env.APPDATA || join(homedir(), 'AppData', 'Roaming');
}

/** Get Windows LOCALAPPDATA path */
export function getLocalAppData(): string {
  return (
    process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local')
  );
}

/**
 * Parse an MCP config file (JSON with mcpServers key).
 * Returns empty array if file doesn't exist or is invalid.
 */
export async function parseMCPConfig(
  configPath: string,
  source: MCPClient
): Promise<MCPServerEntry[]> {
  if (!existsSync(configPath)) {
    return [];
  }

  try {
    const raw = await readFile(configPath, 'utf-8');
    const config = JSON.parse(raw);

    // Handle { mcpServers: {...} }, { servers: {...} } (VS Code), and direct configs
    const servers = config.mcpServers || config.servers || config;

    if (typeof servers !== 'object' || servers === null) {
      return [];
    }

    const entries: MCPServerEntry[] = [];

    for (const [name, serverConfig] of Object.entries(servers)) {
      const sc = serverConfig as Record<string, unknown>;

      // Skip if it doesn't look like a server config
      if (!sc.command && !sc.url) continue;

      entries.push({
        name,
        source,
        command: (sc.command as string) || '',
        args: Array.isArray(sc.args) ? (sc.args as string[]) : [],
        env: sc.env as Record<string, string> | undefined,
        configPath,
      });
    }

    return entries;
  } catch {
    // Invalid JSON, file read error, etc.
    return [];
  }
}

/**
 * Try multiple possible config paths and return all servers found.
 */
export async function tryConfigPaths(
  paths: string[],
  source: MCPClient
): Promise<MCPServerEntry[]> {
  const allServers: MCPServerEntry[] = [];

  for (const path of paths) {
    const servers = await parseMCPConfig(path, source);
    allServers.push(...servers);
  }

  return allServers;
}
