// ============================================================
// OpenClaw — MCP Config Discovery
// ============================================================
// Config locations:
//   All platforms: ~/.openclaw/openclaw.json (mcpServers key)
//   Project-local: openclaw.config.json (in cwd)
//
// OpenClaw also supports agent-level MCP configs:
//   { agents: { list: [{ id: "main", mcp: { servers: [...] } }] } }
//
// Note: OpenClaw uses JSON5 format (comments, trailing commas).
// Our parser uses standard JSON.parse — configs with JSON5-only
// features will be skipped gracefully.

import { join } from 'path';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { getHome, tryConfigPaths } from './utils.js';
import type { MCPServerEntry } from '../types/index.js';

export async function discoverOpenClaw(): Promise<MCPServerEntry[]> {
  const home = getHome();
  const allServers: MCPServerEntry[] = [];
  const seen = new Set<string>();

  // 1. Standard mcpServers block (top-level, same format as Claude Desktop)
  const configPaths = [
    join(home, '.openclaw', 'openclaw.json'),
    join(process.cwd(), 'openclaw.config.json'),
  ];
  for (const server of await tryConfigPaths(configPaths, 'openclaw')) {
    if (!seen.has(server.name)) {
      seen.add(server.name);
      allServers.push(server);
    }
  }

  // 2. Agent-level MCP configs (nested under agents.list[].mcp.servers)
  const globalConfig = join(home, '.openclaw', 'openclaw.json');
  if (existsSync(globalConfig)) {
    for (const server of await parseAgentMCPConfigs(globalConfig)) {
      if (!seen.has(server.name)) {
        seen.add(server.name);
        allServers.push(server);
      }
    }
  }

  return allServers;
}

/**
 * Parse agent-level MCP server configs from OpenClaw config.
 * Structure: { agents: { list: [{ id: "main", mcp: { servers: [...] } }] } }
 *
 * Agent-level servers use an array format with name/command/args properties,
 * unlike the top-level mcpServers which uses an object keyed by server name.
 */
async function parseAgentMCPConfigs(configPath: string): Promise<MCPServerEntry[]> {
  try {
    const raw = await readFile(configPath, 'utf-8');
    const config = JSON.parse(raw);

    const agents = config?.agents?.list;
    if (!Array.isArray(agents)) return [];

    const servers: MCPServerEntry[] = [];

    for (const agent of agents) {
      const mcpServers = agent?.mcp?.servers;
      if (!Array.isArray(mcpServers)) continue;

      for (const server of mcpServers) {
        if (!server.name || (!server.command && !server.url)) continue;

        servers.push({
          name: server.name,
          source: 'openclaw',
          command: server.command || '',
          args: Array.isArray(server.args) ? server.args : [],
          env: server.env,
          configPath,
        });
      }
    }

    return servers;
  } catch {
    return [];
  }
}
