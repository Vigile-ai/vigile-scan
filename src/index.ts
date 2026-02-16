// ============================================================
// Vigil CLI — Main Entry Point
// ============================================================
// Usage: npx vigil-scan [options]
//
// The AI agent security scanner. Discovers MCP server configs
// on your machine, scans them for security issues, and outputs
// trust scores.

import { Command } from 'commander';
import ora from 'ora';
import { writeFile } from 'fs/promises';
import { discoverAllServers } from './discovery/index.js';
import { scanServer } from './scanner/index.js';
import { printBanner, printServerResult, printSummary, printNoServersFound } from './output/terminal.js';
import { formatJSON } from './output/json.js';
import type { ScanOptions, ScanSummary, ScanResult, MCPClient } from './types/index.js';

const VERSION = '0.1.0';

const program = new Command();

program
  .name('vigil-scan')
  .description(
    'Security scanner for AI agent tools — detect tool poisoning, permission abuse, and supply chain attacks in MCP servers'
  )
  .version(VERSION);

program
  .command('scan')
  .description('Scan all MCP server configurations on this machine')
  .option('-j, --json', 'Output results as JSON')
  .option('-v, --verbose', 'Show detailed findings and score breakdown')
  .option('-c, --config <path>', 'Path to a custom MCP config file')
  .option('-o, --output <path>', 'Write results to a file')
  .option(
    '--client <client>',
    'Only scan a specific client (claude-desktop, cursor, claude-code, windsurf, vscode)'
  )
  .action(async (options: ScanOptions) => {
    await runScan(options);
  });

// Default command (no subcommand) also runs scan
program
  .option('-j, --json', 'Output results as JSON')
  .option('-v, --verbose', 'Show detailed findings and score breakdown')
  .option('-c, --config <path>', 'Path to a custom MCP config file')
  .option('-o, --output <path>', 'Write results to a file')
  .option(
    '--client <client>',
    'Only scan a specific client (claude-desktop, cursor, claude-code, windsurf, vscode)'
  )
  .action(async (options: ScanOptions) => {
    // If no subcommand provided, run scan by default
    if (!process.argv.slice(2).includes('scan')) {
      await runScan(options);
    }
  });

async function runScan(options: ScanOptions): Promise<void> {
  const isJSON = options.json;

  if (!isJSON) {
    printBanner();
  }

  // ── Step 1: Discover MCP configs ──
  const spinner = isJSON ? null : ora('Discovering MCP configurations...').start();

  const discovery = await discoverAllServers(options.client as MCPClient | undefined);

  if (discovery.servers.length === 0) {
    spinner?.stop();
    if (!isJSON) {
      printNoServersFound();
    } else {
      console.log(JSON.stringify({ servers: [], message: 'No MCP servers found' }));
    }
    return;
  }

  spinner?.succeed(
    `Found ${discovery.servers.length} MCP server(s) across ${discovery.configsFound} config file(s)`
  );

  // ── Step 2: Scan each server ──
  const scanSpinner = isJSON ? null : ora('Scanning for security issues...').start();

  const results: ScanResult[] = [];

  for (const server of discovery.servers) {
    const result = await scanServer(server);
    results.push(result);
  }

  scanSpinner?.succeed('Scan complete');

  // ── Step 3: Build summary ──
  const summary: ScanSummary = {
    totalServers: results.length,
    byTrustLevel: {
      trusted: results.filter((r) => r.trustLevel === 'trusted').length,
      caution: results.filter((r) => r.trustLevel === 'caution').length,
      risky: results.filter((r) => r.trustLevel === 'risky').length,
      dangerous: results.filter((r) => r.trustLevel === 'dangerous').length,
    },
    bySeverity: {
      critical: results.reduce((n, r) => n + r.findings.filter((f) => f.severity === 'critical').length, 0),
      high: results.reduce((n, r) => n + r.findings.filter((f) => f.severity === 'high').length, 0),
      medium: results.reduce((n, r) => n + r.findings.filter((f) => f.severity === 'medium').length, 0),
      low: results.reduce((n, r) => n + r.findings.filter((f) => f.severity === 'low').length, 0),
      info: results.reduce((n, r) => n + r.findings.filter((f) => f.severity === 'info').length, 0),
    },
    results,
    timestamp: new Date().toISOString(),
    version: VERSION,
  };

  // ── Step 4: Output results ──
  if (isJSON) {
    const jsonOutput = formatJSON(summary);
    if (options.output) {
      await writeFile(options.output, jsonOutput);
    } else {
      console.log(jsonOutput);
    }
  } else {
    console.log('');
    for (const result of results) {
      printServerResult(result, options.verbose ?? false);
    }
    printSummary(summary);

    if (options.output) {
      await writeFile(options.output, formatJSON(summary));
      console.log(`  Results saved to ${options.output}`);
    }
  }

  // ── Exit with appropriate code ──
  // Exit 1 if any critical or high findings (for CI/CD)
  if (summary.bySeverity.critical > 0 || summary.bySeverity.high > 0) {
    process.exit(1);
  }
}

program.parse();
