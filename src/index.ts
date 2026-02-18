// ============================================================
// Vigile CLI — Main Entry Point
// ============================================================
// Usage: npx vigile-scan [options]
//
// The AI agent security scanner. Discovers MCP server configs
// and agent skill files on your machine, scans them for
// security issues, and outputs trust scores.

import { Command } from 'commander';
import ora from 'ora';
import { writeFile } from 'fs/promises';
import { discoverAllServers, discoverAllSkills } from './discovery/index.js';
import { scanServer } from './scanner/index.js';
import { scanSkill } from './scanner/skill-scanner.js';
import {
  printBanner,
  printServerResult,
  printSkillResult,
  printSummary,
  printNoServersFound,
  printNoSkillsFound,
  printNothingFound,
} from './output/terminal.js';
import { formatJSON } from './output/json.js';
import type { ScanOptions, ScanSummary, ScanResult, SkillScanResult, MCPClient } from './types/index.js';

const VERSION = '0.1.2';

const program = new Command();

program
  .name('vigile-scan')
  .description(
    'Security scanner for AI agent tools — detect tool poisoning, permission abuse, and supply chain attacks in MCP servers and agent skills'
  )
  .version(VERSION);

// Shared options for scan commands
function addScanOptions(cmd: Command): Command {
  return cmd
    .option('-j, --json', 'Output results as JSON')
    .option('-v, --verbose', 'Show detailed findings and score breakdown')
    .option('-c, --config <path>', 'Path to a custom MCP config file')
    .option('-o, --output <path>', 'Write results to a file')
    .option(
      '--client <client>',
      'Only scan a specific client (claude-desktop, cursor, claude-code, windsurf, vscode)'
    )
    .option('-s, --skills', 'Scan agent skills only (SKILL.md, .mdc rules, CLAUDE.md, etc.)')
    .option('-a, --all', 'Scan both MCP servers and agent skills');
}

addScanOptions(
  program
    .command('scan')
    .description('Scan MCP server configurations and agent skill files on this machine')
).action(async (options: ScanOptions) => {
  await runScan(options);
});

// Default command (no subcommand) also runs scan
addScanOptions(program).action(async (options: ScanOptions) => {
  if (!process.argv.slice(2).includes('scan')) {
    await runScan(options);
  }
});

async function runScan(options: ScanOptions): Promise<void> {
  const isJSON = options.json;
  const scanMCP = !options.skills; // Scan MCP unless --skills only
  const scanSkills = options.skills || options.all; // Scan skills if --skills or --all

  if (!isJSON) {
    printBanner();
  }

  const results: ScanResult[] = [];
  const skillResults: SkillScanResult[] = [];

  // ── Step 1: Discover & scan MCP servers ──
  if (scanMCP) {
    const spinner = isJSON ? null : ora('Discovering MCP configurations...').start();
    const discovery = await discoverAllServers(options.client as MCPClient | undefined);

    if (discovery.servers.length === 0) {
      spinner?.succeed('No MCP server configurations found');
    } else {
      spinner?.succeed(
        `Found ${discovery.servers.length} MCP server(s) across ${discovery.configsFound} config file(s)`
      );

      const scanSpinner = isJSON ? null : ora('Scanning MCP servers...').start();
      for (const server of discovery.servers) {
        const result = await scanServer(server);
        results.push(result);
      }
      scanSpinner?.succeed(`Scanned ${results.length} MCP server(s)`);
    }
  }

  // ── Step 2: Discover & scan agent skills ──
  if (scanSkills) {
    const spinner = isJSON ? null : ora('Discovering agent skill files...').start();
    const skillDiscovery = await discoverAllSkills();

    if (skillDiscovery.skills.length === 0) {
      spinner?.succeed('No agent skill files found');
    } else {
      spinner?.succeed(
        `Found ${skillDiscovery.skills.length} skill file(s) across ${skillDiscovery.locationsFound} location(s)`
      );

      const scanSpinner = isJSON ? null : ora('Scanning agent skills...').start();
      for (const skill of skillDiscovery.skills) {
        const result = await scanSkill(skill);
        skillResults.push(result);
      }
      scanSpinner?.succeed(`Scanned ${skillResults.length} skill file(s)`);
    }
  }

  // ── Check if anything was found ──
  if (results.length === 0 && skillResults.length === 0) {
    if (!isJSON) {
      if (scanMCP && !scanSkills) {
        printNoServersFound();
      } else if (scanSkills && !scanMCP) {
        printNoSkillsFound();
      } else {
        printNothingFound();
      }
    } else {
      console.log(JSON.stringify({ servers: [], skills: [], message: 'Nothing found to scan' }));
    }
    return;
  }

  // ── Step 3: Build combined summary ──
  const allResults = [...results];
  const allSkillResults = [...skillResults];

  // Combine trust level counts from both MCP and skill results
  const allTrustLevels = [
    ...results.map((r) => r.trustLevel),
    ...skillResults.map((r) => r.trustLevel),
  ];

  // Combine finding severities from both MCP and skill results
  const allFindings = [
    ...results.flatMap((r) => r.findings),
    ...skillResults.flatMap((r) => r.findings),
  ];

  const summary: ScanSummary = {
    totalServers: allResults.length,
    totalSkills: allSkillResults.length,
    byTrustLevel: {
      trusted: allTrustLevels.filter((l) => l === 'trusted').length,
      caution: allTrustLevels.filter((l) => l === 'caution').length,
      risky: allTrustLevels.filter((l) => l === 'risky').length,
      dangerous: allTrustLevels.filter((l) => l === 'dangerous').length,
    },
    bySeverity: {
      critical: allFindings.filter((f) => f.severity === 'critical').length,
      high: allFindings.filter((f) => f.severity === 'high').length,
      medium: allFindings.filter((f) => f.severity === 'medium').length,
      low: allFindings.filter((f) => f.severity === 'low').length,
      info: allFindings.filter((f) => f.severity === 'info').length,
    },
    results: allResults,
    skillResults: allSkillResults,
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

    // Print MCP server results
    if (results.length > 0) {
      for (const result of results) {
        printServerResult(result, options.verbose ?? false);
      }
    }

    // Print skill results
    if (skillResults.length > 0) {
      for (const result of skillResults) {
        printSkillResult(result, options.verbose ?? false);
      }
    }

    printSummary(summary);

    if (options.output) {
      await writeFile(options.output, formatJSON(summary));
      console.log(`  Results saved to ${options.output}`);
    }
  }

  // ── Exit with appropriate code ──
  if (summary.bySeverity.critical > 0 || summary.bySeverity.high > 0) {
    process.exit(1);
  }
}

program.parse();
