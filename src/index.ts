// ============================================================
// Vigile CLI — Main Entry Point
// ============================================================
// Usage: npx vigile-scan [options]
//
// The AI agent security scanner. Discovers MCP server configs
// and agent skill files on your machine, scans them for
// security issues, and outputs trust scores.
//
// v0.2.0: Added API integration — scan results upload to the
// Vigile registry, authentication, and Sentinel API sessions.

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { writeFile } from 'fs/promises';
import { discoverAllServers, discoverAllSkills } from './discovery/index.js';
import { scanServer } from './scanner/index.js';
import { scanSkill } from './scanner/skill-scanner.js';
import {
  SentinelEngine,
  getSentinelFeatures,
  SENTINEL_MARKETING,
} from './sentinel/index.js';
import type { SentinelReport, NetworkEvent } from './sentinel/index.js';
import {
  printBanner,
  printServerResult,
  printSkillResult,
  printSummary,
  printSentinelReport,
  printSentinelUpgrade,
  printNoServersFound,
  printNoSkillsFound,
  printNothingFound,
  printAuthStatus,
  printAuthLoginSuccess,
  printUploadSuccess,
  printUploadSkipped,
} from './output/terminal.js';
import { formatJSON } from './output/json.js';
import { getAuthenticatedClient, authLogin, authStatus, authLogout } from './api/auth.js';
import type { VigileApiClient } from './api/client.js';
import type {
  ScanOptions,
  ScanSummary,
  ScanResult,
  SkillScanResult,
  MCPClient,
  UploadSummary,
} from './types/index.js';

const VERSION = '0.2.0';

const program = new Command();

program
  .name('vigile-scan')
  .description(
    'Security scanner for AI agent tools — detect tool poisoning, permission abuse, and supply chain attacks in MCP servers and agent skills',
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
      'Only scan a specific client (claude-desktop, cursor, claude-code, windsurf, vscode)',
    )
    .option('-s, --skills', 'Scan agent skills only (SKILL.md, .mdc rules, CLAUDE.md, etc.)')
    .option('-a, --all', 'Scan both MCP servers and agent skills')
    .option('--sentinel', 'Enable Sentinel runtime monitoring (Pro+ feature)')
    .option('--sentinel-server <name>', 'Monitor a specific MCP server by name')
    .option('--sentinel-duration <seconds>', 'Monitoring duration in seconds (default: 120)', parseInt)
    .option('--no-upload', 'Skip uploading scan results to Vigile API');
}

addScanOptions(
  program
    .command('scan')
    .description('Scan MCP server configurations and agent skill files on this machine'),
).action(async (options: ScanOptions) => {
  await runScan(options);
});

// Default command (no subcommand) also runs scan
addScanOptions(program).action(async (options: ScanOptions) => {
  if (!process.argv.slice(2).includes('scan') && !process.argv.slice(2).includes('auth')) {
    await runScan(options);
  }
});

// ── Auth subcommand ──
const authCmd = program
  .command('auth')
  .description('Manage Vigile API authentication');

authCmd
  .command('login')
  .description('Authenticate with your Vigile API key')
  .argument('[token]', 'API key (vgl_...) or JWT token. If omitted, reads from VIGILE_TOKEN env var.')
  .action(async (token?: string) => {
    const resolvedToken = token || process.env.VIGILE_TOKEN;
    if (!resolvedToken) {
      console.log(chalk.red('  No token provided. Pass a token argument or set VIGILE_TOKEN env var.'));
      console.log(chalk.gray('  Usage: vigile-scan auth login <vgl_your_api_key>'));
      console.log(chalk.gray('  Get an API key at https://vigile.dev/account'));
      process.exit(1);
    }

    const spinner = ora('Validating token...').start();
    const result = await authLogin(resolvedToken);

    if (result.success && result.user) {
      spinner.succeed('Token validated');
      printAuthLoginSuccess(result.user.email, result.user.tier);
    } else {
      spinner.fail('Authentication failed');
      console.log(chalk.red(`  Error: ${result.error || 'Unknown error'}`));
      process.exit(1);
    }
  });

authCmd
  .command('status')
  .description('Show current authentication status')
  .action(async () => {
    const result = await authStatus();
    printAuthStatus({
      authenticated: result.authenticated,
      source: result.source,
      email: result.user?.email,
      tier: result.user?.tier,
      name: result.user?.name || undefined,
      error: result.error,
    });
  });

authCmd
  .command('logout')
  .description('Clear stored credentials')
  .action(async () => {
    await authLogout();
    console.log(chalk.green('  Logged out. Credentials removed from ~/.vigile/config.json'));
    console.log('');
  });

// ============================================================
// Main Scan Flow
// ============================================================

async function runScan(options: ScanOptions): Promise<void> {
  const isJSON = options.json ?? false;
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
        `Found ${discovery.servers.length} MCP server(s) across ${discovery.configsFound} config file(s)`,
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
        `Found ${skillDiscovery.skills.length} skill file(s) across ${skillDiscovery.locationsFound} location(s)`,
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

  // ── Step 4.5: Upload results to Vigile API (if authenticated) ──
  if (options.noUpload !== true) {
    await uploadResults(results, skillResults, isJSON);
  }

  // ── Step 5: Sentinel Runtime Monitoring (if --sentinel) ──
  if (options.sentinel) {
    await runSentinel(options, results, isJSON);
  }

  // ── Exit with appropriate code ──
  if (summary.bySeverity.critical > 0 || summary.bySeverity.high > 0) {
    process.exit(1);
  }
}

// ============================================================
// API Upload — Send scan results to the Vigile registry
// ============================================================

/**
 * Upload scan results to the Vigile API.
 * Graceful degradation: if API is unreachable or auth fails, just warn.
 */
async function uploadResults(
  mcpResults: ScanResult[],
  skillResults: SkillScanResult[],
  isJSON: boolean,
): Promise<void> {
  const client = await getAuthenticatedClient();

  if (!client) {
    if (!isJSON) {
      printUploadSkipped('not-authenticated');
    }
    return;
  }

  const summary: UploadSummary = {
    mcpUploaded: 0,
    skillsUploaded: 0,
    failures: 0,
    errors: [],
  };

  const spinner = isJSON ? null : ora('Uploading results to Vigile registry...').start();

  // Upload MCP scan results
  for (const result of mcpResults) {
    const payload = mapMCPResultToApiPayload(result);
    const response = await client.submitMCPScan(payload);

    if (response.ok) {
      summary.mcpUploaded++;
    } else {
      summary.failures++;
      summary.errors.push(`${result.server.name}: ${response.error}`);
    }
  }

  // Upload skill scan results
  for (const result of skillResults) {
    const payload = mapSkillResultToApiPayload(result);
    const response = await client.submitSkillScan(payload);

    if (response.ok) {
      summary.skillsUploaded++;
    } else {
      summary.failures++;
      summary.errors.push(`${result.skill.name}: ${response.error}`);
    }
  }

  if (spinner) {
    const total = summary.mcpUploaded + summary.skillsUploaded;
    if (total > 0 && summary.failures === 0) {
      spinner.succeed(`Uploaded ${total} result(s) to Vigile registry`);
    } else if (total > 0 && summary.failures > 0) {
      spinner.warn(`Uploaded ${total} result(s), ${summary.failures} failed`);
    } else {
      spinner.fail('Upload failed');
    }
  }

  if (!isJSON) {
    printUploadSuccess(summary);
  }
}

// ============================================================
// Field Mapping Helpers — CLI types → API request shapes
// ============================================================

/**
 * Map a CLI ScanResult to the API ScanRequest payload.
 */
function mapMCPResultToApiPayload(result: ScanResult): {
  server_name: string;
  source: string;
  package_url?: string;
  description?: string;
  tool_descriptions?: string[];
} {
  // Derive package URL from command + args
  let packageUrl: string | undefined;
  if (result.server.command === 'npx') {
    const packageName = result.server.args.find((a) => !a.startsWith('-'));
    if (packageName) {
      packageUrl = `https://www.npmjs.com/package/${packageName}`;
    }
  } else if (result.server.command === 'uvx' || result.server.command === 'pip') {
    const packageName = result.server.args.find((a) => !a.startsWith('-'));
    if (packageName) {
      packageUrl = `https://pypi.org/project/${packageName}/`;
    }
  }

  // Tool descriptions from non-flag args
  const toolDescriptions = result.server.args.filter((a) => !a.startsWith('-'));

  return {
    server_name: result.server.name,
    source: 'manual', // CLI-discovered servers are always manual source
    package_url: packageUrl,
    description: `MCP server discovered from ${result.server.source} config`,
    tool_descriptions: toolDescriptions.length > 0 ? toolDescriptions : undefined,
  };
}

/**
 * Map a CLI SkillScanResult to the API SkillScanRequest payload.
 */
function mapSkillResultToApiPayload(result: SkillScanResult): {
  skill_name: string;
  content: string;
  file_type: string;
  platform: string;
  source: string;
} {
  // Map CLI SkillSource to API platform values
  const platformMap: Record<string, string> = {
    'claude-code': 'claude-code',
    'github-copilot': 'copilot',
    'cursor': 'cursor',
    'memory-file': 'unknown',
    'custom': 'unknown',
  };

  return {
    skill_name: result.skill.name,
    content: result.skill.content,
    file_type: result.skill.fileType,
    platform: platformMap[result.skill.source] || 'unknown',
    source: 'manual', // CLI submissions are always manual source
  };
}

/**
 * Map a CLI NetworkEvent (camelCase) to the API NetworkEventSubmission (snake_case).
 */
function mapNetworkEventToApi(event: NetworkEvent): {
  timestamp: number;
  server_name: string;
  method: string;
  url: string;
  destination_ip: string | null;
  port: number;
  request_size: number;
  response_size: number | null;
  status_code: number | null;
  headers: Record<string, string> | null;
  dns_query_type: string | null;
  tls: boolean;
  body_hash: string | null;
  body_entropy: number | null;
} {
  return {
    timestamp: event.timestamp,
    server_name: event.serverName,
    method: event.method,
    url: event.url,
    destination_ip: event.destinationIp || null,
    port: event.port,
    request_size: event.requestSize,
    response_size: event.responseSize ?? null,
    status_code: event.statusCode ?? null,
    headers: event.headers || null,
    dns_query_type: event.dnsQueryType ?? null,
    tls: event.tls,
    body_hash: event.bodyHash ?? null,
    body_entropy: event.bodyEntropy ?? null,
  };
}

// ============================================================
// Sentinel Runtime Monitoring — with API integration
// ============================================================

/**
 * Run Sentinel runtime monitoring on discovered MCP servers.
 * When authenticated, creates API sessions and submits events
 * for server-side analysis. Falls back to local-only when offline.
 */
async function runSentinel(
  options: ScanOptions,
  scanResults: ScanResult[],
  isJSON: boolean,
): Promise<void> {
  // Resolve tier: API if authenticated, else env var fallback
  const client = await getAuthenticatedClient();
  let tier: 'free' | 'pro' = 'free';

  if (client) {
    const meResult = await client.getMe();
    if (meResult.ok) {
      tier = meResult.data.tier as typeof tier;
    }
  } else {
    tier = (process.env.VIGILE_TIER as typeof tier) || 'free';
  }

  const features = getSentinelFeatures(tier);

  if (!features.monitoringEnabled) {
    if (!isJSON) {
      printSentinelUpgrade();
    } else {
      console.log(
        JSON.stringify({
          sentinel: { error: 'upgrade_required', message: SENTINEL_MARKETING.upgradePrompt },
        }),
      );
    }
    return;
  }

  // Determine which server(s) to monitor
  const serversToMonitor: string[] = [];
  if (options.sentinelServer) {
    serversToMonitor.push(options.sentinelServer);
  } else if (scanResults.length > 0) {
    // Monitor all discovered servers (up to the tier limit)
    const limit =
      features.maxConcurrentServers === -1
        ? scanResults.length
        : Math.min(scanResults.length, features.maxConcurrentServers);
    for (let i = 0; i < limit; i++) {
      serversToMonitor.push(scanResults[i].server.name);
    }
  } else {
    if (!isJSON) {
      console.log(
        chalk.yellow('  No MCP servers to monitor. Run a scan first or specify --sentinel-server <name>.'),
      );
    }
    return;
  }

  // Clamp duration to tier limit
  const requestedDuration = options.sentinelDuration || 120;
  const maxDuration = features.maxDurationSeconds === -1 ? requestedDuration : features.maxDurationSeconds;
  const duration = Math.min(requestedDuration, maxDuration);

  if (!isJSON) {
    console.log('');
    console.log(chalk.bold.hex('#2C4A7C')('  \u{1F6E1}\uFE0F  Vigile Sentinel \u2014 Runtime Monitor'));
    console.log(
      chalk.gray(`  Tier: ${tier.toUpperCase()} | Duration: ${duration}s | Servers: ${serversToMonitor.length}`),
    );
    console.log('');
  }

  // Start monitoring each server
  const sentinelReports: SentinelReport[] = [];

  for (const serverName of serversToMonitor) {
    // Create API session if authenticated
    let apiSessionId: number | null = null;
    if (client) {
      const sessionResult = await client.createSentinelSession(serverName, duration);
      if (sessionResult.ok) {
        apiSessionId = sessionResult.data.session_id;
      }
    }

    const spinner = isJSON ? null : ora(`Monitoring ${serverName} for ${duration}s...`).start();

    // Batch events for API submission
    let pendingApiEvents: NetworkEvent[] = [];
    let lastApiSubmit = Date.now();

    const engine = new SentinelEngine({
      serverName,
      durationSeconds: duration,
      onEvent: (event) => {
        if (!isJSON && spinner) {
          spinner.text = `Monitoring ${serverName} \u2014 ${(engine as unknown as { events: unknown[] }).events.length} events captured...`;
        }

        // Accumulate events for API batch submission
        if (apiSessionId !== null && client) {
          pendingApiEvents.push(event);

          // Submit every 5 seconds
          const now = Date.now();
          if (now - lastApiSubmit > 5000 && pendingApiEvents.length > 0) {
            const eventsToSubmit = pendingApiEvents.map(mapNetworkEventToApi);
            pendingApiEvents = [];
            lastApiSubmit = now;
            // Fire and forget — don't await in the event handler
            client.submitSentinelEvents(apiSessionId, eventsToSubmit).catch(() => {
              // Silently ignore API submission errors during monitoring
            });
          }
        }
      },
    });

    await engine.startMonitoring();

    // Wait for monitoring duration
    await new Promise((resolve) => setTimeout(resolve, duration * 1000));

    const report = await engine.stopMonitoring();
    sentinelReports.push(report);

    // Submit remaining events and get API analysis
    if (apiSessionId !== null && client) {
      if (pendingApiEvents.length > 0) {
        const finalEvents = pendingApiEvents.map(mapNetworkEventToApi);
        await client.submitSentinelEvents(apiSessionId, finalEvents);
      }

      const apiReport = await client.analyzeSentinelSession(apiSessionId);
      if (apiReport.ok && !isJSON) {
        console.log(
          chalk.gray(
            `    API Analysis: ${apiReport.data.findings.length} findings, threat: ${apiReport.data.threat_level}`,
          ),
        );
      }
    }

    if (spinner) {
      spinner.succeed(
        `${serverName}: ${report.totalEvents} events, ${report.findings.length} findings [${report.threatLevel.toUpperCase()}]`,
      );
    }
  }

  // Output Sentinel results
  if (isJSON) {
    console.log(JSON.stringify({ sentinel: sentinelReports }, null, 2));
  } else {
    for (const report of sentinelReports) {
      printSentinelReport(report);
    }
  }
}

program.parse();
