// ============================================================
// Vigile Sentinel — Runtime Network Monitor for MCP Servers
// ============================================================
// The Sentinel engine monitors MCP server network behavior
// in real-time to detect "phoning home" — C2 beaconing,
// data exfiltration, DNS tunneling, and covert channels.
//
// Architecture:
//   1. Launches a lightweight network monitor alongside MCP servers
//   2. Captures outbound connections using OS-level network inspection
//   3. Feeds events through behavioral + endpoint pattern matching
//   4. Generates a SentinelReport with findings and threat score
//
// This is a PRO+ subscription feature.
//
// Usage:
//   npx vigile-scan --sentinel          # Monitor all discovered MCP servers
//   npx vigile-scan --sentinel --server <name>  # Monitor specific server
//   npx vigile-scan --sentinel --duration 300   # Monitor for 5 minutes

import { execFileSync, spawn, type ChildProcess } from 'child_process';
import { promises as dnsPromises } from 'dns';
import type {
  NetworkEvent,
  SentinelFinding,
  SentinelReport,
  SentinelThreatLevel,
} from './sentinel-patterns.js';
import {
  SUSPICIOUS_ENDPOINT_PATTERNS,
  BEHAVIORAL_PATTERNS,
  CREDENTIAL_EXFIL_PATTERNS,
  calculateThreatScore,
  threatLevelFromScore,
} from './sentinel-patterns.js';

// ──────────────────────────────────────────────────────────
// SENTINEL ENGINE
// ──────────────────────────────────────────────────────────

export class SentinelEngine {
  private events: NetworkEvent[] = [];
  private findings: SentinelFinding[] = [];
  private monitorProcess: ChildProcess | null = null;
  private startTime: number = 0;
  private serverName: string;
  private durationSeconds: number;
  private onEvent?: (event: NetworkEvent) => void;
  /** DNS reverse-lookup cache: IP → hostname. Persists for the session. */
  private dnsCache = new Map<string, string>();

  constructor(options: {
    serverName: string;
    durationSeconds?: number;
    onEvent?: (event: NetworkEvent) => void;
  }) {
    this.serverName = options.serverName;
    this.durationSeconds = options.durationSeconds || 120; // Default 2 minutes
    this.onEvent = options.onEvent;
  }

  /**
   * Start monitoring network activity for the given MCP server.
   *
   * The monitor works in four modes depending on the OS and permissions:
   *   1. macOS: Uses `lsof -i` polling (no root required)
   *   2. Linux: Uses `ss -tnp` polling (no root required)
   *   3. Windows: Uses PowerShell `Get-NetTCPConnection` (no admin required)
   *   4. Fallback: Stub — events must be fed manually via ingestEvent()
   *
   * All modes perform async reverse-DNS enrichment so that endpoint patterns
   * (pastebin.com, ngrok.io, etc.) match against resolved hostnames rather
   * than raw IPs.
   */
  async startMonitoring(): Promise<void> {
    this.startTime = Date.now();
    this.events = [];
    this.findings = [];

    const method = this.detectMonitoringMethod();

    switch (method) {
      case 'lsof-poll':
        await this.startLsofPolling();
        break;
      case 'ss-poll':
        await this.startSsPolling();
        break;
      case 'netstat-poll':
        await this.startNetstatPolling();
        break;
      case 'proxy':
        await this.startProxyCapture();
        break;
    }
  }

  /**
   * Stop monitoring and generate the report.
   */
  async stopMonitoring(): Promise<SentinelReport> {
    if (this.monitorProcess) {
      this.monitorProcess.kill('SIGTERM');
      this.monitorProcess = null;
    }

    // Run all detection patterns against collected events
    this.analyzeEvents();

    const threatScore = calculateThreatScore(this.findings);
    const threatLevel = threatLevelFromScore(threatScore);

    const uniqueDestinations = [
      ...new Set(
        this.events.map(e => {
          try { return new URL(e.url).hostname; } catch { return e.url; }
        })
      ),
    ];

    return {
      serverName: this.serverName,
      monitoringDuration: (Date.now() - this.startTime) / 1000,
      totalEvents: this.events.length,
      uniqueDestinations,
      findings: this.findings,
      threatLevel,
      threatScore,
      startedAt: new Date(this.startTime).toISOString(),
      endedAt: new Date().toISOString(),
    };
  }

  /**
   * Feed a single network event into the engine (for real-time analysis).
   */
  ingestEvent(event: NetworkEvent): void {
    this.events.push(event);
    this.onEvent?.(event);

    // Run real-time endpoint checks (fast, per-event)
    this.checkEndpointPatterns(event);
    this.checkCredentialPatterns(event);
  }

  // ── Detection Methods ──

  /**
   * Run all analysis on collected events.
   */
  private analyzeEvents(): void {
    // 1. Endpoint pattern matching (per-event)
    for (const event of this.events) {
      this.checkEndpointPatterns(event);
      this.checkCredentialPatterns(event);
    }

    // 2. Behavioral pattern matching (across time windows)
    for (const pattern of BEHAVIORAL_PATTERNS) {
      if (this.events.length < pattern.minEvents) continue;

      // Slice events into the time window
      const now = Date.now();
      const windowStart = now - pattern.timeWindowSeconds * 1000;
      const windowEvents = this.events.filter(e => e.timestamp >= windowStart);

      if (windowEvents.length < pattern.minEvents) continue;

      const confidence = pattern.detect(windowEvents);
      if (confidence > 25) {
        // Only report if we haven't already found this pattern
        if (!this.findings.some(f => f.id === pattern.id)) {
          this.findings.push({
            id: pattern.id,
            category: pattern.id.startsWith('SN-01') ? 'c2-beaconing' :
                      pattern.id === 'SN-012' ? 'dns-tunneling' :
                      pattern.id === 'SN-013' ? 'covert-channel' : 'phone-home',
            severity: pattern.severity,
            title: pattern.title,
            description: pattern.description,
            serverName: this.serverName,
            evidence: windowEvents.slice(0, 10), // Cap evidence at 10 events
            recommendation: pattern.recommendation,
            confidence,
          });
        }
      }
    }

    // De-duplicate findings (keep highest confidence per ID)
    const seen = new Map<string, SentinelFinding>();
    for (const f of this.findings) {
      const existing = seen.get(f.id);
      if (!existing || f.confidence > existing.confidence) {
        seen.set(f.id, f);
      }
    }
    this.findings = Array.from(seen.values());
  }

  private checkEndpointPatterns(event: NetworkEvent): void {
    for (const pattern of SUSPICIOUS_ENDPOINT_PATTERNS) {
      if (pattern.urlPattern.test(event.url)) {
        if (!this.findings.some(f => f.id === pattern.id && f.evidence[0]?.url === event.url)) {
          this.findings.push({
            id: pattern.id,
            category: 'phone-home',
            severity: pattern.severity,
            title: pattern.title,
            description: pattern.description,
            serverName: this.serverName,
            evidence: [event],
            recommendation: pattern.recommendation,
            confidence: 95,
          });
        }
      }
    }
  }

  private checkCredentialPatterns(event: NetworkEvent): void {
    for (const pattern of CREDENTIAL_EXFIL_PATTERNS) {
      if (pattern.urlPattern.test(event.url)) {
        this.findings.push({
          id: pattern.id,
          category: 'data-exfiltration',
          severity: pattern.severity,
          title: pattern.title,
          description: pattern.description,
          serverName: this.serverName,
          evidence: [event],
          recommendation: pattern.recommendation,
          confidence: 98,
        });
      }
    }
  }

  // ── Monitoring Methods ──

  private detectMonitoringMethod(): 'lsof-poll' | 'ss-poll' | 'netstat-poll' | 'proxy' {
    // Windows: PowerShell Get-NetTCPConnection is always available on Win 8+
    if (process.platform === 'win32') {
      return 'netstat-poll';
    }

    // macOS: lsof is always present — skip `which` probe entirely
    if (process.platform === 'darwin') {
      return 'lsof-poll';
    }

    // Linux: prefer ss (iproute2), fall back to lsof
    try {
      execFileSync('which', ['ss'], { stdio: 'pipe' });
      return 'ss-poll';
    } catch {
      try {
        execFileSync('which', ['lsof'], { stdio: 'pipe' });
        return 'lsof-poll';
      } catch {
        return 'proxy';
      }
    }
  }

  /**
   * macOS: Poll `lsof -i` to capture network connections.
   * No root required. DNS-enriches IPs → hostnames before pattern matching.
   */
  private async startLsofPolling(): Promise<void> {
    const safeName = this.serverName.replace(/[^a-zA-Z0-9._@/-]/g, '');

    const pollInterval = setInterval(async () => {
      try {
        const lsofOutput = execFileSync('/usr/sbin/lsof', ['-i', '-n', '-P'], {
          timeout: 5000,
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        const lines = lsofOutput
          .split('\n')
          .filter(line => line.toLowerCase().includes(safeName.toLowerCase()))
          .filter(Boolean);

        // Parse all lines, then DNS-enrich all IPs in parallel before ingesting
        const rawEvents = lines.map(l => this.parseLsofLine(l)).filter((e): e is NetworkEvent => e !== null);
        const enriched = await Promise.all(rawEvents.map(e => this.enrichWithHostname(e)));
        for (const event of enriched) this.ingestEvent(event);
      } catch {
        // lsof failed, continue
      }
    }, 2000);

    this.monitorProcess = { kill: () => clearInterval(pollInterval) } as unknown as ChildProcess;
    setTimeout(() => clearInterval(pollInterval), this.durationSeconds * 1000);
  }

  /**
   * Linux: Poll `ss -tnp` (socket statistics) for network connections.
   * No root required. DNS-enriches IPs → hostnames before pattern matching.
   */
  private async startSsPolling(): Promise<void> {
    const safeName = this.serverName.replace(/[^a-zA-Z0-9._@/-]/g, '');

    const pollInterval = setInterval(async () => {
      try {
        const ssOutput = execFileSync('ss', ['-tnp'], {
          timeout: 5000,
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        const lines = ssOutput
          .split('\n')
          .filter(line => line.includes(safeName))
          .filter(Boolean);

        const rawEvents = lines.map(l => this.parseSsLine(l)).filter((e): e is NetworkEvent => e !== null);
        const enriched = await Promise.all(rawEvents.map(e => this.enrichWithHostname(e)));
        for (const event of enriched) this.ingestEvent(event);
      } catch {
        // ss failed, continue
      }
    }, 2000);

    this.monitorProcess = { kill: () => clearInterval(pollInterval) } as unknown as ChildProcess;
    setTimeout(() => clearInterval(pollInterval), this.durationSeconds * 1000);
  }

  /**
   * Windows: Poll PowerShell `Get-NetTCPConnection` for established connections.
   * No admin required (available on Windows 8+ / Server 2012+).
   * DNS-enriches IPs → hostnames so endpoint patterns match correctly.
   *
   * Note: Unlike lsof/ss, this captures ALL machine connections (not filtered
   * by process name) because Windows process-to-connection mapping requires
   * admin rights. Vigil's patterns handle the noise — it flags what matters.
   */
  private async startNetstatPolling(): Promise<void> {
    // PowerShell command: get established external TCP connections as CSV
    const psCommand =
      `Get-NetTCPConnection -State Established | ` +
      `Where-Object { $_.RemoteAddress -notmatch '^(127\\.|::1$|0\\.0\\.0\\.0$|::$)' } | ` +
      `Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort | ` +
      `ConvertTo-Csv -NoTypeInformation`;

    const pollInterval = setInterval(async () => {
      try {
        const output = execFileSync('powershell', [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          psCommand,
        ], {
          timeout: 8000, // PowerShell startup is slower than lsof
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        // CSV rows: skip header, parse each line
        const lines = output.split('\n').slice(1).map(l => l.trim()).filter(Boolean);
        const rawEvents = lines.map(l => this.parsePowerShellLine(l)).filter((e): e is NetworkEvent => e !== null);
        const enriched = await Promise.all(rawEvents.map(e => this.enrichWithHostname(e)));
        for (const event of enriched) this.ingestEvent(event);
      } catch {
        // PowerShell failed or unavailable
      }
    }, 3000); // 3s interval — PS startup adds ~1-2s overhead

    this.monitorProcess = { kill: () => clearInterval(pollInterval) } as unknown as ChildProcess;
    setTimeout(() => clearInterval(pollInterval), this.durationSeconds * 1000);
  }

  /**
   * Fallback: Start a lightweight MITM proxy that MCP traffic routes through.
   * This requires the runtime proxy (Phase 3) to be active.
   */
  private async startProxyCapture(): Promise<void> {
    // Proxy mode requires the full runtime proxy infrastructure (Phase 3).
    // For Phase 2, this is a stub that collects events fed via ingestEvent().
    console.warn(
      '[Sentinel] Proxy capture requires the runtime proxy (coming soon). ' +
      'Using manual event ingestion mode.'
    );
  }

  // ── Parsers ──

  private parseLsofLine(line: string): NetworkEvent | null {
    // lsof output format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    // NAME for TCP: host:port->remote:port (ESTABLISHED)
    const match = line.match(
      /(\S+)\s+(\d+)\s+\S+\s+\S+\s+IPv[46]\s+\S+\s+\S+\s+TCP\s+\S+->(\S+):(\d+)\s/
    );
    if (!match) return null;

    const [, _command, _pid, remoteHost, remotePort] = match;

    return {
      timestamp: Date.now(),
      serverName: this.serverName,
      method: 'TCP',
      url: `https://${remoteHost}:${remotePort}/`,
      destinationIp: remoteHost,
      port: parseInt(remotePort, 10),
      requestSize: 0,
      tls: parseInt(remotePort, 10) === 443,
    };
  }

  private parseSsLine(line: string): NetworkEvent | null {
    // ss output: State Recv-Q Send-Q Local:Port Peer:Port Process
    const match = line.match(
      /ESTAB\s+\d+\s+(\d+)\s+\S+\s+(\S+):(\d+)/
    );
    if (!match) return null;

    const [, sendQueue, remoteHost, remotePort] = match;

    return {
      timestamp: Date.now(),
      serverName: this.serverName,
      method: 'TCP',
      url: `https://${remoteHost}:${remotePort}/`,
      destinationIp: remoteHost,
      port: parseInt(remotePort, 10),
      requestSize: parseInt(sendQueue, 10),
      tls: parseInt(remotePort, 10) === 443,
    };
  }

  /**
   * Windows: Parse a CSV row from PowerShell `Get-NetTCPConnection | ConvertTo-Csv`.
   * Format: "LocalAddress","LocalPort","RemoteAddress","RemotePort"
   * Example: "192.168.1.5","54123","172.64.155.209","443"
   */
  private parsePowerShellLine(line: string): NetworkEvent | null {
    // CSV values may be quoted or unquoted depending on PS version
    const match = line.match(/^"?([^",]+)"?,"\d+","?([^",]+)"?,"?(\d+)"?/);
    if (!match) return null;

    const [, , remoteAddress, remotePort] = match;
    const port = parseInt(remotePort, 10);

    // Skip RFC-1918 private addresses and loopback (already filtered by PS
    // but guard here in case the regex misses edge cases)
    if (
      remoteAddress === '127.0.0.1' ||
      remoteAddress === '::1' ||
      remoteAddress.startsWith('10.') ||
      remoteAddress.startsWith('192.168.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(remoteAddress)
    ) {
      return null;
    }

    return {
      timestamp: Date.now(),
      serverName: this.serverName,
      method: 'TCP',
      url: `https://${remoteAddress}:${remotePort}/`,
      destinationIp: remoteAddress,
      port,
      requestSize: 0,
      tls: port === 443,
    };
  }

  // ── DNS Enrichment ──

  /**
   * Reverse-DNS lookup with a session-scoped cache.
   * Returns the first PTR record if available, otherwise the raw IP.
   *
   * WHY this matters: Sentinel's endpoint patterns match against known-bad
   * hostnames (pastebin.com, ngrok.io, etc.). Without DNS enrichment, lsof/ss/
   * netstat all return raw IPs and those patterns would silently miss every hit.
   */
  private async resolveIp(ip: string): Promise<string> {
    const cached = this.dnsCache.get(ip);
    if (cached !== undefined) return cached;

    try {
      const hostnames = await dnsPromises.reverse(ip);
      const hostname = hostnames[0] ?? ip;
      this.dnsCache.set(ip, hostname);
      return hostname;
    } catch {
      // Reverse DNS failed (common for CDN IPs) — fall back to raw IP
      this.dnsCache.set(ip, ip);
      return ip;
    }
  }

  /**
   * Enrich a NetworkEvent's url field with a resolved hostname.
   * Returns a new event object (does not mutate the original).
   */
  private async enrichWithHostname(event: NetworkEvent): Promise<NetworkEvent> {
    if (!event.destinationIp) return event;
    const hostname = await this.resolveIp(event.destinationIp);
    if (hostname === event.destinationIp) return event; // No change
    return {
      ...event,
      url: `https://${hostname}:${event.port}/`,
    };
  }
}

// ──────────────────────────────────────────────────────────
// SUBSCRIPTION GATING
// Sentinel is a premium feature (Pro tier and above).
// ──────────────────────────────────────────────────────────

// Launch tiers: free + pro only. Team and enterprise planned for future builds.
export type SubscriptionTier = 'free' | 'pro';

export interface SentinelFeatureGate {
  /** Whether Sentinel monitoring is available */
  monitoringEnabled: boolean;
  /** Maximum monitoring duration in seconds */
  maxDurationSeconds: number;
  /** Maximum number of servers to monitor simultaneously */
  maxConcurrentServers: number;
  /** Whether behavioral detection is available (vs. endpoint-only) */
  behavioralDetection: boolean;
  /** Whether real-time alerts are enabled */
  realTimeAlerts: boolean;
  /** Whether historical Sentinel data is stored */
  historyRetentionDays: number;
  /** Whether API access to Sentinel data is available */
  apiAccess: boolean;
}

export function getSentinelFeatures(tier: SubscriptionTier): SentinelFeatureGate {
  switch (tier) {
    case 'free':
      return {
        monitoringEnabled: false, // Upgrade required
        maxDurationSeconds: 0,
        maxConcurrentServers: 0,
        behavioralDetection: false,
        realTimeAlerts: false,
        historyRetentionDays: 0,
        apiAccess: false,
      };
    case 'pro':
      return {
        monitoringEnabled: true,
        maxDurationSeconds: 300, // 5 minutes
        maxConcurrentServers: 3,
        behavioralDetection: true,
        realTimeAlerts: false, // Future: Team+ only
        historyRetentionDays: 7,
        apiAccess: true,
      };
    // Future tiers — uncomment when team/enterprise plans launch
    // case 'team':
    //   return {
    //     monitoringEnabled: true,
    //     maxDurationSeconds: 1800, // 30 minutes
    //     maxConcurrentServers: 10,
    //     behavioralDetection: true,
    //     realTimeAlerts: true,
    //     historyRetentionDays: 30,
    //     apiAccess: true,
    //   };
    // case 'enterprise':
    //   return {
    //     monitoringEnabled: true,
    //     maxDurationSeconds: -1, // Unlimited (continuous)
    //     maxConcurrentServers: -1, // Unlimited
    //     behavioralDetection: true,
    //     realTimeAlerts: true,
    //     historyRetentionDays: 365,
    //     apiAccess: true,
    //   };
  }
}

/**
 * Pretty marketing name for tier-gated Sentinel features.
 * Used in CLI output and web UI.
 */
export const SENTINEL_MARKETING = {
  tagline: 'Always watching what your tools are doing.',
  featureName: 'Vigile Sentinel',
  tierName: 'Sentinel Protection',
  upgradePrompt:
    '🛡️ Vigile Sentinel is a Pro feature. Upgrade at https://vigile.dev/pricing to monitor your MCP servers for real-time phone-home detection.',
  categories: [
    { icon: '📡', name: 'C2 Beaconing Detection', desc: 'Catches tools phoning home on a schedule' },
    { icon: '🔐', name: 'Credential Theft Alerts', desc: 'Detects SSH keys & API tokens leaving your machine' },
    { icon: '🕵️', name: 'DNS Tunneling Detection', desc: 'Spots data hidden in DNS queries' },
    { icon: '📊', name: 'Behavioral Analysis', desc: 'Machine-learning-ready traffic pattern analysis' },
    { icon: '⚡', name: 'Real-Time Alerts', desc: 'Instant notification when threats are detected' },
    { icon: '🛡️', name: 'Continuous Monitoring', desc: '24/7 protection for enterprise environments' },
  ],
} as const;
