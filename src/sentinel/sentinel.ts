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
   * The monitor works in three modes depending on the OS and permissions:
   *   1. macOS: Uses `nettop` or `networksetup` + `tcpdump`
   *   2. Linux: Uses `ss` polling + optional `tcpdump`
   *   3. Fallback: Uses Node.js HTTP/HTTPS module monkey-patching
   *      (only captures Node.js HTTP requests from the current process tree)
   */
  async startMonitoring(): Promise<void> {
    this.startTime = Date.now();
    this.events = [];
    this.findings = [];

    // Detect which monitoring method is available
    const method = this.detectMonitoringMethod();

    switch (method) {
      case 'lsof-poll':
        await this.startLsofPolling();
        break;
      case 'ss-poll':
        await this.startSsPolling();
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

  private detectMonitoringMethod(): 'lsof-poll' | 'ss-poll' | 'proxy' {
    try {
      execFileSync('/usr/bin/which', ['lsof'], { stdio: 'pipe' });
      return 'lsof-poll';
    } catch {
      try {
        execFileSync('/usr/bin/which', ['ss'], { stdio: 'pipe' });
        return 'ss-poll';
      } catch {
        return 'proxy';
      }
    }
  }

  /**
   * macOS/Linux: Poll `lsof` to capture network connections for a process.
   * This is the lowest-privilege method — no root needed.
   */
  private async startLsofPolling(): Promise<void> {
    // Sanitize serverName to prevent injection — only allow safe chars
    const safeName = this.serverName.replace(/[^a-zA-Z0-9._@/-]/g, '');

    const pollInterval = setInterval(() => {
      try {
        // Use execFileSync to avoid shell injection. Pipe lsof through grep
        // by running them separately.
        const lsofOutput = execFileSync('/usr/sbin/lsof', ['-i', '-n', '-P'], {
          timeout: 5000,
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        // Filter in-process instead of piping through shell
        const output = lsofOutput
          .split('\n')
          .filter(line => line.toLowerCase().includes(safeName.toLowerCase()));

        for (const line of output.filter(Boolean)) {
          const event = this.parseLsofLine(line);
          if (event) this.ingestEvent(event);
        }
      } catch {
        // lsof failed, continue
      }
    }, 2000); // Poll every 2 seconds

    // Store cleanup handle
    this.monitorProcess = {
      kill: () => clearInterval(pollInterval),
    } as unknown as ChildProcess;

    // Auto-stop after duration
    setTimeout(() => {
      clearInterval(pollInterval);
    }, this.durationSeconds * 1000);
  }

  /**
   * Linux: Poll `ss` (socket statistics) for network connections.
   */
  private async startSsPolling(): Promise<void> {
    const safeName = this.serverName.replace(/[^a-zA-Z0-9._@/-]/g, '');

    const pollInterval = setInterval(() => {
      try {
        const ssOutput = execFileSync('/usr/sbin/ss', ['-tnp'], {
          timeout: 5000,
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        // Filter in-process instead of piping through shell
        const lines = ssOutput
          .split('\n')
          .filter(line => line.includes(safeName));

        for (const line of lines.filter(Boolean)) {
          const event = this.parseSsLine(line);
          if (event) this.ingestEvent(event);
        }
      } catch {
        // ss failed, continue
      }
    }, 2000);

    this.monitorProcess = {
      kill: () => clearInterval(pollInterval),
    } as unknown as ChildProcess;

    setTimeout(() => {
      clearInterval(pollInterval);
    }, this.durationSeconds * 1000);
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
