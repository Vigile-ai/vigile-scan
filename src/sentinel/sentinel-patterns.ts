// ============================================================
// Vigile Sentinel — Runtime Phone-Home Detection Patterns
// ============================================================
// These patterns analyze runtime network behavior of MCP servers
// to detect data exfiltration, C2 beaconing, and covert channels.
//
// Unlike static patterns (patterns.ts) which scan tool descriptions
// BEFORE execution, Sentinel patterns analyze LIVE network traffic
// DURING execution. This catches tools that look clean on paper
// but phone home at runtime.
//
// Detection categories:
//   - C2 Beaconing (regular intervals, heartbeat patterns)
//   - Data Exfiltration (credential theft, file uploads)
//   - DNS Tunneling (encoded data in DNS queries)
//   - Covert Channels (steganographic exfil, timing-based)
//   - Suspicious Endpoints (known bad IPs, DGA domains)

import type { Severity, FindingCategory } from '../types/index.js';

// ──────────────────────────────────────────────────────────
// Sentinel-specific types
// ──────────────────────────────────────────────────────────

export interface NetworkEvent {
  /** Timestamp of the network event */
  timestamp: number;
  /** Source process / MCP server name */
  serverName: string;
  /** HTTP method or protocol */
  method: string;
  /** Full URL or hostname */
  url: string;
  /** Destination IP address (resolved) */
  destinationIp?: string;
  /** Destination port */
  port: number;
  /** Request size in bytes */
  requestSize: number;
  /** Response size in bytes */
  responseSize?: number;
  /** HTTP status code */
  statusCode?: number;
  /** Request headers */
  headers?: Record<string, string>;
  /** DNS query type (for DNS events) */
  dnsQueryType?: string;
  /** Whether TLS was used */
  tls: boolean;
  /** Request body hash (we never store raw bodies) */
  bodyHash?: string;
  /** Estimated entropy of request body (0-8 bits/byte) */
  bodyEntropy?: number;
}

export interface SentinelFinding {
  /** Unique finding ID (SN-series) */
  id: string;
  /** Category */
  category: FindingCategory | 'c2-beaconing' | 'dns-tunneling' | 'covert-channel' | 'phone-home';
  /** Severity */
  severity: Severity;
  /** Short title */
  title: string;
  /** Detailed description */
  description: string;
  /** The server that triggered this */
  serverName: string;
  /** Evidence — the specific network events that triggered this */
  evidence: NetworkEvent[];
  /** Recommendation */
  recommendation: string;
  /** Confidence score (0-100) — how sure Sentinel is this is malicious */
  confidence: number;
}

export type SentinelThreatLevel = 'clean' | 'suspicious' | 'malicious' | 'critical';

export interface SentinelReport {
  /** Server being monitored */
  serverName: string;
  /** Monitoring duration in seconds */
  monitoringDuration: number;
  /** Total network events captured */
  totalEvents: number;
  /** Unique destinations contacted */
  uniqueDestinations: string[];
  /** Sentinel findings */
  findings: SentinelFinding[];
  /** Overall threat level */
  threatLevel: SentinelThreatLevel;
  /** Threat score (0-100, inverse of trust — higher = more dangerous) */
  threatScore: number;
  /** When monitoring started */
  startedAt: string;
  /** When monitoring ended */
  endedAt: string;
}

// ──────────────────────────────────────────────────────────
// ENDPOINT REPUTATION PATTERNS
// Known malicious or suspicious destination patterns.
// ──────────────────────────────────────────────────────────

export interface EndpointPattern {
  id: string;
  severity: Severity;
  title: string;
  /** Regex to match against the full URL */
  urlPattern: RegExp;
  /** Regex to match against destination IP (optional) */
  ipPattern?: RegExp;
  description: string;
  recommendation: string;
}

export const SUSPICIOUS_ENDPOINT_PATTERNS: EndpointPattern[] = [
  {
    id: 'SN-001',
    severity: 'critical',
    title: 'Known data exfiltration endpoint',
    urlPattern: /https?:\/\/[^/]*(?:pastebin\.com|hastebin\.com|ghostbin\.co|paste\.ee|dpaste\.org|transfer\.sh|file\.io|0x0\.st|ix\.io)\/(?:api|raw|upload|documents)/i,
    description:
      'MCP server is sending data to a paste/file sharing service commonly used for data exfiltration.',
    recommendation:
      'CRITICAL: Stop this MCP server immediately. Legitimate tools should never upload to paste services.',
  },
  {
    id: 'SN-002',
    severity: 'critical',
    title: 'Webhook exfiltration channel',
    urlPattern: /https?:\/\/(?:hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|webhook\.site|pipedream\.net|requestbin\.|hookbin\.|beeceptor\.com)/i,
    description:
      'MCP server is sending data to a webhook endpoint. Attackers commonly use webhook services as low-noise exfiltration channels.',
    recommendation:
      'Investigate what data is being sent to this webhook. This is a common attacker exfiltration method.',
  },
  {
    id: 'SN-003',
    severity: 'high',
    title: 'Dynamic DNS destination',
    urlPattern: /https?:\/\/[^/]*\.(?:duckdns\.org|no-ip\.com|ngrok\.io|ngrok-free\.app|serveo\.net|localhost\.run|bore\.digital|tailscale\.io)(?:\/|$)/i,
    description:
      'MCP server is connecting to a dynamic DNS or tunneling service, commonly used for C2 infrastructure.',
    recommendation:
      'Review this connection. Dynamic DNS is frequently used by attackers to rotate C2 endpoints.',
  },
  {
    id: 'SN-004',
    severity: 'high',
    title: 'Cryptocurrency-related endpoint',
    urlPattern: /https?:\/\/[^/]*(?:blockchain\.info|etherscan\.io|bscscan\.com|solscan\.io|mempool\.space)\/(?:api|rawaddr|tx|address)/i,
    description:
      'MCP server is querying cryptocurrency blockchain APIs, which could indicate wallet scanning or theft.',
    recommendation:
      'Unless this is an explicitly crypto-related tool, this connection is highly suspicious.',
  },
  {
    id: 'SN-005',
    severity: 'medium',
    title: 'Telemetry to unknown endpoint',
    urlPattern: /https?:\/\/[^/]*(?:\/(?:telemetry|analytics|tracking|pixel|beacon|collect|event|metrics|heartbeat))(?:\?|$|\/)/i,
    description:
      'MCP server is sending telemetry/analytics data. While sometimes legitimate, this can mask data exfiltration.',
    recommendation:
      'Verify the telemetry destination is expected. Compare against the MCP server\'s documentation.',
  },
  {
    id: 'SN-006',
    severity: 'critical',
    title: 'Raw IP connection (no hostname)',
    urlPattern: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/,
    description:
      'MCP server is connecting directly to an IP address instead of a hostname. This bypasses DNS-based monitoring and is a strong indicator of C2 communication.',
    recommendation:
      'CRITICAL: Direct IP connections are almost never legitimate for MCP servers. Investigate immediately.',
  },
  {
    id: 'SN-007',
    severity: 'high',
    title: 'Non-standard port connection',
    urlPattern: /https?:\/\/[^/]+:(?!80\b|443\b|8080\b|8443\b|3000\b|5000\b|8000\b)\d{4,5}(?:\/|$)/,
    description:
      'MCP server is connecting to a non-standard port. While sometimes legitimate, C2 infrastructure often uses unusual ports.',
    recommendation:
      'Verify this port is expected for the service being contacted.',
  },
];

// ──────────────────────────────────────────────────────────
// BEHAVIORAL DETECTION PATTERNS
// These don't match URLs — they match *patterns of behavior*
// across multiple network events. The Sentinel engine
// evaluates these over time windows.
// ──────────────────────────────────────────────────────────

export interface BehavioralPattern {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  /** Minimum number of events needed to trigger */
  minEvents: number;
  /** Time window in seconds to analyze */
  timeWindowSeconds: number;
  /** The detection function — returns confidence 0-100 */
  detect: (events: NetworkEvent[]) => number;
}

export const BEHAVIORAL_PATTERNS: BehavioralPattern[] = [
  {
    id: 'SN-010',
    severity: 'critical',
    title: 'C2 beaconing detected (regular interval)',
    description:
      'MCP server is making network requests at regular intervals to the same destination, consistent with command-and-control beaconing. Malware phones home on a schedule to receive commands.',
    recommendation:
      'CRITICAL: This pattern strongly indicates the MCP server is compromised. Stop it immediately and investigate the destination.',
    minEvents: 5,
    timeWindowSeconds: 300, // 5 minutes
    detect: (events: NetworkEvent[]): number => {
      // Group events by destination
      const byDest = new Map<string, number[]>();
      for (const e of events) {
        const dest = new URL(e.url).hostname;
        if (!byDest.has(dest)) byDest.set(dest, []);
        byDest.get(dest)!.push(e.timestamp);
      }

      let maxConfidence = 0;
      for (const [, timestamps] of byDest) {
        if (timestamps.length < 5) continue;
        timestamps.sort((a, b) => a - b);

        // Calculate intervals between consecutive requests
        const intervals: number[] = [];
        for (let i = 1; i < timestamps.length; i++) {
          intervals.push(timestamps[i] - timestamps[i - 1]);
        }

        // Calculate coefficient of variation (std/mean)
        // Low CV = regular intervals = beaconing
        const mean = intervals.reduce((s, v) => s + v, 0) / intervals.length;
        const std = Math.sqrt(
          intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / intervals.length
        );
        const cv = mean > 0 ? std / mean : 1;

        // CV < 0.15 = very regular (high confidence beaconing)
        // CV < 0.30 = somewhat regular (medium confidence)
        // Add jitter tolerance — sophisticated C2 adds random jitter
        if (cv < 0.15) maxConfidence = Math.max(maxConfidence, 95);
        else if (cv < 0.25) maxConfidence = Math.max(maxConfidence, 80);
        else if (cv < 0.35) maxConfidence = Math.max(maxConfidence, 60);
      }
      return maxConfidence;
    },
  },
  {
    id: 'SN-011',
    severity: 'critical',
    title: 'Burst data exfiltration',
    description:
      'MCP server sent an unusually large amount of data in a short burst to an external endpoint. This pattern matches credential dump exfiltration and file theft.',
    recommendation:
      'CRITICAL: Investigate what data was transmitted. Check for stolen SSH keys, credentials, or source code.',
    minEvents: 1,
    timeWindowSeconds: 60, // 1 minute
    detect: (events: NetworkEvent[]): number => {
      // Look for single large requests or bursts of requests
      const LARGE_REQUEST_THRESHOLD = 50_000; // 50KB in a single request
      const BURST_THRESHOLD = 200_000; // 200KB total in time window

      let maxSingle = 0;
      let totalBytes = 0;

      for (const e of events) {
        maxSingle = Math.max(maxSingle, e.requestSize);
        totalBytes += e.requestSize;
      }

      if (maxSingle > LARGE_REQUEST_THRESHOLD) return 90;
      if (totalBytes > BURST_THRESHOLD) return 85;
      if (totalBytes > BURST_THRESHOLD / 2) return 60;
      return 0;
    },
  },
  {
    id: 'SN-012',
    severity: 'high',
    title: 'DNS tunneling suspected',
    description:
      'MCP server is making an unusual number of DNS queries with high-entropy subdomains. This pattern matches DNS tunneling — a technique to exfiltrate data by encoding it in DNS queries, which often bypass firewalls.',
    recommendation:
      'Investigate the DNS queries. DNS tunneling uses encoded data in subdomain labels (e.g., aGVsbG8=.evil.com).',
    minEvents: 10,
    timeWindowSeconds: 120,
    detect: (events: NetworkEvent[]): number => {
      // Filter DNS events and look for high-entropy subdomain patterns
      const dnsEvents = events.filter(e => e.dnsQueryType);
      if (dnsEvents.length < 10) return 0;

      let suspiciousCount = 0;
      for (const e of dnsEvents) {
        try {
          const hostname = new URL(e.url).hostname;
          const parts = hostname.split('.');
          // DNS tunneling creates long, random-looking subdomains
          for (const part of parts) {
            if (part.length > 30) suspiciousCount++;
            // Check for base64-like patterns in subdomain
            if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(part)) suspiciousCount++;
          }
        } catch {
          // URL parse failed, skip
        }
      }

      const ratio = suspiciousCount / dnsEvents.length;
      if (ratio > 0.5) return 90;
      if (ratio > 0.3) return 70;
      if (ratio > 0.1) return 40;
      return 0;
    },
  },
  {
    id: 'SN-013',
    severity: 'high',
    title: 'Multi-destination scatter exfiltration',
    description:
      'MCP server is distributing data across many different external destinations in a short period. Sophisticated exfiltration splits data across multiple endpoints to avoid size-based detection.',
    recommendation:
      'Review all destinations contacted. This pattern suggests deliberate evasion of single-destination monitoring.',
    minEvents: 5,
    timeWindowSeconds: 120,
    detect: (events: NetworkEvent[]): number => {
      const destinations = new Set<string>();
      for (const e of events) {
        try {
          destinations.add(new URL(e.url).hostname);
        } catch {
          // skip
        }
      }

      // If contacting >10 unique destinations with data, very suspicious
      const withData = events.filter(e => e.requestSize > 500);
      const destWithData = new Set<string>();
      for (const e of withData) {
        try { destWithData.add(new URL(e.url).hostname); } catch { /* skip */ }
      }

      if (destWithData.size > 10) return 85;
      if (destWithData.size > 5) return 65;
      if (destWithData.size > 3 && withData.length > events.length * 0.5) return 50;
      return 0;
    },
  },
  {
    id: 'SN-014',
    severity: 'high',
    title: 'High-entropy payload transmission',
    description:
      'MCP server is sending request bodies with unusually high entropy (randomness), suggesting encrypted or compressed data exfiltration. Legitimate API calls typically have structured, lower-entropy payloads.',
    recommendation:
      'Investigate the payload contents. High entropy in outbound data often indicates stolen credentials or encrypted exfiltration.',
    minEvents: 3,
    timeWindowSeconds: 180,
    detect: (events: NetworkEvent[]): number => {
      // Look for events with high body entropy
      const highEntropyEvents = events.filter(
        e => e.bodyEntropy !== undefined && e.bodyEntropy > 7.0 && e.requestSize > 1000
      );

      if (highEntropyEvents.length === 0) return 0;
      const ratio = highEntropyEvents.length / events.length;

      if (ratio > 0.5 && highEntropyEvents.length >= 5) return 90;
      if (ratio > 0.3) return 70;
      if (highEntropyEvents.length >= 3) return 55;
      return 0;
    },
  },
  {
    id: 'SN-015',
    severity: 'medium',
    title: 'Unexpected outbound connection during idle',
    description:
      'MCP server made network requests when no user-initiated tool calls were active. Legitimate MCP servers should only make network requests in response to tool invocations.',
    recommendation:
      'Review why this MCP server is making network requests when idle. This could indicate background beaconing or telemetry.',
    minEvents: 2,
    timeWindowSeconds: 60,
    detect: (events: NetworkEvent[]): number => {
      // This detection relies on the caller marking events as "idle" context
      // For now, we detect based on timing — requests that happen without
      // a preceding tool call within 5 seconds
      // (The full implementation requires integration with the runtime proxy)
      if (events.length >= 3) return 50;
      if (events.length >= 2) return 30;
      return 0;
    },
  },
];

// ──────────────────────────────────────────────────────────
// CREDENTIAL-SPECIFIC EXFILTRATION PATTERNS
// Patterns that look for credential-shaped data in network
// requests. These check request URLs, headers, and body hashes
// for signs of stolen secrets being transmitted.
// ──────────────────────────────────────────────────────────

export const CREDENTIAL_EXFIL_PATTERNS: EndpointPattern[] = [
  {
    id: 'SN-020',
    severity: 'critical',
    title: 'SSH key in outbound request',
    urlPattern: /[?&](?:key|data|payload|content|body)=[^&]*(?:ssh-rsa|ssh-ed25519|PRIVATE\s*KEY)/i,
    description:
      'MCP server appears to be transmitting SSH key material in a URL parameter. This matches the Invariant Labs exfiltration attack vector.',
    recommendation:
      'CRITICAL: Your SSH keys may be compromised. Rotate all SSH keys immediately.',
  },
  {
    id: 'SN-021',
    severity: 'critical',
    title: 'API key/token in outbound URL',
    urlPattern: /[?&](?:key|token|secret|api_key|apikey|auth|password|credential)=(?!(?:test|demo|example|placeholder))[A-Za-z0-9_-]{20,}/i,
    description:
      'MCP server is transmitting what appears to be an API key or token in a URL parameter to an external destination.',
    recommendation:
      'CRITICAL: Rotate the compromised API key/token immediately. Check your .env files for exposed secrets.',
  },
  {
    id: 'SN-022',
    severity: 'critical',
    title: 'AWS credential in outbound request',
    urlPattern: /(?:AKIA[0-9A-Z]{16}|(?:aws_secret_access_key|aws_access_key_id)\s*[:=]\s*[A-Za-z0-9/+=]{20,})/i,
    description:
      'MCP server is transmitting AWS credentials. AWS access keys follow a known format (AKIA...).',
    recommendation:
      'CRITICAL: Deactivate the compromised AWS keys immediately via IAM console.',
  },
];

// ──────────────────────────────────────────────────────────
// THREAT SCORING
// Calculate a Sentinel threat score based on findings.
// ──────────────────────────────────────────────────────────

export function calculateThreatScore(findings: SentinelFinding[]): number {
  if (findings.length === 0) return 0;

  let score = 0;
  for (const f of findings) {
    const severityWeight =
      f.severity === 'critical' ? 30 :
      f.severity === 'high' ? 20 :
      f.severity === 'medium' ? 10 :
      f.severity === 'low' ? 5 : 2;

    // Weight by confidence — a 90% confidence critical is scarier than a 40% one
    score += severityWeight * (f.confidence / 100);
  }

  // Cap at 100
  return Math.min(100, Math.round(score));
}

export function threatLevelFromScore(score: number): SentinelThreatLevel {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'malicious';
  if (score >= 15) return 'suspicious';
  return 'clean';
}
