import { describe, it, expect } from 'vitest';
import {
  SUSPICIOUS_ENDPOINT_PATTERNS,
  BEHAVIORAL_PATTERNS,
  CREDENTIAL_EXFIL_PATTERNS,
  calculateThreatScore,
  threatLevelFromScore,
  type NetworkEvent,
  type SentinelFinding,
} from '../../src/sentinel/sentinel-patterns.js';

function makeEvent(overrides: Partial<NetworkEvent> = {}): NetworkEvent {
  return {
    timestamp: Date.now(),
    serverName: 'test-server',
    method: 'TCP',
    url: 'https://example.com/api',
    port: 443,
    requestSize: 100,
    tls: true,
    ...overrides,
  };
}

function makeFinding(overrides: Partial<SentinelFinding> = {}): SentinelFinding {
  return {
    id: 'SN-TEST',
    category: 'phone-home',
    severity: 'medium',
    title: 'Test finding',
    description: 'Test',
    serverName: 'test-server',
    evidence: [],
    recommendation: 'Test',
    confidence: 80,
    ...overrides,
  };
}

describe('Endpoint Patterns', () => {
  it('should have 7 endpoint patterns', () => {
    expect(SUSPICIOUS_ENDPOINT_PATTERNS).toHaveLength(7);
  });

  it('SN-001: detects paste/file sharing exfiltration', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-001')!;
    expect(pattern.urlPattern.test('https://pastebin.com/api/create')).toBe(true);
    expect(pattern.urlPattern.test('https://transfer.sh/upload')).toBe(true);
    expect(pattern.urlPattern.test('https://hastebin.com/documents')).toBe(true);
    expect(pattern.urlPattern.test('https://file.io/upload')).toBe(true);
    expect(pattern.urlPattern.test('https://0x0.st/upload')).toBe(true);
    expect(pattern.urlPattern.test('https://ix.io/api')).toBe(true);
    expect(pattern.urlPattern.test('https://github.com/api')).toBe(false);
    expect(pattern.urlPattern.test('https://npmjs.org/package/express')).toBe(false);
  });

  it('SN-002: detects webhook exfiltration', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-002')!;
    expect(pattern.urlPattern.test('https://hooks.slack.com/services/T00/B00/xxx')).toBe(true);
    expect(pattern.urlPattern.test('https://discord.com/api/webhooks/123/abc')).toBe(true);
    expect(pattern.urlPattern.test('https://webhook.site/abc-123')).toBe(true);
    expect(pattern.urlPattern.test('https://pipedream.net/xxx')).toBe(true);
    expect(pattern.urlPattern.test('https://beeceptor.com/console/test')).toBe(true);
    expect(pattern.urlPattern.test('https://api.github.com/hooks')).toBe(false);
  });

  it('SN-003: detects dynamic DNS/tunneling', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-003')!;
    expect(pattern.urlPattern.test('https://abc.ngrok.io/callback')).toBe(true);
    expect(pattern.urlPattern.test('https://abc.ngrok-free.app/callback')).toBe(true);
    expect(pattern.urlPattern.test('https://test.duckdns.org/')).toBe(true);
    expect(pattern.urlPattern.test('https://myapp.serveo.net/')).toBe(true);
    expect(pattern.urlPattern.test('https://tunnel.localhost.run/')).toBe(true);
    expect(pattern.urlPattern.test('https://api.github.com/')).toBe(false);
  });

  it('SN-004: detects cryptocurrency endpoints', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-004')!;
    expect(pattern).toBeDefined();
    expect(pattern.urlPattern.test('https://blockchain.info/api/balance')).toBe(true);
    expect(pattern.urlPattern.test('https://api.etherscan.io/api/account')).toBe(true);
    expect(pattern.urlPattern.test('https://solscan.io/api/account')).toBe(true);
    expect(pattern.urlPattern.test('https://mempool.space/api/tx')).toBe(true);
    expect(pattern.urlPattern.test('https://api.github.com/repos')).toBe(false);
    expect(pattern.severity).toBe('high');
  });

  it('SN-005: detects telemetry/analytics to unknown endpoints', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-005')!;
    expect(pattern).toBeDefined();
    expect(pattern.urlPattern.test('https://unknown.com/telemetry?data=x')).toBe(true);
    expect(pattern.urlPattern.test('https://evil.com/analytics?user=123')).toBe(true);
    expect(pattern.urlPattern.test('https://evil.com/tracking/')).toBe(true);
    expect(pattern.urlPattern.test('https://evil.com/beacon?id=1')).toBe(true);
    expect(pattern.urlPattern.test('https://evil.com/metrics?')).toBe(true);
    expect(pattern.urlPattern.test('https://api.github.com/repos')).toBe(false);
    expect(pattern.severity).toBe('medium');
  });

  it('SN-006: detects raw IP connections', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-006')!;
    expect(pattern.urlPattern.test('https://192.168.1.1/exfil')).toBe(true);
    expect(pattern.urlPattern.test('https://10.0.0.1:8080/')).toBe(true);
    expect(pattern.urlPattern.test('http://172.16.0.1/')).toBe(true);
    expect(pattern.urlPattern.test('https://api.example.com/')).toBe(false);
  });

  it('SN-007: detects non-standard port connections', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-007')!;
    expect(pattern.urlPattern.test('https://evil.com:9999/')).toBe(true);
    expect(pattern.urlPattern.test('https://evil.com:4444/')).toBe(true);
    expect(pattern.urlPattern.test('http://server.com:31337/')).toBe(true);
    // Standard ports should not match
    expect(pattern.urlPattern.test('https://api.com:443/')).toBe(false);
    expect(pattern.urlPattern.test('https://api.com:8080/')).toBe(false);
    expect(pattern.urlPattern.test('http://api.com:3000/')).toBe(false);
    expect(pattern.urlPattern.test('http://api.com:5000/')).toBe(false);
    expect(pattern.urlPattern.test('http://api.com:8000/')).toBe(false);
    expect(pattern.urlPattern.test('https://api.com:8443/')).toBe(false);
  });
});

describe('Behavioral Patterns', () => {
  it('should have 6 behavioral patterns', () => {
    expect(BEHAVIORAL_PATTERNS).toHaveLength(6);
  });

  describe('SN-010: C2 beaconing detection', () => {
    const pattern = BEHAVIORAL_PATTERNS.find((p) => p.id === 'SN-010')!;

    it('detects regular interval beaconing', () => {
      // 5 events at exactly 10-second intervals to the same host
      const events: NetworkEvent[] = Array.from({ length: 6 }, (_, i) =>
        makeEvent({
          timestamp: 1000 + i * 10000, // every 10s
          url: 'https://c2.evil.com/beacon',
        })
      );
      const confidence = pattern.detect(events);
      expect(confidence).toBeGreaterThanOrEqual(80);
    });

    it('returns 0 for random timing events', () => {
      const events: NetworkEvent[] = [
        makeEvent({ timestamp: 1000, url: 'https://a.com/x' }),
        makeEvent({ timestamp: 5000, url: 'https://b.com/y' }),
        makeEvent({ timestamp: 5500, url: 'https://c.com/z' }),
        makeEvent({ timestamp: 20000, url: 'https://d.com/w' }),
        makeEvent({ timestamp: 90000, url: 'https://e.com/v' }),
      ];
      const confidence = pattern.detect(events);
      expect(confidence).toBeLessThan(60);
    });

    it('needs at least 5 events', () => {
      const events = Array.from({ length: 3 }, (_, i) =>
        makeEvent({ timestamp: 1000 + i * 10000, url: 'https://c2.com/beacon' })
      );
      expect(pattern.detect(events)).toBe(0);
    });
  });

  describe('SN-011: Burst data exfiltration', () => {
    const pattern = BEHAVIORAL_PATTERNS.find((p) => p.id === 'SN-011')!;

    it('detects single large request (>50KB)', () => {
      const events = [makeEvent({ requestSize: 60_000 })];
      expect(pattern.detect(events)).toBeGreaterThanOrEqual(90);
    });

    it('detects burst of smaller requests totaling >200KB', () => {
      const events = Array.from({ length: 5 }, () =>
        makeEvent({ requestSize: 50_000 })
      );
      expect(pattern.detect(events)).toBeGreaterThanOrEqual(85);
    });

    it('returns 0 for small requests', () => {
      const events = [makeEvent({ requestSize: 500 })];
      expect(pattern.detect(events)).toBe(0);
    });
  });

  describe('SN-014: High-entropy payload transmission', () => {
    const pattern = BEHAVIORAL_PATTERNS.find((p) => p.id === 'SN-014')!;

    it('detects high-entropy large payloads', () => {
      const events = Array.from({ length: 5 }, () =>
        makeEvent({ bodyEntropy: 7.5, requestSize: 5000 })
      );
      expect(pattern.detect(events)).toBeGreaterThanOrEqual(70);
    });

    it('ignores small high-entropy payloads', () => {
      const events = Array.from({ length: 5 }, () =>
        makeEvent({ bodyEntropy: 7.8, requestSize: 100 })
      );
      expect(pattern.detect(events)).toBe(0);
    });
  });
});

describe('Credential Exfiltration Patterns', () => {
  it('should have 3 patterns', () => {
    expect(CREDENTIAL_EXFIL_PATTERNS).toHaveLength(3);
  });

  it('SN-020: detects SSH keys in URL params', () => {
    const pattern = CREDENTIAL_EXFIL_PATTERNS.find((p) => p.id === 'SN-020')!;
    expect(
      pattern.urlPattern.test('https://evil.com?data=ssh-rsa+AAAA...')
    ).toBe(true);
    expect(pattern.severity).toBe('critical');
  });

  it('SN-021: detects API keys in URL params', () => {
    const pattern = CREDENTIAL_EXFIL_PATTERNS.find((p) => p.id === 'SN-021')!;
    expect(
      pattern.urlPattern.test(
        'https://evil.com?token=sk_live_abcdefghijklmnopqrstuvwx'
      )
    ).toBe(true);
    // Test/demo values should NOT match
    expect(
      pattern.urlPattern.test('https://evil.com?token=test')
    ).toBe(false);
  });

  it('SN-022: detects AWS credentials', () => {
    const pattern = CREDENTIAL_EXFIL_PATTERNS.find((p) => p.id === 'SN-022')!;
    expect(pattern.urlPattern.test('AKIAIOSFODNN7EXAMPLE')).toBe(true);
    expect(
      pattern.urlPattern.test('aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCY')
    ).toBe(true);
  });
});

describe('calculateThreatScore', () => {
  it('returns 0 for empty findings', () => {
    expect(calculateThreatScore([])).toBe(0);
  });

  it('weights by severity', () => {
    const critical = calculateThreatScore([makeFinding({ severity: 'critical', confidence: 100 })]);
    const high = calculateThreatScore([makeFinding({ severity: 'high', confidence: 100 })]);
    const medium = calculateThreatScore([makeFinding({ severity: 'medium', confidence: 100 })]);

    expect(critical).toBeGreaterThan(high);
    expect(high).toBeGreaterThan(medium);
  });

  it('weights by confidence', () => {
    const highConf = calculateThreatScore([makeFinding({ severity: 'critical', confidence: 100 })]);
    const lowConf = calculateThreatScore([makeFinding({ severity: 'critical', confidence: 50 })]);
    expect(highConf).toBeGreaterThan(lowConf);
  });

  it('caps score at 100', () => {
    const manyFindings = Array.from({ length: 20 }, (_, i) =>
      makeFinding({ id: `SN-${i}`, severity: 'critical', confidence: 100 })
    );
    expect(calculateThreatScore(manyFindings)).toBe(100);
  });
});

describe('threatLevelFromScore', () => {
  it('returns clean for low scores', () => {
    expect(threatLevelFromScore(0)).toBe('clean');
    expect(threatLevelFromScore(14)).toBe('clean');
  });

  it('returns suspicious for moderate scores', () => {
    expect(threatLevelFromScore(15)).toBe('suspicious');
    expect(threatLevelFromScore(39)).toBe('suspicious');
  });

  it('returns malicious for high scores', () => {
    expect(threatLevelFromScore(40)).toBe('malicious');
    expect(threatLevelFromScore(69)).toBe('malicious');
  });

  it('returns critical for very high scores', () => {
    expect(threatLevelFromScore(70)).toBe('critical');
    expect(threatLevelFromScore(100)).toBe('critical');
  });
});

// ── Missing Behavioral Pattern Tests ────────────────────────

describe('SN-012: DNS tunneling detection', () => {
  const pattern = BEHAVIORAL_PATTERNS.find((p) => p.id === 'SN-012')!;

  it('detects high-entropy DNS subdomains', () => {
    // 12 DNS events with long base64-like subdomains
    const events: NetworkEvent[] = Array.from({ length: 12 }, (_, i) =>
      makeEvent({
        timestamp: 1000 + i * 5000,
        url: `https://aGVsbG8gd29ybGQgdGhpcyBpcyBlbmNvZGVk${i}.evil.com/`,
        dnsQueryType: 'A',
      })
    );
    const confidence = pattern.detect(events);
    expect(confidence).toBeGreaterThanOrEqual(40);
  });

  it('returns 0 for normal DNS with <10 events', () => {
    const events: NetworkEvent[] = Array.from({ length: 5 }, (_, i) =>
      makeEvent({
        timestamp: 1000 + i * 5000,
        url: 'https://api.github.com/',
        dnsQueryType: 'A',
      })
    );
    expect(pattern.detect(events)).toBe(0);
  });

  it('returns 0 when no DNS events present', () => {
    const events: NetworkEvent[] = Array.from({ length: 15 }, (_, i) =>
      makeEvent({ timestamp: 1000 + i * 1000 })
    );
    expect(pattern.detect(events)).toBe(0);
  });
});

describe('SN-013: Multi-destination scatter exfiltration', () => {
  const pattern = BEHAVIORAL_PATTERNS.find((p) => p.id === 'SN-013')!;

  it('detects >10 destinations with data', () => {
    const events: NetworkEvent[] = Array.from({ length: 12 }, (_, i) =>
      makeEvent({
        timestamp: 1000 + i * 1000,
        url: `https://dest${i}.example.com/upload`,
        requestSize: 1000,
      })
    );
    expect(pattern.detect(events)).toBeGreaterThanOrEqual(85);
  });

  it('detects >5 destinations with data', () => {
    const events: NetworkEvent[] = Array.from({ length: 6 }, (_, i) =>
      makeEvent({
        timestamp: 1000 + i * 1000,
        url: `https://dest${i}.example.com/upload`,
        requestSize: 1000,
      })
    );
    expect(pattern.detect(events)).toBeGreaterThanOrEqual(65);
  });

  it('returns 0 for small request sizes', () => {
    // Many destinations but request_size <= 500 (threshold)
    const events: NetworkEvent[] = Array.from({ length: 15 }, (_, i) =>
      makeEvent({
        timestamp: 1000 + i * 1000,
        url: `https://dest${i}.example.com/ping`,
        requestSize: 100,
      })
    );
    expect(pattern.detect(events)).toBe(0);
  });

  it('returns 0 for few destinations', () => {
    // Only 2 unique destinations
    const events: NetworkEvent[] = Array.from({ length: 10 }, (_, i) =>
      makeEvent({
        timestamp: 1000 + i * 1000,
        url: `https://dest${i % 2}.example.com/upload`,
        requestSize: 1000,
      })
    );
    expect(pattern.detect(events)).toBe(0);
  });
});

describe('SN-015: Unexpected outbound during idle', () => {
  const pattern = BEHAVIORAL_PATTERNS.find((p) => p.id === 'SN-015')!;

  it('detects 3+ events as suspicious', () => {
    const events: NetworkEvent[] = Array.from({ length: 3 }, (_, i) =>
      makeEvent({ timestamp: 1000 + i * 10000 })
    );
    expect(pattern.detect(events)).toBeGreaterThanOrEqual(50);
  });

  it('detects 2 events at lower confidence', () => {
    const events: NetworkEvent[] = Array.from({ length: 2 }, (_, i) =>
      makeEvent({ timestamp: 1000 + i * 10000 })
    );
    const confidence = pattern.detect(events);
    expect(confidence).toBeGreaterThanOrEqual(30);
    expect(confidence).toBeLessThan(50);
  });

  it('returns 0 for single event', () => {
    expect(pattern.detect([makeEvent()])).toBe(0);
  });
});

// ── Edge Cases ──────────────────────────────────────────────

describe('Edge Cases', () => {
  it('beaconing: handles zero-interval timestamps without crashing', () => {
    const pattern = BEHAVIORAL_PATTERNS.find((p) => p.id === 'SN-010')!;
    // All same timestamp → mean=0 → CV would be division by zero
    const events: NetworkEvent[] = Array.from({ length: 6 }, () =>
      makeEvent({ timestamp: 1000, url: 'https://same.host.com/beacon' })
    );
    // Should not throw
    expect(() => pattern.detect(events)).not.toThrow();
    // Mean is 0, so cv = std/mean → guarded by mean > 0 check
    expect(pattern.detect(events)).toBe(0);
  });

  it('burst: exactly at 50KB boundary', () => {
    const pattern = BEHAVIORAL_PATTERNS.find((p) => p.id === 'SN-011')!;
    // Exactly 50,000 — should NOT trigger (> threshold, not >=)
    const atBoundary = [makeEvent({ requestSize: 50_000 })];
    expect(pattern.detect(atBoundary)).toBe(0);

    // 50,001 — should trigger
    const aboveBoundary = [makeEvent({ requestSize: 50_001 })];
    expect(pattern.detect(aboveBoundary)).toBeGreaterThanOrEqual(90);
  });

  it('burst: 200KB total triggers at 85, 100-200KB at 60', () => {
    const pattern = BEHAVIORAL_PATTERNS.find((p) => p.id === 'SN-011')!;
    // 200KB exactly = NOT > 200KB, but IS > 100KB → triggers mid-tier (60)
    const at200K = Array.from({ length: 4 }, () =>
      makeEvent({ requestSize: 50_000 })
    );
    expect(pattern.detect(at200K)).toBe(60);

    // 200,001 total — should trigger top tier (85)
    const above200K = [
      ...Array.from({ length: 4 }, () => makeEvent({ requestSize: 50_000 })),
      makeEvent({ requestSize: 1 }),
    ];
    expect(pattern.detect(above200K)).toBeGreaterThanOrEqual(85);

    // 100KB exactly = NOT > 100KB → returns 0
    const at100K = Array.from({ length: 2 }, () =>
      makeEvent({ requestSize: 50_000 })
    );
    expect(pattern.detect(at100K)).toBe(0);
  });

  it('SN-007: three-digit ports should NOT match (regex requires 4-5 digits)', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-007')!;
    expect(pattern.urlPattern.test('http://evil.com:999/')).toBe(false);
    expect(pattern.urlPattern.test('http://evil.com:22/')).toBe(false);
  });

  it('SN-006: localhost IPs should still match (127.x.x.x)', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-006')!;
    expect(pattern.urlPattern.test('http://127.0.0.1/')).toBe(true);
    expect(pattern.urlPattern.test('http://127.0.0.1:3000/')).toBe(true);
  });

  it('threat score handles unknown severity gracefully', () => {
    const result = calculateThreatScore([
      makeFinding({ severity: 'unknown' as any, confidence: 100 }),
    ]);
    // Should use fallback weight of 2
    expect(result).toBe(2);
  });
});
