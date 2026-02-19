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
    expect(pattern.urlPattern.test('https://github.com/api')).toBe(false);
  });

  it('SN-002: detects webhook exfiltration', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-002')!;
    expect(pattern.urlPattern.test('https://hooks.slack.com/services/T00/B00/xxx')).toBe(true);
    expect(pattern.urlPattern.test('https://discord.com/api/webhooks/123/abc')).toBe(true);
    expect(pattern.urlPattern.test('https://webhook.site/abc-123')).toBe(true);
  });

  it('SN-003: detects dynamic DNS/tunneling', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-003')!;
    expect(pattern.urlPattern.test('https://abc.ngrok.io/callback')).toBe(true);
    expect(pattern.urlPattern.test('https://test.duckdns.org/')).toBe(true);
    expect(pattern.urlPattern.test('https://api.github.com/')).toBe(false);
  });

  it('SN-006: detects raw IP connections', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-006')!;
    expect(pattern.urlPattern.test('https://192.168.1.1/exfil')).toBe(true);
    expect(pattern.urlPattern.test('https://10.0.0.1:8080/')).toBe(true);
    expect(pattern.urlPattern.test('https://api.example.com/')).toBe(false);
  });

  it('SN-007: detects non-standard port connections', () => {
    const pattern = SUSPICIOUS_ENDPOINT_PATTERNS.find((p) => p.id === 'SN-007')!;
    expect(pattern.urlPattern.test('https://evil.com:9999/')).toBe(true);
    expect(pattern.urlPattern.test('https://evil.com:4444/')).toBe(true);
    // Standard ports should not match
    expect(pattern.urlPattern.test('https://api.com:443/')).toBe(false);
    expect(pattern.urlPattern.test('https://api.com:8080/')).toBe(false);
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
