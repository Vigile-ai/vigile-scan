import { describe, it, expect } from 'vitest';
import { SECRET_PATTERNS, matchSecrets } from '../../../src/scanner/baas/secret-patterns.js';
import type { SecretPattern, SecretMatch } from '../../../src/scanner/baas/secret-patterns.js';

// ── Pattern registry tests ──────────────────────────────────

describe('SECRET_PATTERNS', () => {
  it('should contain exactly 150 patterns', () => {
    expect(SECRET_PATTERNS).toHaveLength(150);
  });

  it('should have unique IDs from SP-001 to SP-150', () => {
    const ids = SECRET_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(150);

    // First and last
    expect(ids[0]).toBe('SP-001');
    expect(ids[ids.length - 1]).toBe('SP-150');
  });

  it('every pattern should have all required fields', () => {
    for (const p of SECRET_PATTERNS) {
      expect(p.id).toBeTruthy();
      expect(p.name).toBeTruthy();
      expect(p.provider).toBeTruthy();
      expect(p.severity).toBeTruthy();
      expect(p.pattern).toBeInstanceOf(RegExp);
      expect(p.description).toBeTruthy();
      expect(p.recommendation).toBeTruthy();
    }
  });

  it('severity should only be critical, high, medium, or low', () => {
    const validSeverities = ['critical', 'high', 'medium', 'low'];
    for (const p of SECRET_PATTERNS) {
      expect(validSeverities).toContain(p.severity);
    }
  });

  it('IDs should follow SP-NNN format', () => {
    for (const p of SECRET_PATTERNS) {
      expect(p.id).toMatch(/^SP-\d{3}$/);
    }
  });
});

// ── Individual pattern positive/negative tests ──────────────

describe('Individual Secret Patterns', () => {
  // Helper to find a pattern by ID
  function findPattern(id: string): SecretPattern {
    const p = SECRET_PATTERNS.find((sp) => sp.id === id);
    if (!p) throw new Error(`Pattern ${id} not found`);
    return p;
  }

  // ── AI / LLM Providers ──

  describe('SP-001: OpenAI API Key', () => {
    it('matches valid OpenAI keys', () => {
      const p = findPattern('SP-001');
      expect(p.pattern.test('sk-' + 'a'.repeat(48))).toBe(true);
      expect(p.pattern.test('sk-' + 'A1b2C3d4'.repeat(6))).toBe(true);
    });

    it('rejects short keys', () => {
      const p = findPattern('SP-001');
      expect(p.pattern.test('sk-' + 'a'.repeat(10))).toBe(false);
    });

    it('has critical severity', () => {
      expect(findPattern('SP-001').severity).toBe('critical');
    });
  });

  describe('SP-004: Anthropic API Key', () => {
    it('matches valid Anthropic keys', () => {
      const p = findPattern('SP-004');
      const key = 'sk-ant-api03-' + 'a'.repeat(93);
      expect(p.pattern.test(key)).toBe(true);
    });

    it('rejects wrong prefix', () => {
      const p = findPattern('SP-004');
      expect(p.pattern.test('sk-ant-wrong-' + 'a'.repeat(93))).toBe(false);
    });

    it('has critical severity', () => {
      expect(findPattern('SP-004').severity).toBe('critical');
    });
  });

  // ── BaaS Providers ──

  describe('SP-034: Firebase Web API Key', () => {
    it('matches Firebase API key in env var pattern', () => {
      const p = findPattern('SP-034');
      // NEXT_PUBLIC_FIREBASE_API_KEY="AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ12345678"
      const text = 'NEXT_PUBLIC_FIREBASE_API_KEY="AIzaSy' + 'A'.repeat(33) + '"';
      expect(p.pattern.test(text)).toBe(true);
    });

    it('matches firebaseConfig.apiKey pattern', () => {
      const p = findPattern('SP-034');
      const text = 'firebaseConfig.apiKey = "AIzaSy' + 'B'.repeat(33) + '"';
      expect(p.pattern.test(text)).toBe(true);
    });

    it('rejects non-Firebase API keys', () => {
      const p = findPattern('SP-034');
      expect(p.pattern.test('SOME_KEY="notafirebasekey"')).toBe(false);
    });
  });

  describe('SP-036: Supabase Service Role Key', () => {
    it('matches service role key pattern', () => {
      const p = findPattern('SP-036');
      // Supabase JWTs start with eyJ... (base64 header)
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE2MDAwMDAwMDB9.abc123def456';
      const text = `SUPABASE_SERVICE_ROLE_KEY="${jwt}"`;
      expect(p.pattern.test(text)).toBe(true);
    });

    it('has critical severity', () => {
      expect(findPattern('SP-036').severity).toBe('critical');
    });
  });

  describe('SP-037: Supabase Anon Key', () => {
    it('matches anon key pattern', () => {
      const p = findPattern('SP-037');
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNjAwMDAwMDAwfQ.sig123';
      const text = `NEXT_PUBLIC_SUPABASE_ANON_KEY="${jwt}"`;
      expect(p.pattern.test(text)).toBe(true);
    });

    it('has low severity (designed to be public)', () => {
      expect(findPattern('SP-037').severity).toBe('low');
    });
  });

  // ── Git/VCS Providers ──

  describe('SP-075: GitHub Personal Access Token (Classic)', () => {
    it('matches valid GitHub PATs', () => {
      const p = findPattern('SP-075');
      expect(p.pattern.test('ghp_' + 'A'.repeat(36))).toBe(true);
    });

    it('rejects short tokens', () => {
      const p = findPattern('SP-075');
      expect(p.pattern.test('ghp_' + 'A'.repeat(10))).toBe(false);
    });

    it('has critical severity', () => {
      expect(findPattern('SP-075').severity).toBe('critical');
    });
  });

  // ── Database Connection Strings ──

  describe('SP-082: PostgreSQL Connection String', () => {
    it('matches postgres:// URLs with credentials', () => {
      const p = findPattern('SP-082');
      expect(p.pattern.test('postgres://user:pass@host:5432/dbname')).toBe(true);
      expect(p.pattern.test('postgresql://admin:secret@db.example.com/mydb')).toBe(true);
    });

    it('rejects URLs without credentials', () => {
      const p = findPattern('SP-082');
      // Pattern requires user:pass@ format
      expect(p.pattern.test('postgres://host/dbname')).toBe(false);
    });

    it('has critical severity', () => {
      expect(findPattern('SP-082').severity).toBe('critical');
    });
  });

  // ── Crypto / Private Keys ──

  describe('SP-101: RSA Private Key Header', () => {
    it('matches RSA private key blocks', () => {
      const p = findPattern('SP-101');
      expect(p.pattern.test('-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
    });

    it('does not match public key blocks', () => {
      const p = findPattern('SP-101');
      expect(p.pattern.test('-----BEGIN PUBLIC KEY-----')).toBe(false);
    });
  });

  // ── Framework-Specific Leaks ──

  describe('SP-134: Next.js NEXT_PUBLIC Secret Leak', () => {
    it('matches NEXT_PUBLIC_ prefixed secrets', () => {
      const p = findPattern('SP-134');
      expect(p.pattern.test('NEXT_PUBLIC_SECRET_KEY="myvalue12345678901234567890"')).toBe(true);
    });
  });

  // ── Generic Patterns ──

  describe('SP-150: Generic Bearer Token', () => {
    it('matches Authorization: Bearer headers', () => {
      const p = findPattern('SP-150');
      const token = 'A'.repeat(50);
      expect(p.pattern.test(`Authorization: Bearer ${token}`)).toBe(true);
    });

    it('rejects short tokens', () => {
      const p = findPattern('SP-150');
      expect(p.pattern.test('Authorization: Bearer short')).toBe(false);
    });
  });
});

// ── matchSecrets() function tests ───────────────────────────

describe('matchSecrets', () => {
  it('returns empty array for clean text', () => {
    const result = matchSecrets('const foo = "hello world";');
    expect(result).toEqual([]);
  });

  it('detects an OpenAI key in bundled JS', () => {
    const fakeKey = 'sk-' + 'a'.repeat(48);
    const bundle = `const apiKey = "${fakeKey}";`;
    const result = matchSecrets(bundle);

    expect(result.length).toBeGreaterThanOrEqual(1);
    const openaiMatch = result.find((r) => r.pattern.id === 'SP-001');
    expect(openaiMatch).toBeDefined();
    expect(openaiMatch!.pattern.provider).toBe('openai');
    expect(openaiMatch!.pattern.severity).toBe('critical');
  });

  it('masks matched secrets (first4***last4)', () => {
    const fakeKey = 'sk-' + 'abcdefghijklmnopqrstuvwxyz'.repeat(2);
    const bundle = `key="${fakeKey}"`;
    const result = matchSecrets(bundle);

    expect(result.length).toBeGreaterThanOrEqual(1);
    // Mask format: first 4 chars + *** + last 4 chars
    const match = result[0];
    expect(match.match).toContain('***');
    expect(match.match.startsWith('sk-a')).toBe(true);
  });

  it('provides context around matched secrets', () => {
    const fakeKey = 'ghp_' + 'A'.repeat(36);
    const bundle = `const githubToken = "${fakeKey}"; // do not leak`;
    const result = matchSecrets(bundle);

    const ghMatch = result.find((r) => r.pattern.id === 'SP-075');
    expect(ghMatch).toBeDefined();
    // Context should include surrounding text (25 chars each side)
    expect(ghMatch!.context.length).toBeGreaterThan(0);
    expect(ghMatch!.context.length).toBeLessThanOrEqual(
      fakeKey.length + 50 + 10, // key + 25 each side + margin
    );
  });

  it('detects multiple secrets in one text block', () => {
    const openaiKey = 'sk-' + 'x'.repeat(48);
    const githubToken = 'ghp_' + 'Y'.repeat(36);
    const bundle = `const a = "${openaiKey}"; const b = "${githubToken}";`;
    const result = matchSecrets(bundle);

    const ids = result.map((r) => r.pattern.id);
    expect(ids).toContain('SP-001'); // OpenAI
    expect(ids).toContain('SP-075'); // GitHub PAT
  });

  it('detects Firebase API key in config-like text', () => {
    const text = 'NEXT_PUBLIC_FIREBASE_API_KEY="AIzaSy' + 'A'.repeat(33) + '"';
    const result = matchSecrets(text);

    const fbMatch = result.find((r) => r.pattern.id === 'SP-034');
    expect(fbMatch).toBeDefined();
    expect(fbMatch!.pattern.provider).toBe('firebase');
  });

  it('detects PostgreSQL connection string', () => {
    const text = 'const db = "postgres://admin:s3cret@db.prod.internal:5432/myapp"';
    const result = matchSecrets(text);

    const pgMatch = result.find((r) => r.pattern.id === 'SP-082');
    expect(pgMatch).toBeDefined();
    expect(pgMatch!.pattern.severity).toBe('critical');
  });

  it('detects SendGrid API key', () => {
    const sgKey = 'SG.' + 'A'.repeat(22) + '.' + 'B'.repeat(43);
    const text = `const key = "${sgKey}";`;
    const result = matchSecrets(text);

    const sgMatch = result.find((r) => r.pattern.id === 'SP-071');
    expect(sgMatch).toBeDefined();
    expect(sgMatch!.pattern.provider).toBe('sendgrid');
  });

  it('returns SecretMatch objects with correct structure', () => {
    const fakeKey = 'ghp_' + 'Z'.repeat(36);
    const result = matchSecrets(`token = "${fakeKey}"`);

    expect(result.length).toBeGreaterThanOrEqual(1);
    const match = result[0];
    expect(match).toHaveProperty('pattern');
    expect(match).toHaveProperty('match');
    expect(match).toHaveProperty('context');
    expect(match.pattern).toHaveProperty('id');
    expect(match.pattern).toHaveProperty('name');
    expect(match.pattern).toHaveProperty('provider');
    expect(match.pattern).toHaveProperty('severity');
  });

  it('handles empty string input', () => {
    expect(matchSecrets('')).toEqual([]);
  });

  it('handles very large input without crashing', () => {
    // 1MB of innocuous text
    const largeText = 'const x = "hello"; '.repeat(50_000);
    const result = matchSecrets(largeText);
    expect(result).toEqual([]);
  });
});
