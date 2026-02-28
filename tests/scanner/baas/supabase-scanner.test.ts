import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scanSupabase } from '../../../src/scanner/baas/supabase-scanner.js';
import { analyzeBundles } from '../../../src/scanner/baas/bundle-analyzer.js';

// Mock bundle-analyzer to isolate scanner logic from real bundle fetching
vi.mock('../../../src/scanner/baas/bundle-analyzer.js', () => ({
  analyzeBundles: vi.fn(),
}));

const mockAnalyzeBundles = vi.mocked(analyzeBundles);

// ── Mock Response helper ────────────────────────────────────

function mockResponse(
  body: string,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(headers),
    text: () => Promise.resolve(body),
    json: () => Promise.resolve(JSON.parse(body)),
  } as unknown as Response;
}

function cleanBundleResult(url = 'https://test.supabase.co') {
  return {
    url,
    bundlesAnalyzed: 0,
    findings: [] as import('../../../src/types/index.js').Finding[],
    errors: [] as string[],
  };
}

// ── scanSupabase ────────────────────────────────────────────

describe('scanSupabase', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    mockAnalyzeBundles.mockResolvedValue(cleanBundleResult());
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // ── Step 1: Reachability ────────────────────────────────

  it('returns early when project is unreachable (network error)', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co' });
    expect(result.reachable).toBe(false);
    expect(result.errors).toContain(
      'Supabase project not reachable at https://test.supabase.co',
    );
    expect(result.findings).toEqual([]);
  });

  it('returns early for unexpected status (e.g. 500)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('Error', 500));

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co' });
    expect(result.reachable).toBe(false);
    expect(result.errors.some((e) => e.includes('unexpected status'))).toBe(true);
  });

  it('treats 401 as reachable (expected without apikey)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('', 401));

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co' });
    expect(result.reachable).toBe(true);
  });

  it('treats 403 as reachable', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('', 403));

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co' });
    expect(result.reachable).toBe(true);
  });

  // ── Step 2: Bundle analysis passthrough ─────────────────

  it('includes bundle findings in results', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'critical',
          title: 'Secret found',
          description: 'A secret was found',
          recommendation: 'Remove it',
        },
      ],
    });
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('', 401));

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co' });
    expect(result.findings.some((f) => f.id === 'BU-001')).toBe(true);
  });

  it('prefixes bundle errors with [bundle]', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      errors: ['Some bundle error'],
    });
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('', 401));

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co' });
    expect(result.errors.some((e) => e.includes('[bundle] Some bundle error'))).toBe(true);
  });

  it('detects service_role key exposure (SB-005)', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'critical',
          title: 'Exposed Secret',
          description: 'Found service_role key',
          evidence: 'service_role key detected via SP-023',
          recommendation: 'Remove',
        },
      ],
    });
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('', 401));

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co' });
    const sb005 = result.findings.find((f) => f.id === 'SB-005');
    expect(sb005).toBeDefined();
    expect(sb005!.severity).toBe('critical');
    expect(sb005!.category).toBe('exposed-secret');
    expect(sb005!.title).toContain('service_role');
  });

  // ── Step 3: Anon key resolution ─────────────────────────

  it('reports error when no anon key available', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('', 401));

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co' });
    expect(result.errors.some((e) => e.includes('No anon key'))).toBe(true);
  });

  it('uses anon key from options (skips "No anon key" error)', async () => {
    const anonKey = 'eyJtest.eyJtest.sig';
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 401));
      if (url.endsWith('/rest/v1/') && method === 'GET') {
        return Promise.resolve(mockResponse(JSON.stringify({ paths: {} })));
      }
      if (url.includes('/auth/v1/settings')) {
        return Promise.resolve(mockResponse(JSON.stringify({})));
      }
      if (method === 'OPTIONS') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('{}', 200));
    });

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co', anonKey });
    expect(result.errors.some((e) => e.includes('No anon key'))).toBe(false);
  });

  // ── Steps 4+5: Table enumeration and RLS testing ────────

  it('discovers tables and detects RLS read exposure (SB-001)', async () => {
    const anonKey = 'eyJtest.eyJtest.sig';
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'HEAD') return Promise.resolve(mockResponse('', 401));

      // Table enumeration — OpenAPI spec with two tables
      if (url.endsWith('/rest/v1/') && method === 'GET') {
        return Promise.resolve(
          mockResponse(JSON.stringify({ paths: { '/users': {}, '/posts': {} } })),
        );
      }

      // RLS read: users returns data (RLS off), posts returns empty (safe)
      if (url.includes('/rest/v1/users') && url.includes('select=')) {
        return Promise.resolve(mockResponse('[{"id":1,"email":"test@test.com"}]'));
      }
      if (url.includes('/rest/v1/posts') && url.includes('select=')) {
        return Promise.resolve(mockResponse('[]'));
      }

      // Write probes — RLS blocks
      if (method === 'POST') return Promise.resolve(mockResponse('', 403));

      // Auth & CORS
      if (url.includes('/auth/v1/settings')) {
        return Promise.resolve(mockResponse(JSON.stringify({})));
      }
      if (method === 'OPTIONS') return Promise.resolve(mockResponse('', 200));

      return Promise.resolve(mockResponse('{}', 200));
    });

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co', anonKey });

    expect(result.tablesFound).toContain('users');
    expect(result.tablesFound).toContain('posts');
    expect(result.anonReadExposed).toBe(true);

    const sb001 = result.findings.find((f) => f.id === 'SB-001');
    expect(sb001).toBeDefined();
    expect(sb001!.severity).toBe('critical');
    expect(sb001!.title).toContain('users');
    expect(sb001!.category).toBe('rls-misconfiguration');
  });

  it('detects RLS write exposure via 400 (SB-006)', async () => {
    const anonKey = 'eyJtest.eyJtest.sig';
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'HEAD') return Promise.resolve(mockResponse('', 401));
      if (url.endsWith('/rest/v1/') && method === 'GET') {
        return Promise.resolve(
          mockResponse(JSON.stringify({ paths: { '/orders': {} } })),
        );
      }
      if (url.includes('select=')) return Promise.resolve(mockResponse('[]'));

      // 400 = RLS didn't block, schema constraints caught it
      if (method === 'POST' && url.includes('/rest/v1/orders')) {
        return Promise.resolve(mockResponse('{"message":"schema error"}', 400));
      }

      if (url.includes('/auth/v1/settings')) {
        return Promise.resolve(mockResponse(JSON.stringify({})));
      }
      if (method === 'OPTIONS') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('{}', 200));
    });

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co', anonKey });
    const sb006 = result.findings.find((f) => f.id === 'SB-006');
    expect(sb006).toBeDefined();
    expect(sb006!.severity).toBe('critical');
    expect(sb006!.title).toContain('orders');
    expect(sb006!.evidence).toContain('400');
  });

  // ── Step 6: Auth settings ───────────────────────────────

  it('detects autoconfirm enabled (SB-003)', async () => {
    const anonKey = 'eyJtest.eyJtest.sig';
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 401));
      if (url.endsWith('/rest/v1/') && method === 'GET') {
        return Promise.resolve(mockResponse(JSON.stringify({ paths: {} })));
      }
      if (url.includes('/auth/v1/settings')) {
        return Promise.resolve(
          mockResponse(JSON.stringify({ mailer_autoconfirm: true })),
        );
      }
      if (method === 'OPTIONS') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('{}', 200));
    });

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co', anonKey });
    const sb003 = result.findings.find((f) => f.id === 'SB-003');
    expect(sb003).toBeDefined();
    expect(sb003!.severity).toBe('medium');
    expect(sb003!.category).toBe('auth-misconfiguration');
    expect(sb003!.title).toContain('autoconfirm');
  });

  it('detects open signup (SB-007)', async () => {
    const anonKey = 'eyJtest.eyJtest.sig';
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 401));
      if (url.endsWith('/rest/v1/') && method === 'GET') {
        return Promise.resolve(mockResponse(JSON.stringify({ paths: {} })));
      }
      if (url.includes('/auth/v1/settings')) {
        return Promise.resolve(
          mockResponse(JSON.stringify({ disable_signup: false })),
        );
      }
      if (method === 'OPTIONS') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('{}', 200));
    });

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co', anonKey });
    const sb007 = result.findings.find((f) => f.id === 'SB-007');
    expect(sb007).toBeDefined();
    expect(sb007!.severity).toBe('low');
    expect(sb007!.category).toBe('auth-misconfiguration');
  });

  // ── Step 7: CORS ────────────────────────────────────────

  it('detects CORS wildcard policy (SB-004)', async () => {
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 401));
      if (method === 'OPTIONS') {
        return Promise.resolve(
          mockResponse('', 200, { 'access-control-allow-origin': '*' }),
        );
      }
      return Promise.resolve(mockResponse('{}', 200));
    });

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co' });
    const sb004 = result.findings.find((f) => f.id === 'SB-004');
    expect(sb004).toBeDefined();
    expect(sb004!.severity).toBe('medium');
    expect(sb004!.title).toContain('wildcard');
    expect(sb004!.category).toBe('cors-misconfiguration');
  });

  it('detects CORS origin reflection (SB-004)', async () => {
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 401));
      if (method === 'OPTIONS') {
        return Promise.resolve(
          mockResponse('', 200, {
            'access-control-allow-origin': 'https://evil-attacker-site.com',
          }),
        );
      }
      return Promise.resolve(mockResponse('{}', 200));
    });

    const result = await scanSupabase({ projectUrl: 'https://test.supabase.co' });
    const sb004 = result.findings.find((f) => f.id === 'SB-004');
    expect(sb004).toBeDefined();
    expect(sb004!.title).toContain('reflects');
  });

  // ── URL normalisation ───────────────────────────────────

  it('normalises URL (adds https, strips trailing slashes)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('', 401));

    const result = await scanSupabase({ projectUrl: 'test.supabase.co/' });
    expect(result.projectUrl).toBe('https://test.supabase.co');
  });

  // ── Clean project (all secure) ──────────────────────────

  it('reports no findings for a fully secure project', async () => {
    const anonKey = 'eyJtest.eyJtest.sig';
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'HEAD') return Promise.resolve(mockResponse('', 401));

      // Table enum — one table
      if (url.endsWith('/rest/v1/') && method === 'GET') {
        return Promise.resolve(
          mockResponse(JSON.stringify({ paths: { '/users': {} } })),
        );
      }

      // RLS blocks reads (empty array is not flagged)
      if (url.includes('select=')) return Promise.resolve(mockResponse('[]'));

      // RLS blocks writes
      if (method === 'POST') return Promise.resolve(mockResponse('', 403));

      // Auth is secure
      if (url.includes('/auth/v1/settings')) {
        return Promise.resolve(
          mockResponse(
            JSON.stringify({ mailer_autoconfirm: false, disable_signup: true }),
          ),
        );
      }

      // CORS is restrictive
      if (method === 'OPTIONS') {
        return Promise.resolve(
          mockResponse('', 200, {
            'access-control-allow-origin': 'https://myapp.com',
          }),
        );
      }

      return Promise.resolve(mockResponse('{}', 200));
    });

    const result = await scanSupabase({
      projectUrl: 'https://test.supabase.co',
      anonKey,
    });
    expect(result.reachable).toBe(true);
    expect(result.findings).toEqual([]);
    expect(result.tablesFound).toContain('users');
  });
});
