import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scanFirebase } from '../../../src/scanner/baas/firebase-scanner.js';
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

function cleanBundleResult(url = 'https://test-project.web.app') {
  return {
    url,
    bundlesAnalyzed: 0,
    findings: [] as import('../../../src/types/index.js').Finding[],
    errors: [] as string[],
  };
}

// ── scanFirebase ────────────────────────────────────────────

describe('scanFirebase', () => {
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

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.reachable).toBe(false);
    expect(result.errors).toContain(
      'Firebase project not reachable at https://test-project.web.app',
    );
    expect(result.findings).toEqual([]);
  });

  it('returns early for unexpected status (e.g. 500)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('Error', 500));

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.reachable).toBe(false);
    expect(result.errors.some((e) => e.includes('unexpected status'))).toBe(true);
  });

  it('treats 200 as reachable', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      // Default for all other probes
      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.reachable).toBe(true);
  });

  it('treats 4xx (except 500+) as reachable', async () => {
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 404));
      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.reachable).toBe(true);
  });

  // ── Project ID extraction ─────────────────────────────

  it('extracts project ID from .web.app URL', async () => {
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://my-cool-app.web.app' });
    expect(result.projectId).toBe('my-cool-app');
  });

  it('extracts project ID from .firebaseapp.com URL', async () => {
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://my-cool-app.firebaseapp.com' });
    expect(result.projectId).toBe('my-cool-app');
  });

  it('uses provided projectId over URL extraction', async () => {
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({
      projectUrl: 'https://my-cool-app.web.app',
      projectId: 'override-project',
    });
    expect(result.projectId).toBe('override-project');
  });

  it('reports error when no project ID is available', async () => {
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://example.com' });
    expect(result.projectId).toBeNull();
    expect(result.errors.some((e) => e.includes('Could not determine Firebase project ID'))).toBe(true);
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
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.findings.some((f) => f.id === 'BU-001')).toBe(true);
  });

  it('prefixes bundle errors with [bundle]', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      errors: ['Some bundle error'],
    });
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.errors.some((e) => e.includes('[bundle] Some bundle error'))).toBe(true);
  });

  // ── Firebase config exposure (FB-003) ─────────────────

  it('detects Firebase config exposure via AIzaSy key (FB-003)', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'high',
          title: 'Firebase API Key',
          description: 'Found Firebase key',
          evidence: 'apiKey: "AIzaSy' + 'A'.repeat(33) + '"',
          recommendation: 'Remove',
        },
      ],
    });
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    const fb003 = result.findings.find((f) => f.id === 'FB-003');
    expect(fb003).toBeDefined();
    expect(fb003!.severity).toBe('high');
    expect(fb003!.category).toBe('exposed-secret');
    expect(fb003!.title).toContain('Firebase config');
    expect(result.configExposed).toBe(true);
  });

  // ── Step 3: Firestore probes (FB-001) ─────────────────

  it('detects Firestore public read access (FB-001)', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));

      // Firestore documents GET — public read
      if (url.includes('firestore.googleapis.com') && method === 'GET') {
        return Promise.resolve(
          mockResponse(JSON.stringify({ documents: [{ name: 'doc1' }] })),
        );
      }

      // Block writes and all other probes
      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.firestorePublicAccess).toBe(true);

    const fb001 = result.findings.find(
      (f) => f.id === 'FB-001' && f.title.includes('read'),
    );
    expect(fb001).toBeDefined();
    expect(fb001!.severity).toBe('critical');
    expect(fb001!.category).toBe('firebase-rules-issue');
    expect(fb001!.evidence).toContain('returned 200');
    expect(fb001!.evidence).toContain('1 documents');
  });

  it('detects Firestore public write access (FB-001)', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));

      // Firestore documents GET — blocked (good)
      if (url.includes('firestore.googleapis.com') && method === 'GET') {
        return Promise.resolve(mockResponse('', 403));
      }

      // Firestore POST (write probe) — succeeds (bad)
      if (url.includes('firestore.googleapis.com') && method === 'POST') {
        return Promise.resolve(mockResponse('{"name":"doc"}', 200));
      }

      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.firestorePublicAccess).toBe(true);

    const fb001Write = result.findings.find(
      (f) => f.id === 'FB-001' && f.title.includes('WRITE'),
    );
    expect(fb001Write).toBeDefined();
    expect(fb001Write!.severity).toBe('critical');
  });

  // ── Step 4: RTDB probes (FB-002) ──────────────────────

  it('detects RTDB public read access via default-rtdb URL (FB-002)', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));

      // RTDB default-rtdb URL returns data (public read)
      if (url.includes('-default-rtdb.firebaseio.com') && method === 'GET') {
        return Promise.resolve(
          mockResponse(JSON.stringify({ users: true, posts: true, config: true })),
        );
      }

      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.rtdbPublicAccess).toBe(true);

    const fb002 = result.findings.find(
      (f) => f.id === 'FB-002' && f.title.includes('read'),
    );
    expect(fb002).toBeDefined();
    expect(fb002!.severity).toBe('critical');
    expect(fb002!.evidence).toContain('3 top-level keys');
  });

  it('falls back to legacy RTDB URL when default-rtdb fails', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));

      // default-rtdb URL fails (404 = not provisioned)
      if (url.includes('-default-rtdb.firebaseio.com')) {
        return Promise.resolve(mockResponse('', 404));
      }

      // Legacy URL succeeds (public read)
      if (url.includes('test-project.firebaseio.com') && method === 'GET') {
        return Promise.resolve(
          mockResponse(JSON.stringify({ data: true })),
        );
      }

      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.rtdbPublicAccess).toBe(true);

    const fb002 = result.findings.find((f) => f.id === 'FB-002');
    expect(fb002).toBeDefined();
  });

  it('detects RTDB public write access (FB-002)', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));

      // RTDB read blocked
      if (url.includes('firebaseio.com') && method === 'GET') {
        return Promise.resolve(mockResponse('', 401));
      }

      // RTDB write succeeds (bad)
      if (url.includes('firebaseio.com') && method === 'PUT') {
        return Promise.resolve(
          mockResponse(JSON.stringify({ _vigile_probe: 'security_test' })),
        );
      }

      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    expect(result.rtdbPublicAccess).toBe(true);

    const fb002Write = result.findings.find(
      (f) => f.id === 'FB-002' && f.title.includes('WRITE'),
    );
    expect(fb002Write).toBeDefined();
    expect(fb002Write!.severity).toBe('critical');
  });

  // ── Step 5: Storage bucket probe (FB-004) ─────────────

  it('detects publicly listable Storage bucket (FB-004)', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));

      // Storage listing returns items
      if (url.includes('firebasestorage.googleapis.com')) {
        return Promise.resolve(
          mockResponse(JSON.stringify({
            items: [
              { name: 'uploads/photo.jpg' },
              { name: 'uploads/doc.pdf' },
            ],
          })),
        );
      }

      return Promise.resolve(mockResponse('', 403));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    const fb004 = result.findings.find((f) => f.id === 'FB-004');
    expect(fb004).toBeDefined();
    expect(fb004!.severity).toBe('high');
    expect(fb004!.category).toBe('firebase-rules-issue');
    expect(fb004!.evidence).toContain('2 files');
  });

  it('uses storageBucket from bundle config if available', async () => {
    // Bundle findings contain appspot.com reference
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'high',
          title: 'Firebase config',
          description: 'Found config',
          evidence: 'storageBucket: "custom-bucket.appspot.com"',
          recommendation: 'Remove',
        },
      ],
    });

    const fetchedUrls: string[] = [];
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      fetchedUrls.push(url);
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      return Promise.resolve(mockResponse('', 403));
    });

    await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    // Should use custom-bucket.appspot.com, not test-project.appspot.com
    expect(fetchedUrls.some((u) => u.includes('custom-bucket.appspot.com'))).toBe(true);
  });

  // ── Step 6: Security headers (FB-005) ─────────────────

  it('detects missing security headers when >= 2 missing (FB-005)', async () => {
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      // GET response with NO security headers
      return Promise.resolve(mockResponse('{}', 200));
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    const fb005 = result.findings.find((f) => f.id === 'FB-005');
    expect(fb005).toBeDefined();
    expect(fb005!.severity).toBe('medium');
    expect(fb005!.category).toBe('cors-misconfiguration');
    expect(fb005!.evidence).toContain('Missing:');
  });

  it('does NOT flag headers when only 1 is missing (below threshold)', async () => {
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));
      // Response has 2 of 3 security headers
      return Promise.resolve(
        mockResponse('{}', 200, {
          'x-content-type-options': 'nosniff',
          'strict-transport-security': 'max-age=31536000',
          // Missing x-frame-options and CSP — but only 1 "slot" missing
        }),
      );
    });

    const result = await scanFirebase({ projectUrl: 'https://test-project.web.app' });
    const fb005 = result.findings.find((f) => f.id === 'FB-005');
    expect(fb005).toBeUndefined();
  });

  // ── URL normalisation ─────────────────────────────────

  it('normalises URL (adds https, strips trailing slashes)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('', 200));

    const result = await scanFirebase({ projectUrl: 'test-project.web.app/' });
    expect(result.projectUrl).toBe('https://test-project.web.app');
  });

  // ── Clean project (all secure) ────────────────────────

  it('reports no findings for a fully secure project', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'HEAD') return Promise.resolve(mockResponse('', 200));

      // Firestore — blocked
      if (url.includes('firestore.googleapis.com')) {
        return Promise.resolve(mockResponse('', 403));
      }

      // RTDB — blocked
      if (url.includes('firebaseio.com')) {
        return Promise.resolve(mockResponse('', 401));
      }

      // Storage — blocked
      if (url.includes('firebasestorage.googleapis.com')) {
        return Promise.resolve(mockResponse('', 403));
      }

      // GET (hosting headers check) — has all security headers
      return Promise.resolve(
        mockResponse('{}', 200, {
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'strict-transport-security': 'max-age=31536000',
        }),
      );
    });

    const result = await scanFirebase({
      projectUrl: 'https://test-project.web.app',
    });
    expect(result.reachable).toBe(true);
    expect(result.findings).toEqual([]);
    expect(result.firestorePublicAccess).toBe(false);
    expect(result.rtdbPublicAccess).toBe(false);
    expect(result.configExposed).toBe(false);
  });
});
