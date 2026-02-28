import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { analyzeBundles } from '../../../src/scanner/baas/bundle-analyzer.js';

// ── Mock Response helper ────────────────────────────────────

function mockResponse(
  body: string,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  const encoder = new TextEncoder();
  const buffer = encoder.encode(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(headers),
    text: () => Promise.resolve(body),
    json: () => Promise.resolve(JSON.parse(body)),
    arrayBuffer: () => Promise.resolve(buffer.buffer.slice(0)),
  } as unknown as Response;
}

// ── analyzeBundles ──────────────────────────────────────────

describe('analyzeBundles', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('returns error when root HTML fetch fails', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('Not Found', 404));

    const result = await analyzeBundles('https://example.com');
    expect(result.bundlesAnalyzed).toBe(0);
    expect(result.findings).toEqual([]);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns error when HTML has no script tags', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      mockResponse('<html><body>No scripts here</body></html>'),
    );

    const result = await analyzeBundles('https://example.com');
    expect(result.bundlesAnalyzed).toBe(0);
    expect(result.findings).toEqual([]);
    expect(result.errors).toContain(
      'No <script src> tags found in HTML at https://example.com/',
    );
  });

  it('fetches and analyzes clean JS bundles', async () => {
    const html = '<html><script src="/app.js"></script><script src="/vendor.js"></script></html>';

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if ((url as string).endsWith('/'))
        return Promise.resolve(mockResponse(html));
      return Promise.resolve(mockResponse('const x = 42;'));
    });

    const result = await analyzeBundles('https://example.com');
    expect(result.bundlesAnalyzed).toBe(2);
    expect(result.findings).toEqual([]);
    expect(result.errors).toEqual([]);
  });

  it('detects secrets in JS bundles', async () => {
    const fakeKey = 'sk-' + 'a'.repeat(48);
    const html = '<html><script src="/app.js"></script></html>';
    const bundle = `const apiKey = "${fakeKey}";`;

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if ((url as string).endsWith('/'))
        return Promise.resolve(mockResponse(html));
      return Promise.resolve(mockResponse(bundle));
    });

    const result = await analyzeBundles('https://example.com');
    expect(result.bundlesAnalyzed).toBe(1);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].category).toBe('exposed-secret');
    expect(result.findings[0].id).toBe('BU-001');
    expect(result.findings[0].title).toContain('Exposed');
  });

  it('assigns sequential BU-NNN IDs to multiple findings', async () => {
    const fakeOpenAI = 'sk-' + 'a'.repeat(48);
    const fakeGitHub = 'ghp_' + 'A'.repeat(36);
    const html = '<html><script src="/app.js"></script></html>';
    const bundle = `const a = "${fakeOpenAI}"; const b = "${fakeGitHub}";`;

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if ((url as string).endsWith('/'))
        return Promise.resolve(mockResponse(html));
      return Promise.resolve(mockResponse(bundle));
    });

    const result = await analyzeBundles('https://example.com');
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
    expect(result.findings[0].id).toBe('BU-001');
    expect(result.findings[1].id).toBe('BU-002');
  });

  it('handles bundle fetch errors gracefully', async () => {
    const html = '<html><script src="/app.js"></script></html>';

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if ((url as string).endsWith('/'))
        return Promise.resolve(mockResponse(html));
      return Promise.resolve(mockResponse('Not Found', 404));
    });

    const result = await analyzeBundles('https://example.com');
    expect(result.bundlesAnalyzed).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('HTTP 404');
  });

  it('handles network errors during fetch', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Connection refused'));

    const result = await analyzeBundles('https://example.com');
    expect(result.bundlesAnalyzed).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('Connection refused');
  });

  it('skips data: URIs in script tags', async () => {
    const html = '<html><script src="data:text/javascript,alert(1)"></script></html>';

    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse(html));

    const result = await analyzeBundles('https://example.com');
    expect(result.bundlesAnalyzed).toBe(0);
    expect(result.errors).toContain(
      'No <script src> tags found in HTML at https://example.com/',
    );
  });

  it('limits bundles to MAX_BUNDLES (10)', async () => {
    const scriptTags = Array.from(
      { length: 15 },
      (_, i) => `<script src="/bundle${i}.js"></script>`,
    ).join('');
    const html = `<html>${scriptTags}</html>`;

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if ((url as string).endsWith('/'))
        return Promise.resolve(mockResponse(html));
      return Promise.resolve(mockResponse('const x = 1;'));
    });

    const result = await analyzeBundles('https://example.com');
    // Should analyze at most 10 bundles
    expect(result.bundlesAnalyzed).toBeLessThanOrEqual(10);
  });

  it('normalises URL with trailing slash', async () => {
    const html = '<html><script src="/app.js"></script></html>';

    globalThis.fetch = vi.fn().mockImplementation(() =>
      Promise.resolve(mockResponse(html)),
    );

    await analyzeBundles('https://example.com');
    const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
    // First call should be the normalised URL with trailing slash
    expect(calls[0][0]).toBe('https://example.com/');
  });

  it('resolves relative script URLs against base URL', async () => {
    const html = '<html><script src="./static/app.js"></script></html>';
    const fetchedUrls: string[] = [];

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      fetchedUrls.push(url as string);
      return Promise.resolve(
        mockResponse(
          (url as string).endsWith('/') ? html : 'const x = 1;',
        ),
      );
    });

    await analyzeBundles('https://example.com');
    expect(fetchedUrls).toContain('https://example.com/static/app.js');
  });

  it('skips oversized bundles based on content-length', async () => {
    const html = '<html><script src="/huge.js"></script></html>';

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if ((url as string).endsWith('/'))
        return Promise.resolve(mockResponse(html));
      return Promise.resolve(
        mockResponse('x', 200, { 'content-length': '10000000' }),
      );
    });

    const result = await analyzeBundles('https://example.com');
    expect(result.bundlesAnalyzed).toBe(0);
    expect(result.errors.some((e) => e.includes('too large'))).toBe(true);
  });

  it('returns correct url in result', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      mockResponse('<html></html>'),
    );

    const result = await analyzeBundles('https://myapp.vercel.app');
    expect(result.url).toBe('https://myapp.vercel.app');
  });
});
