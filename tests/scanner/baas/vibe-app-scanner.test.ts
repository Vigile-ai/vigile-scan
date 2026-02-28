import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scanVibeApp } from '../../../src/scanner/baas/vibe-app-scanner.js';
import { analyzeBundles } from '../../../src/scanner/baas/bundle-analyzer.js';
import { scanSupabase } from '../../../src/scanner/baas/supabase-scanner.js';
import { scanFirebase } from '../../../src/scanner/baas/firebase-scanner.js';
import { detectCves, parseNpmPackages } from '../../../src/scanner/baas/cve-detector.js';
import type { Finding } from '../../../src/types/index.js';

// ── Mock all sub-modules ────────────────────────────────────

vi.mock('../../../src/scanner/baas/bundle-analyzer.js', () => ({
  analyzeBundles: vi.fn(),
}));

vi.mock('../../../src/scanner/baas/supabase-scanner.js', () => ({
  scanSupabase: vi.fn(),
}));

vi.mock('../../../src/scanner/baas/firebase-scanner.js', () => ({
  scanFirebase: vi.fn(),
}));

vi.mock('../../../src/scanner/baas/cve-detector.js', () => ({
  detectCves: vi.fn(),
  parseNpmPackages: vi.fn(),
}));

const mockAnalyzeBundles = vi.mocked(analyzeBundles);
const mockScanSupabase = vi.mocked(scanSupabase);
const mockScanFirebase = vi.mocked(scanFirebase);
const mockDetectCves = vi.mocked(detectCves);
const mockParseNpmPackages = vi.mocked(parseNpmPackages);

// ── Helpers ─────────────────────────────────────────────────

function cleanBundleResult(url = 'https://myapp.vercel.app') {
  return {
    url,
    bundlesAnalyzed: 0,
    findings: [] as Finding[],
    errors: [] as string[],
  };
}

function cleanSupabaseResult() {
  return {
    projectUrl: 'https://test.supabase.co',
    reachable: true,
    anonKeyAvailable: false,
    anonReadExposed: false,
    tablesFound: [] as string[],
    findings: [] as Finding[],
    errors: [] as string[],
  };
}

function cleanFirebaseResult() {
  return {
    projectUrl: 'https://test-project.web.app',
    projectId: 'test-project',
    firestorePublicAccess: false,
    rtdbPublicAccess: false,
    configExposed: false,
    reachable: true,
    findings: [] as Finding[],
    errors: [] as string[],
  };
}

function cleanCveResult() {
  return {
    packagesChecked: 0,
    matches: [] as { cveId: string; packageName: string; installedVersion: string; patchedVersion: string | null; summary: string; severity: string }[],
    findings: [] as Finding[],
    errors: [] as string[],
  };
}

// ── Mock Response helper for package.json fetch ─────────────

function mockResponse(
  body: string,
  status = 200,
): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(),
    text: () => Promise.resolve(body),
    json: () => Promise.resolve(JSON.parse(body)),
  } as unknown as Response;
}

// ── scanVibeApp ─────────────────────────────────────────────

describe('scanVibeApp', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    // Default: all sub-modules return clean (no findings)
    mockAnalyzeBundles.mockResolvedValue(cleanBundleResult());
    mockScanSupabase.mockResolvedValue(cleanSupabaseResult());
    mockScanFirebase.mockResolvedValue(cleanFirebaseResult());
    mockDetectCves.mockResolvedValue(cleanCveResult());
    mockParseNpmPackages.mockReturnValue([]);
    // Default: no package.json served
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse('Not Found', 404));
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // ── Step 1: Bundle analysis ─────────────────────────────

  it('always runs bundle analysis', async () => {
    await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    expect(mockAnalyzeBundles).toHaveBeenCalledWith('https://myapp.vercel.app');
  });

  it('includes bundle findings and errors', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'critical',
          title: 'Secret found',
          description: 'A secret',
          recommendation: 'Remove',
        },
      ],
      errors: ['Failed to fetch /app.js'],
    });

    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    expect(result.findings.some((f) => f.id === 'BU-001')).toBe(true);
    expect(result.errors).toContain('Failed to fetch /app.js');
  });

  // ── Step 2: Platform detection ──────────────────────────

  it('detects Supabase from finding evidence', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'low',
          title: 'Supabase anon key',
          description: 'Found key',
          evidence: 'supabase anon key detected',
          recommendation: 'Review',
        },
      ],
    });

    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    expect(result.detectedPlatform).toBe('supabase');
    expect(mockScanSupabase).toHaveBeenCalled();
  });

  it('detects Firebase from finding evidence', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'high',
          title: 'Firebase API Key',
          description: 'Found Firebase config',
          evidence: 'AIzaSy' + 'A'.repeat(33),
          recommendation: 'Review',
        },
      ],
    });

    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    expect(result.detectedPlatform).toBe('firebase');
    expect(mockScanFirebase).toHaveBeenCalled();
  });

  it('detects Supabase from URL hostname', async () => {
    const result = await scanVibeApp({ appUrl: 'https://test.supabase.co' });
    expect(result.detectedPlatform).toBe('supabase');
    expect(mockScanSupabase).toHaveBeenCalled();
  });

  it('detects Firebase from .web.app URL', async () => {
    const result = await scanVibeApp({ appUrl: 'https://test-project.web.app' });
    expect(result.detectedPlatform).toBe('firebase');
    expect(mockScanFirebase).toHaveBeenCalled();
  });

  it('detects Firebase from .firebaseapp.com URL', async () => {
    const result = await scanVibeApp({ appUrl: 'https://test-project.firebaseapp.com' });
    expect(result.detectedPlatform).toBe('firebase');
    expect(mockScanFirebase).toHaveBeenCalled();
  });

  it('returns unknown when no platform signals found', async () => {
    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    expect(result.detectedPlatform).toBe('unknown');
    expect(result.errors.some((e) => e.includes('Could not detect BaaS platform'))).toBe(true);
  });

  it('uses platform override from options', async () => {
    const result = await scanVibeApp({
      appUrl: 'https://myapp.vercel.app',
      platform: 'supabase',
    });
    expect(result.detectedPlatform).toBe('supabase');
    expect(mockScanSupabase).toHaveBeenCalled();
  });

  // ── Step 3: Platform-specific scanning ──────────────────

  it('runs Supabase scan when supabaseUrl is provided', async () => {
    const result = await scanVibeApp({
      appUrl: 'https://myapp.vercel.app',
      supabaseUrl: 'https://my-project.supabase.co',
    });
    expect(mockScanSupabase).toHaveBeenCalledWith({
      projectUrl: 'https://my-project.supabase.co',
    });
    // Platform still unknown from URL, but supabase scan ran
    expect(mockScanSupabase).toHaveBeenCalled();
  });

  it('runs Firebase scan when firebaseUrl is provided', async () => {
    await scanVibeApp({
      appUrl: 'https://myapp.vercel.app',
      firebaseUrl: 'https://my-project.web.app',
    });
    expect(mockScanFirebase).toHaveBeenCalledWith({
      projectUrl: 'https://my-project.web.app',
    });
  });

  it('aggregates sub-scanner findings and errors', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'critical',
          title: 'Bundle secret',
          description: 'Found',
          recommendation: 'Remove',
        },
      ],
    });

    mockScanSupabase.mockResolvedValue({
      ...cleanSupabaseResult(),
      findings: [
        {
          id: 'SB-001',
          category: 'rls-misconfiguration',
          severity: 'critical',
          title: 'RLS disabled on users',
          description: 'Exposed',
          recommendation: 'Enable RLS',
        },
      ],
      errors: ['No anon key found'],
    });

    const result = await scanVibeApp({
      appUrl: 'https://test.supabase.co',
    });

    expect(result.findings.some((f) => f.id === 'BU-001')).toBe(true);
    expect(result.findings.some((f) => f.id === 'SB-001')).toBe(true);
    expect(result.errors).toContain('No anon key found');
  });

  it('handles sub-scanner crash gracefully', async () => {
    mockScanSupabase.mockRejectedValue(new Error('Scanner exploded'));

    const result = await scanVibeApp({
      appUrl: 'https://test.supabase.co',
    });

    expect(result.errors.some((e) => e.includes('Supabase scan failed'))).toBe(true);
    expect(result.errors.some((e) => e.includes('Scanner exploded'))).toBe(true);
  });

  it('handles Firebase scanner crash gracefully', async () => {
    mockScanFirebase.mockRejectedValue(new Error('Firebase down'));

    const result = await scanVibeApp({
      appUrl: 'https://test-project.web.app',
    });

    expect(result.errors.some((e) => e.includes('Firebase scan failed'))).toBe(true);
  });

  // ── Step 4: Package.json + CVE detection ────────────────

  it('fetches package.json and runs CVE detection', async () => {
    const packageJson = JSON.stringify({
      dependencies: { react: '^18.2.0', next: '14.1.0' },
    });

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if ((url as string).includes('package.json')) {
        return Promise.resolve(mockResponse(packageJson));
      }
      return Promise.resolve(mockResponse('Not Found', 404));
    });

    mockParseNpmPackages.mockReturnValue([
      { name: 'react', version: '18.2.0', ecosystem: 'npm' },
      { name: 'next', version: '14.1.0', ecosystem: 'npm' },
    ]);

    mockDetectCves.mockResolvedValue({
      packagesChecked: 2,
      matches: [
        {
          cveId: 'CVE-2024-12345',
          packageName: 'next',
          installedVersion: '14.1.0',
          patchedVersion: '14.1.1',
          summary: 'SSRF in Next.js',
          severity: 'high',
        },
      ],
      findings: [
        {
          id: 'CVE-2024-12345',
          category: 'cve-detected',
          severity: 'high',
          title: 'CVE-2024-12345 in next@14.1.0',
          description: 'SSRF in Next.js',
          recommendation: 'Upgrade to 14.1.1',
        },
      ],
      errors: [],
    });

    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    expect(result.packagesChecked).toBe(2);
    expect(result.cveMatches).toBe(1);
    expect(result.findings.some((f) => f.id === 'CVE-2024-12345')).toBe(true);
  });

  it('skips CVE detection when no packages found', async () => {
    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    expect(mockDetectCves).not.toHaveBeenCalled();
    expect(result.packagesChecked).toBe(0);
    expect(result.cveMatches).toBe(0);
  });

  it('reports bundle-detected packages when no package.json available', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'high',
          title: 'Secret found',
          description: 'Found in bundle',
          evidence: 'found in node_modules/react/index.js and node_modules/@supabase/supabase-js/dist',
          recommendation: 'Remove',
        },
      ],
    });

    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    expect(result.errors.some((e) => e.includes('Detected') && e.includes('package'))).toBe(true);
  });

  it('handles CVE detection crash gracefully', async () => {
    const packageJson = JSON.stringify({
      dependencies: { react: '18.2.0' },
    });

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if ((url as string).includes('package.json')) {
        return Promise.resolve(mockResponse(packageJson));
      }
      return Promise.resolve(mockResponse('Not Found', 404));
    });

    mockParseNpmPackages.mockReturnValue([
      { name: 'react', version: '18.2.0', ecosystem: 'npm' },
    ]);

    mockDetectCves.mockRejectedValue(new Error('OSV.dev timeout'));

    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    expect(result.errors.some((e) => e.includes('CVE detection failed'))).toBe(true);
  });

  // ── Step 6: Finding deduplication ─────────────────────

  it('deduplicates findings with same id + evidence', async () => {
    const duplicateFinding: Finding = {
      id: 'BU-001',
      category: 'exposed-secret',
      severity: 'critical',
      title: 'Secret found',
      description: 'A secret',
      evidence: 'sk-aaaa***aaaa via SP-001',
      recommendation: 'Remove',
    };

    // Both bundle analysis and supabase scan return the same finding
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [duplicateFinding],
    });

    mockScanSupabase.mockResolvedValue({
      ...cleanSupabaseResult(),
      findings: [duplicateFinding],
    });

    const result = await scanVibeApp({ appUrl: 'https://test.supabase.co' });
    // Should be deduplicated to 1
    const bu001Count = result.findings.filter((f) => f.id === 'BU-001').length;
    expect(bu001Count).toBe(1);
  });

  it('keeps findings with same id but different evidence', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      findings: [
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'critical',
          title: 'Secret 1',
          description: 'First secret',
          evidence: 'sk-aaaa***aaaa via SP-001',
          recommendation: 'Remove',
        },
        {
          id: 'BU-001',
          category: 'exposed-secret',
          severity: 'critical',
          title: 'Secret 2',
          description: 'Second secret',
          evidence: 'ghp_AAAA***AAAA via SP-075',
          recommendation: 'Remove',
        },
      ],
    });

    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    const bu001Count = result.findings.filter((f) => f.id === 'BU-001').length;
    expect(bu001Count).toBe(2);
  });

  // ── Result structure ──────────────────────────────────

  it('returns correct result structure', async () => {
    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });

    expect(result).toHaveProperty('appUrl', 'https://myapp.vercel.app');
    expect(result).toHaveProperty('detectedPlatform');
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('bundlesAnalyzed');
    expect(result).toHaveProperty('packagesChecked');
    expect(result).toHaveProperty('cveMatches');
    expect(result).toHaveProperty('errors');
    expect(Array.isArray(result.findings)).toBe(true);
    expect(Array.isArray(result.errors)).toBe(true);
  });

  it('reports bundlesAnalyzed from bundle result', async () => {
    mockAnalyzeBundles.mockResolvedValue({
      ...cleanBundleResult(),
      bundlesAnalyzed: 5,
    });

    const result = await scanVibeApp({ appUrl: 'https://myapp.vercel.app' });
    expect(result.bundlesAnalyzed).toBe(5);
  });
});
