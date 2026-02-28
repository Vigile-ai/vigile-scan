// ============================================================
// Vigile CLI — Vibe App Scanner (orchestrator)
// The top-level BaaS scan orchestrator. Given a URL, detects
// which BaaS platform is in use, then routes to the appropriate
// sub-scanner, bundle-analyzer, and CVE detector.
// ============================================================
//
// Scan flow:
//   1. Bundle analysis  — download JS bundles, scan for secrets
//   2. Platform detect  — identify Supabase or Firebase signals
//   3. Platform scan    — run supabase-scanner or firebase-scanner
//   4. Package detection — try fetching package.json for CVE scan
//   5. CVE detection    — check detected packages against OSV.dev
//   6. Aggregate        — merge and deduplicate all findings
// ============================================================

import { analyzeBundles } from './bundle-analyzer.js';
import { scanSupabase } from './supabase-scanner.js';
import { scanFirebase } from './firebase-scanner.js';
import { detectCves, parseNpmPackages } from './cve-detector.js';
import type { DetectedPackage } from './cve-detector.js';
import type { Finding } from '../../types/index.js';

const FETCH_TIMEOUT_MS = 10_000;

export type BaaSPlatform = 'supabase' | 'firebase' | 'unknown';

export interface VibeAppScanOptions {
  /** The deployed app URL (e.g. https://myapp.vercel.app) */
  appUrl: string;
  /** Override BaaS platform detection */
  platform?: BaaSPlatform;
  /** Extra Supabase project URL if different from appUrl */
  supabaseUrl?: string;
  /** Extra Firebase project URL if different from appUrl */
  firebaseUrl?: string;
}

export interface VibeAppScanResult {
  appUrl: string;
  detectedPlatform: BaaSPlatform;
  findings: Finding[];
  bundlesAnalyzed: number;
  packagesChecked: number;
  cveMatches: number;
  errors: string[];
}

// ── Fetch with timeout ──────────────────────────────────────

async function fetchWithTimeout(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ── Platform detection ──────────────────────────────────────

/**
 * Detects which BaaS platform is used by examining:
 *   1. Secret finding evidence from bundle analysis
 *   2. URL patterns (*.supabase.co, *.web.app, *.firebaseapp.com)
 *   3. Bundle content signals (import paths, SDK references)
 */
function detectPlatform(findings: Finding[], appUrl: string): BaaSPlatform {
  // Signal 1: Evidence from secret pattern matches
  for (const f of findings) {
    const ev = (f.evidence ?? '').toLowerCase();
    const title = f.title.toLowerCase();

    // Supabase signals — anon key JWTs, supabase SDK references
    if (
      ev.includes('supabase') ||
      title.includes('supabase') ||
      ev.includes('sb-') ||
      ev.includes('.supabase.co')
    ) {
      return 'supabase';
    }

    // Firebase signals — API keys, firebase SDK references
    if (
      ev.includes('firebase') ||
      title.includes('firebase') ||
      ev.includes('aizasy') || // Firebase API key prefix (lowercased)
      ev.includes('.firebaseapp.com') ||
      ev.includes('.firebaseio.com')
    ) {
      return 'firebase';
    }
  }

  // Signal 2: URL patterns
  try {
    const hostname = new URL(appUrl).hostname;
    if (hostname.endsWith('.supabase.co')) return 'supabase';
    if (hostname.endsWith('.web.app') || hostname.endsWith('.firebaseapp.com')) {
      return 'firebase';
    }
  } catch {
    // Invalid URL — fall through
  }

  return 'unknown';
}

// ── Package.json detection ──────────────────────────────────

/**
 * Attempts to fetch package.json from common paths on the deployed app.
 * Many frameworks (Next.js on Vercel, CRA) don't serve package.json,
 * but some setups expose it. This is a best-effort heuristic.
 */
async function tryFetchPackageJson(appUrl: string): Promise<DetectedPackage[]> {
  const baseUrl = appUrl.endsWith('/') ? appUrl : `${appUrl}/`;

  // Common paths where package.json might be accessible
  const paths = [
    'package.json',
    'assets/package.json',
  ];

  for (const path of paths) {
    try {
      const res = await fetchWithTimeout(`${baseUrl}${path}`);
      if (res.ok) {
        const text = await res.text();
        // Validate it looks like a real package.json (not an HTML 404 page)
        if (text.trimStart().startsWith('{') && text.includes('"dependencies"')) {
          return parseNpmPackages(text);
        }
      }
    } catch {
      // Path not available — try next
      continue;
    }
  }

  return [];
}

/**
 * Extract npm package references from bundle content.
 * Bundles often contain package version comments or source map references
 * like "node_modules/react/index.js" that reveal dependency names.
 * We can't get exact versions from minified bundles, but we can detect
 * which packages are in use for informational purposes.
 */
function extractPackagesFromBundleFindings(findings: Finding[]): string[] {
  const packageNames = new Set<string>();

  for (const f of findings) {
    const ev = f.evidence ?? '';
    // Look for node_modules references in evidence
    const nodeModuleMatches = ev.matchAll(/node_modules\/(@[^/]+\/[^/]+|[^/]+)/g);
    for (const m of nodeModuleMatches) {
      if (m[1]) packageNames.add(m[1]);
    }
  }

  return Array.from(packageNames);
}

// ── Finding deduplication ───────────────────────────────────

/**
 * Deduplicates findings by their id + evidence combination.
 * The bundle analyzer and platform scanners may both find the
 * same secret, so we remove exact duplicates.
 */
function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const unique: Finding[] = [];

  for (const f of findings) {
    const key = `${f.id}::${f.evidence ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(f);
  }

  return unique;
}

// ── Main export ─────────────────────────────────────────────

/**
 * Orchestrates a full BaaS security scan for a deployed web app.
 *
 * @param opts  App URL and optional platform overrides
 */
export async function scanVibeApp(opts: VibeAppScanOptions): Promise<VibeAppScanResult> {
  const allFindings: Finding[] = [];
  const errors: string[] = [];
  let packagesChecked = 0;
  let cveMatches = 0;

  // ── Step 1: Bundle analysis (always runs) ─────────────────
  const bundleResult = await analyzeBundles(opts.appUrl);
  allFindings.push(...bundleResult.findings);
  errors.push(...bundleResult.errors);

  // ── Step 2: Platform detection ────────────────────────────
  const detectedPlatform: BaaSPlatform =
    opts.platform ?? detectPlatform(bundleResult.findings, opts.appUrl);

  // ── Step 3: Platform-specific scan ────────────────────────
  if (detectedPlatform === 'supabase' || opts.supabaseUrl) {
    const supabaseUrl = opts.supabaseUrl ?? opts.appUrl;
    try {
      const supabaseResult = await scanSupabase({ projectUrl: supabaseUrl });
      // Only add non-duplicate findings (bundle analyzer already ran inside scanSupabase)
      allFindings.push(...supabaseResult.findings);
      errors.push(...supabaseResult.errors);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`Supabase scan failed: ${msg}`);
    }
  }

  if (detectedPlatform === 'firebase' || opts.firebaseUrl) {
    const firebaseUrl = opts.firebaseUrl ?? opts.appUrl;
    try {
      const firebaseResult = await scanFirebase({ projectUrl: firebaseUrl });
      allFindings.push(...firebaseResult.findings);
      errors.push(...firebaseResult.errors);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`Firebase scan failed: ${msg}`);
    }
  }

  if (detectedPlatform === 'unknown' && !opts.supabaseUrl && !opts.firebaseUrl) {
    errors.push(
      'Could not detect BaaS platform (Supabase or Firebase) from bundle analysis or URL. ' +
      'Provide --supabase <url> or --firebase <url> explicitly for deeper platform scanning.',
    );
  }

  // ── Step 4: Package detection for CVE scan ────────────────
  let packages: DetectedPackage[] = [];

  // Try fetching package.json from the deployed app
  try {
    packages = await tryFetchPackageJson(opts.appUrl);
  } catch {
    // Non-fatal — package.json fetch is best-effort
  }

  // If no package.json found, note the bundle-detected packages
  if (packages.length === 0) {
    const bundlePackageNames = extractPackagesFromBundleFindings(bundleResult.findings);
    if (bundlePackageNames.length > 0) {
      errors.push(
        `Detected ${bundlePackageNames.length} package(s) in bundles but could not ` +
        `determine versions for CVE lookup: ${bundlePackageNames.slice(0, 5).join(', ')}` +
        (bundlePackageNames.length > 5 ? '...' : ''),
      );
    }
  }

  // ── Step 5: CVE detection ─────────────────────────────────
  if (packages.length > 0) {
    try {
      const cveResult = await detectCves(packages);
      allFindings.push(...cveResult.findings);
      errors.push(...cveResult.errors);
      packagesChecked = cveResult.packagesChecked;
      cveMatches = cveResult.matches.length;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`CVE detection failed: ${msg}`);
    }
  }

  // ── Step 6: Deduplicate and return ────────────────────────
  const findings = deduplicateFindings(allFindings);

  return {
    appUrl: opts.appUrl,
    detectedPlatform,
    findings,
    bundlesAnalyzed: bundleResult.bundlesAnalyzed,
    packagesChecked,
    cveMatches,
    errors,
  };
}
