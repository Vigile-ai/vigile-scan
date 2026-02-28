// ============================================================
// Vigile CLI — BaaS Bundle Analyzer
// Downloads JS bundles from a deployed web app and scans them
// for exposed secrets using the secret-patterns library.
// ============================================================
//
// Limits (chosen to mirror browser devtools behavior):
//   MAX_BUNDLE_SIZE  5 MB  — realistic for any production bundle
//   MAX_BUNDLES      10    — covers most SPAs; prevents runaway
//   FETCH_TIMEOUT    15 s  — generous enough for slow edge CDNs

import { matchSecrets } from './secret-patterns.js';
import type { Finding } from '../../types/index.js';

const MAX_BUNDLE_SIZE = 5 * 1024 * 1024; // 5 MB
const MAX_BUNDLES = 10;
const FETCH_TIMEOUT_MS = 15_000;

export interface BundleAnalysisResult {
  /** The app URL that was scanned */
  url: string;
  /** Number of JS bundles successfully analyzed */
  bundlesAnalyzed: number;
  /** Security findings from all bundles */
  findings: Finding[];
  /** Non-fatal errors (e.g. one bundle 404'd but others succeeded) */
  errors: string[];
}

// ── HTML script-source extraction ──────────────────────────

/**
 * Parses raw HTML and returns all script src values that look
 * like JS bundle paths (relative or absolute).
 */
function extractScriptSrcs(html: string, baseUrl: string): string[] {
  const srcs: string[] = [];
  // Match <script src="..."> and <script src='...'>
  const scriptRe = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  for (const m of html.matchAll(scriptRe)) {
    const src = m[1];
    if (!src) continue;
    // Skip obvious non-bundle srcs (inline polyfills, analytics tags)
    if (src.startsWith('data:')) continue;
    try {
      const resolved = new URL(src, baseUrl).toString();
      srcs.push(resolved);
    } catch {
      // Malformed src — skip
    }
  }
  return srcs;
}

// ── Fetch helpers ───────────────────────────────────────────

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchText(url: string): Promise<{ text: string; error?: string }> {
  try {
    const res = await fetchWithTimeout(url, FETCH_TIMEOUT_MS);
    if (!res.ok) {
      return { text: '', error: `HTTP ${res.status} for ${url}` };
    }
    const contentLength = parseInt(res.headers.get('content-length') ?? '0', 10);
    if (contentLength > MAX_BUNDLE_SIZE) {
      return { text: '', error: `Bundle too large (${contentLength} bytes): ${url}` };
    }
    const buffer = await res.arrayBuffer();
    if (buffer.byteLength > MAX_BUNDLE_SIZE) {
      return { text: '', error: `Bundle exceeds 5 MB limit: ${url}` };
    }
    return { text: new TextDecoder().decode(buffer) };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { text: '', error: `Fetch failed for ${url}: ${msg}` };
  }
}

// ── Finding construction ────────────────────────────────────

function makeSecretFinding(
  bundleUrl: string,
  matchedId: string,
  matchedName: string,
  severity: 'critical' | 'high' | 'medium' | 'low',
  maskedValue: string,
  context: string,
  index: number,
): Finding {
  return {
    id: `BU-${String(index + 1).padStart(3, '0')}`,
    category: 'exposed-secret',
    severity,
    title: `Exposed ${matchedName} secret in JS bundle`,
    description:
      `A ${matchedName} credential was found in a compiled JavaScript bundle ` +
      `at ${bundleUrl}. Secrets baked into frontend bundles are readable by ` +
      `anyone who inspects your app's network traffic or source code.`,
    evidence: `Pattern: ${matchedId} | Masked value: ${maskedValue} | Context: ${context}`,
    recommendation:
      `Move this secret to a server-side environment variable. Never include ` +
      `API keys or tokens in frontend JavaScript. Use a backend proxy or BFF ` +
      `(Backend for Frontend) pattern to make authenticated API calls.`,
  };
}

// ── Main export ─────────────────────────────────────────────

/**
 * Downloads JS bundles from a deployed web app URL, then scans
 * each bundle for exposed secrets using secret-patterns.ts.
 *
 * @param appUrl  The root URL of the deployed app (e.g. https://myapp.com)
 */
export async function analyzeBundles(appUrl: string): Promise<BundleAnalysisResult> {
  const errors: string[] = [];
  const findings: Finding[] = [];
  let bundlesAnalyzed = 0;

  // Normalise URL
  const baseUrl = appUrl.endsWith('/') ? appUrl : `${appUrl}/`;

  // Step 1: Fetch the root HTML page
  const { text: html, error: htmlError } = await fetchText(baseUrl);
  if (htmlError || !html) {
    errors.push(htmlError ?? `Could not fetch root HTML for ${baseUrl}`);
    return { url: appUrl, bundlesAnalyzed: 0, findings, errors };
  }

  // Step 2: Extract script sources
  const scriptUrls = extractScriptSrcs(html, baseUrl).slice(0, MAX_BUNDLES);
  if (scriptUrls.length === 0) {
    errors.push(`No <script src> tags found in HTML at ${baseUrl}`);
    return { url: appUrl, bundlesAnalyzed: 0, findings, errors };
  }

  // Step 3: Fetch and scan each bundle
  let findingIndex = 0;
  for (const scriptUrl of scriptUrls) {
    const { text: bundleText, error: fetchError } = await fetchText(scriptUrl);
    if (fetchError || !bundleText) {
      errors.push(fetchError ?? `Empty bundle at ${scriptUrl}`);
      continue;
    }

    bundlesAnalyzed++;

    const matches = matchSecrets(bundleText);
    for (const secretMatch of matches) {
      findings.push(
        makeSecretFinding(
          scriptUrl,
          secretMatch.pattern.id,
          secretMatch.pattern.name,
          secretMatch.pattern.severity,
          secretMatch.match,
          secretMatch.context,
          findingIndex++,
        ),
      );
    }
  }

  return { url: appUrl, bundlesAnalyzed, findings, errors };
}
