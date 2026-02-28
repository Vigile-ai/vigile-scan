// ============================================================
// Vigile CLI — Supabase Scanner
// Actively probes a Supabase project for RLS misconfigurations,
// exposed credentials, auth settings, and CORS policy issues.
// ============================================================
//
// Finding IDs:
//   SB-001  RLS disabled (anon read allowed)     — critical
//   SB-002  Anon key exposed in frontend bundle   — high
//   SB-003  Email confirmation disabled           — medium
//   SB-004  CORS wildcard policy                  — medium
//   SB-005  Service role key exposed in bundle    — critical
//   SB-006  Anon write allowed (RLS disabled)     — critical
//   SB-007  Open signup enabled                   — low
// ============================================================

import type { Finding } from '../../types/index.js';
import { analyzeBundles } from './bundle-analyzer.js';

export interface SupabaseScanOptions {
  /** Supabase project URL (e.g. https://abcdefgh.supabase.co) */
  projectUrl: string;
  /** Anon/public key — usually safe to provide; used to test anon-level access */
  anonKey?: string;
}

export interface SupabaseScanResult {
  projectUrl: string;
  findings: Finding[];
  /** Tables discovered via anon REST API */
  tablesFound: string[];
  /** Whether anon read was allowed on any table */
  anonReadExposed: boolean;
  /** Whether the project URL resolves (basic reachability) */
  reachable: boolean;
  errors: string[];
}

const FETCH_TIMEOUT_MS = 10_000;

// ── Fetch with timeout (same pattern as bundle-analyzer) ────

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

// ── URL normalisation ───────────────────────────────────────

function normaliseSupabaseUrl(url: string): string {
  let u = url.replace(/\/+$/, '');
  if (!u.startsWith('http')) {
    u = `https://${u}`;
  }
  return u;
}

// ── Anon key extraction from bundle findings ────────────────

/**
 * Look through bundle analysis findings for a Supabase anon key.
 * SP-022/SP-023 patterns match the JWT format Supabase uses for
 * anon and service_role keys (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...).
 */
function extractAnonKeyFromFindings(findings: Finding[]): string | null {
  for (const f of findings) {
    const ev = f.evidence ?? '';
    if (
      (ev.includes('supabase') || ev.includes('SP-022') || ev.includes('SP-023')) &&
      ev.includes('eyJ')
    ) {
      const jwtMatch = ev.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
      if (jwtMatch) return jwtMatch[0];
    }
  }
  return null;
}

// ── Main export ─────────────────────────────────────────────

/**
 * Scans a Supabase project for security misconfigurations.
 *
 * Scan flow:
 *   1. Reachability check — does the REST API respond?
 *   2. Bundle analysis — scan the hosting URL for exposed keys
 *   3. Anon key resolution — use provided key, or extract from bundle
 *   4. Table enumeration — GET /rest/v1/ with anon key
 *   5. RLS testing — probe each table for anon read/write
 *   6. Auth settings — GET /auth/v1/settings
 *   7. CORS check — inspect Access-Control-Allow-Origin header
 */
export async function scanSupabase(
  opts: SupabaseScanOptions,
): Promise<SupabaseScanResult> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const tablesFound: string[] = [];
  let anonReadExposed = false;
  let reachable = false;

  const baseUrl = normaliseSupabaseUrl(opts.projectUrl);

  // ── Step 1: Reachability ────────────────────────────────
  try {
    const res = await fetchWithTimeout(`${baseUrl}/rest/v1/`, {
      method: 'HEAD',
    });
    // Supabase returns 401 without apikey — that's still reachable
    reachable = res.status === 401 || res.status === 200 || res.status === 403;
  } catch {
    errors.push(`Supabase project not reachable at ${baseUrl}`);
    return { projectUrl: baseUrl, findings, tablesFound, anonReadExposed, reachable, errors };
  }

  if (!reachable) {
    errors.push(`Supabase project returned unexpected status at ${baseUrl}/rest/v1/`);
    return { projectUrl: baseUrl, findings, tablesFound, anonReadExposed, reachable, errors };
  }

  // ── Step 2: Bundle analysis (for key exposure) ──────────
  const bundleResult = await analyzeBundles(baseUrl);
  findings.push(...bundleResult.findings);
  if (bundleResult.errors.length > 0) {
    errors.push(...bundleResult.errors.map((e) => `[bundle] ${e}`));
  }

  // Check for service_role key specifically
  const hasServiceRoleKey = bundleResult.findings.some(
    (f) =>
      f.evidence?.includes('service_role') ||
      f.evidence?.includes('SP-023'),
  );
  if (hasServiceRoleKey) {
    findings.push({
      id: 'SB-005',
      category: 'exposed-secret',
      severity: 'critical',
      title: 'Supabase service_role key exposed in frontend bundle',
      description:
        'The Supabase service_role key was found in a JavaScript bundle. ' +
        'This key bypasses all Row Level Security policies and grants full ' +
        'read/write/delete access to every table and storage bucket. ' +
        'This is equivalent to database superuser access.',
      evidence: 'Detected via bundle analysis — service_role JWT in compiled JS',
      recommendation:
        'Rotate the service_role key immediately in Supabase Dashboard > ' +
        'Settings > API. This key must NEVER appear in frontend code. ' +
        'Use it only in server-side functions (Edge Functions, API routes).',
    });
  }

  // ── Step 3: Resolve anon key ────────────────────────────
  let anonKey = opts.anonKey ?? null;
  if (!anonKey) {
    anonKey = extractAnonKeyFromFindings(bundleResult.findings);
  }

  if (!anonKey) {
    errors.push(
      'No anon key provided or detected in bundles — skipping RLS and table enumeration. ' +
      'Pass --supabase-key or ensure the app URL serves JS bundles with the anon key.',
    );
  }

  // ── Step 4: Table enumeration ───────────────────────────
  if (anonKey) {
    try {
      const tablesRes = await fetchWithTimeout(`${baseUrl}/rest/v1/`, {
        headers: {
          apikey: anonKey,
          Authorization: `Bearer ${anonKey}`,
        },
      });

      if (tablesRes.ok) {
        try {
          const schema = (await tablesRes.json()) as Record<string, unknown>;
          // The /rest/v1/ endpoint returns an OpenAPI spec.
          // Table names appear as keys under "paths" (e.g. "/users").
          const paths = (schema.paths ?? {}) as Record<string, unknown>;
          for (const path of Object.keys(paths)) {
            const tableName = path.replace(/^\//, '').split('?')[0];
            if (tableName && !tableName.includes('/')) {
              tablesFound.push(tableName);
            }
          }
        } catch {
          errors.push('Could not parse Supabase REST schema response');
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`Table enumeration failed: ${msg}`);
    }

    // ── Step 5: RLS testing per table ───────────────────────
    for (const table of tablesFound) {
      // Test anon READ
      try {
        const readRes = await fetchWithTimeout(
          `${baseUrl}/rest/v1/${table}?select=*&limit=1`,
          {
            headers: {
              apikey: anonKey,
              Authorization: `Bearer ${anonKey}`,
            },
          },
        );

        if (readRes.ok) {
          const body = await readRes.text();
          // Non-empty array means data was returned — RLS is off for reads
          if (body.startsWith('[') && body !== '[]') {
            anonReadExposed = true;
            findings.push({
              id: 'SB-001',
              category: 'rls-misconfiguration',
              severity: 'critical',
              title: `RLS disabled: anonymous read on "${table}"`,
              description:
                `Table "${table}" returned data via the anon key without any Row Level ` +
                `Security policies. Any user with the anon key (which is public) can ` +
                `read all rows in this table. This is the #1 Supabase security mistake.`,
              evidence: `GET /rest/v1/${table}?select=*&limit=1 returned 200 with data`,
              recommendation:
                `Enable RLS on table "${table}" in Supabase Dashboard > Database > ` +
                `Tables. Add a policy like: CREATE POLICY "auth read" ON "${table}" ` +
                `FOR SELECT USING (auth.uid() = user_id);`,
            });
          }
        }
      } catch {
        // Individual table probe failure — non-fatal
      }

      // Test anon WRITE
      // POST with empty object — 400 means RLS let it through to DB layer
      // (schema constraints caught it), 401/403 means RLS blocked it
      try {
        const writeRes = await fetchWithTimeout(
          `${baseUrl}/rest/v1/${table}`,
          {
            method: 'POST',
            headers: {
              apikey: anonKey,
              Authorization: `Bearer ${anonKey}`,
              'Content-Type': 'application/json',
              Prefer: 'return=minimal',
            },
            body: JSON.stringify({}),
          },
        );

        // 400 = RLS didn't block, schema constraints did (RLS is OFF)
        // 201/200 = insert succeeded (RLS is OFF and no constraints)
        // 401/403 = RLS blocked it (safe)
        if (
          writeRes.status === 400 ||
          writeRes.status === 201 ||
          writeRes.status === 200
        ) {
          findings.push({
            id: 'SB-006',
            category: 'rls-misconfiguration',
            severity: 'critical',
            title: `RLS disabled: anonymous write on "${table}"`,
            description:
              `Table "${table}" allows INSERT operations via the anon key. The ` +
              `request reached the database layer (RLS did not block it). Even if ` +
              `it failed on a constraint, the lack of RLS means anyone can attempt ` +
              `to write data to this table.`,
            evidence: `POST /rest/v1/${table} returned ${writeRes.status} (not 401/403)`,
            recommendation:
              `Enable RLS on table "${table}" and add INSERT policies. For example: ` +
              `CREATE POLICY "auth insert" ON "${table}" FOR INSERT WITH CHECK ` +
              `(auth.uid() = user_id);`,
          });
        }
      } catch {
        // Individual write probe failure — non-fatal
      }
    }
  }

  // ── Step 6: Auth configuration ──────────────────────────
  if (anonKey) {
    try {
      const authRes = await fetchWithTimeout(`${baseUrl}/auth/v1/settings`, {
        headers: {
          apikey: anonKey,
          Authorization: `Bearer ${anonKey}`,
        },
      });

      if (authRes.ok) {
        try {
          const settings = (await authRes.json()) as Record<string, unknown>;

          const autoconfirm = settings.mailer_autoconfirm ?? settings.autoconfirm;
          if (autoconfirm === true) {
            findings.push({
              id: 'SB-003',
              category: 'auth-misconfiguration',
              severity: 'medium',
              title: 'Email confirmation disabled (autoconfirm enabled)',
              description:
                'Supabase auth is configured to automatically confirm email addresses ' +
                'without requiring the user to click a verification link. This allows ' +
                'attackers to create accounts with any email address, including ' +
                'impersonating legitimate users.',
              evidence: 'GET /auth/v1/settings returned mailer_autoconfirm: true',
              recommendation:
                'Disable autoconfirm in Supabase Dashboard > Authentication > ' +
                'Settings > Email Auth. Require email verification for all new signups.',
            });
          }

          const disableSignup = settings.disable_signup;
          if (disableSignup === false) {
            findings.push({
              id: 'SB-007',
              category: 'auth-misconfiguration',
              severity: 'low',
              title: 'Open signup enabled',
              description:
                'Public signup is enabled on this Supabase project. If this is an ' +
                'internal tool or admin panel, open signup allows anyone to create ' +
                'an account.',
              evidence: 'GET /auth/v1/settings returned disable_signup: false',
              recommendation:
                'If this project is not meant for public registration, disable ' +
                'signup in Supabase Dashboard > Authentication > Settings.',
            });
          }
        } catch {
          errors.push('Could not parse auth settings response');
        }
      }
    } catch {
      errors.push('Auth settings endpoint not reachable');
    }
  }

  // ── Step 7: CORS policy check ───────────────────────────
  try {
    const corsRes = await fetchWithTimeout(`${baseUrl}/rest/v1/`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://evil-attacker-site.com',
        'Access-Control-Request-Method': 'GET',
      },
    });

    const allowOrigin = corsRes.headers.get('access-control-allow-origin');
    if (allowOrigin === '*' || allowOrigin === 'https://evil-attacker-site.com') {
      const isReflected = allowOrigin === 'https://evil-attacker-site.com';
      findings.push({
        id: 'SB-004',
        category: 'cors-misconfiguration',
        severity: 'medium',
        title: isReflected
          ? 'CORS reflects arbitrary origins on REST API'
          : 'CORS wildcard policy on REST API',
        description: isReflected
          ? 'The Supabase REST API reflects any Origin header back in ' +
            'Access-Control-Allow-Origin, which is functionally equivalent ' +
            'to a wildcard policy but harder to detect.'
          : 'The Supabase REST API returns Access-Control-Allow-Origin: * which ' +
            'allows any website to make authenticated requests to your API. ' +
            'Combined with an exposed anon key, this enables cross-origin ' +
            'data access from malicious sites.',
        evidence: isReflected
          ? 'OPTIONS /rest/v1/ reflected origin: https://evil-attacker-site.com'
          : 'OPTIONS /rest/v1/ returned Access-Control-Allow-Origin: *',
        recommendation:
          'Configure allowed origins in Supabase Dashboard > Settings > API. ' +
          'Restrict to your app domain(s) only.',
      });
    }
  } catch {
    // CORS check is non-critical
  }

  return {
    projectUrl: baseUrl,
    findings,
    tablesFound,
    anonReadExposed,
    reachable,
    errors,
  };
}
