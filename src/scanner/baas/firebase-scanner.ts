// ============================================================
// Vigile CLI — Firebase Scanner
// Probes a Firebase project for Firestore/RTDB public access,
// Storage bucket exposure, config leaks, and missing App Check.
// ============================================================
//
// Finding IDs:
//   FB-001  Firestore public read/write           — critical
//   FB-002  RTDB public read/write                 — critical
//   FB-003  Firebase config object in bundle        — high
//   FB-004  Storage bucket publicly listable        — high
//   FB-005  Missing security headers on hosting     — medium
//   FB-006  RTDB .indexOn missing (data exposure)   — medium
// ============================================================

import type { Finding } from '../../types/index.js';
import { analyzeBundles } from './bundle-analyzer.js';

export interface FirebaseScanOptions {
  /** Firebase project URL (e.g. https://my-project.web.app or https://my-project.firebaseapp.com) */
  projectUrl: string;
  /** Firebase project ID — extracted from projectUrl if not provided */
  projectId?: string;
}

export interface FirebaseScanResult {
  projectUrl: string;
  projectId: string | null;
  findings: Finding[];
  /** Whether Firestore rules allow unauthenticated read/write */
  firestorePublicAccess: boolean;
  /** Whether RTDB rules allow unauthenticated read/write */
  rtdbPublicAccess: boolean;
  /** Whether Firebase config object was found exposed in bundles */
  configExposed: boolean;
  reachable: boolean;
  errors: string[];
}

const FETCH_TIMEOUT_MS = 10_000;

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

// ── URL normalisation ───────────────────────────────────────

function normaliseUrl(url: string): string {
  let u = url.replace(/\/+$/, '');
  if (!u.startsWith('http')) {
    u = `https://${u}`;
  }
  return u;
}

// ── Project ID extraction ───────────────────────────────────

/** Best-effort project ID extraction from Firebase hosting URLs. */
function extractProjectId(url: string): string | null {
  try {
    const hostname = new URL(url).hostname;
    // my-project.web.app -> my-project
    // my-project.firebaseapp.com -> my-project
    const match = hostname.match(/^([^.]+)\.(web\.app|firebaseapp\.com)$/);
    return match?.[1] ?? null;
  } catch {
    return null;
  }
}

// ── Firestore config extraction from bundle findings ────────

interface FirebaseConfigFromBundle {
  apiKey?: string;
  projectId?: string;
  storageBucket?: string;
}

/**
 * Attempt to extract Firebase config values from bundle analysis
 * findings. The SP-015/SP-016/SP-017 patterns match Firebase
 * apiKey, projectId, and storageBucket in compiled JS.
 */
function extractConfigFromFindings(findings: Finding[]): FirebaseConfigFromBundle {
  const config: FirebaseConfigFromBundle = {};
  for (const f of findings) {
    const ev = f.evidence ?? '';
    // Firebase API key pattern (AIzaSy...)
    if (ev.includes('AIzaSy')) {
      const keyMatch = ev.match(/AIzaSy[A-Za-z0-9_-]{33}/);
      if (keyMatch) config.apiKey = keyMatch[0];
    }
    // Project ID from evidence
    if (ev.includes('projectId') || ev.includes('firebase')) {
      const projMatch = ev.match(/["']([a-z0-9-]+)\.firebaseapp\.com["']/);
      if (projMatch) config.projectId = projMatch[1];
    }
    // Storage bucket
    if (ev.includes('storageBucket') || ev.includes('.appspot.com')) {
      const bucketMatch = ev.match(/([a-z0-9-]+)\.appspot\.com/);
      if (bucketMatch) config.storageBucket = bucketMatch[0];
    }
  }
  return config;
}

// ── Main export ─────────────────────────────────────────────

/**
 * Scans a Firebase-backed app for security misconfigurations.
 *
 * Scan flow:
 *   1. Extract project ID from URL
 *   2. Reachability check
 *   3. Bundle analysis — look for Firebase config exposure
 *   4. Firestore REST API — probe for unauthenticated read
 *   5. RTDB — probe /.json for unauthenticated read
 *   6. Storage — probe bucket for public file listing
 *   7. Hosting headers — check for security headers
 */
export async function scanFirebase(
  opts: FirebaseScanOptions,
): Promise<FirebaseScanResult> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  let firestorePublicAccess = false;
  let rtdbPublicAccess = false;
  let configExposed = false;
  let reachable = false;

  const baseUrl = normaliseUrl(opts.projectUrl);
  const projectId = opts.projectId ?? extractProjectId(baseUrl);

  // ── Step 1: Reachability ────────────────────────────────
  try {
    const res = await fetchWithTimeout(baseUrl, { method: 'HEAD' });
    reachable = res.status >= 200 && res.status < 500;
  } catch {
    errors.push(`Firebase project not reachable at ${baseUrl}`);
    return {
      projectUrl: baseUrl, projectId, findings,
      firestorePublicAccess, rtdbPublicAccess, configExposed,
      reachable, errors,
    };
  }

  if (!reachable) {
    errors.push(`Firebase project returned unexpected status at ${baseUrl}`);
    return {
      projectUrl: baseUrl, projectId, findings,
      firestorePublicAccess, rtdbPublicAccess, configExposed,
      reachable, errors,
    };
  }

  // ── Step 2: Bundle analysis ─────────────────────────────
  const bundleResult = await analyzeBundles(baseUrl);
  findings.push(...bundleResult.findings);
  if (bundleResult.errors.length > 0) {
    errors.push(...bundleResult.errors.map((e) => `[bundle] ${e}`));
  }

  // Check if Firebase config was exposed in bundles
  const bundleConfig = extractConfigFromFindings(bundleResult.findings);
  const detectedProjectId = projectId ?? bundleConfig.projectId ?? null;

  if (bundleConfig.apiKey) {
    configExposed = true;
    findings.push({
      id: 'FB-003',
      category: 'exposed-secret',
      severity: 'high',
      title: 'Firebase config object exposed in frontend bundle',
      description:
        'The Firebase client configuration (apiKey, projectId, etc.) was found ' +
        'in a JavaScript bundle. While Firebase API keys are designed to be ' +
        'public for client-side use, exposure without App Check enforcement ' +
        'allows abuse: automated account creation, Firestore/RTDB enumeration, ' +
        'and quota exhaustion attacks.',
      evidence: `Firebase apiKey: ${bundleConfig.apiKey.slice(0, 8)}*** detected in bundle`,
      recommendation:
        'Enable Firebase App Check in the Firebase Console to restrict API ' +
        'access to your legitimate app. Configure reCAPTCHA Enterprise or ' +
        'DeviceCheck attestation. Without App Check, anyone with the config ' +
        'can call your Firebase APIs.',
    });
  }

  // ── Step 3: Firestore public access probe ───────────────
  if (detectedProjectId) {
    const firestoreUrl =
      `https://firestore.googleapis.com/v1/projects/${detectedProjectId}/databases/(default)/documents`;

    try {
      const fsRes = await fetchWithTimeout(firestoreUrl);

      if (fsRes.ok) {
        // 200 without auth = Firestore rules allow public read
        firestorePublicAccess = true;

        let docCount = 0;
        try {
          const body = (await fsRes.json()) as { documents?: unknown[] };
          docCount = body.documents?.length ?? 0;
        } catch {
          // JSON parse failure is non-fatal
        }

        findings.push({
          id: 'FB-001',
          category: 'firebase-rules-issue',
          severity: 'critical',
          title: 'Firestore allows unauthenticated read access',
          description:
            'The Firestore REST API returned documents without any authentication ' +
            'token. This means Firestore Security Rules are configured with ' +
            '`allow read: if true` or similar permissive rules at the database or ' +
            'collection level. Any data in Firestore is publicly accessible.',
          evidence:
            `GET ${firestoreUrl} returned 200` +
            (docCount > 0 ? ` (${docCount} documents visible)` : ''),
          recommendation:
            'Update Firestore Security Rules to require authentication: ' +
            '`allow read: if request.auth != null;` at minimum. Ideally, add ' +
            'per-user rules: `allow read: if request.auth.uid == resource.data.userId;`',
        });
      }
      // 403/401 = rules are blocking unauthenticated access (good)
      // 404 = no default database or project not found
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`Firestore probe failed: ${msg}`);
    }

    // Also test write access
    try {
      const writeUrl =
        `https://firestore.googleapis.com/v1/projects/${detectedProjectId}/databases/(default)/documents/vigile_probe_test`;
      const writeRes = await fetchWithTimeout(writeUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fields: {
            _vigile_probe: { stringValue: 'security_test' },
          },
        }),
      });

      // 200 = write succeeded without auth (very bad)
      // 400 = request reached Firestore (rules didn't block, bad format)
      if (writeRes.status === 200) {
        firestorePublicAccess = true;
        findings.push({
          id: 'FB-001',
          category: 'firebase-rules-issue',
          severity: 'critical',
          title: 'Firestore allows unauthenticated WRITE access',
          description:
            'A document was successfully written to Firestore without any ' +
            'authentication. This means anyone on the internet can create, ' +
            'modify, or delete data in your database.',
          evidence: `POST to Firestore documents endpoint returned 200`,
          recommendation:
            'Immediately update Firestore Security Rules to block unauthenticated ' +
            'writes: `allow write: if request.auth != null;` — and review all ' +
            'existing data for tampering.',
        });
      }
    } catch {
      // Write probe failure is non-critical
    }
  } else {
    errors.push(
      'Could not determine Firebase project ID — skipping Firestore/RTDB probes. ' +
      'Provide --firebase-project-id or use a *.web.app / *.firebaseapp.com URL.',
    );
  }

  // ── Step 4: RTDB public access probe ────────────────────
  if (detectedProjectId) {
    // Firebase RTDB URLs follow: https://<project-id>-default-rtdb.firebaseio.com/
    // or https://<project-id>.firebaseio.com/ for older projects
    const rtdbUrls = [
      `https://${detectedProjectId}-default-rtdb.firebaseio.com/.json?shallow=true`,
      `https://${detectedProjectId}.firebaseio.com/.json?shallow=true`,
    ];

    for (const rtdbUrl of rtdbUrls) {
      try {
        const rtdbRes = await fetchWithTimeout(rtdbUrl);

        if (rtdbRes.ok) {
          rtdbPublicAccess = true;
          let keyCount = 0;
          try {
            const body = (await rtdbRes.json()) as Record<string, unknown> | null;
            if (body && typeof body === 'object') {
              keyCount = Object.keys(body).length;
            }
          } catch {
            // JSON parse failure is non-fatal
          }

          findings.push({
            id: 'FB-002',
            category: 'firebase-rules-issue',
            severity: 'critical',
            title: 'Realtime Database allows unauthenticated read access',
            description:
              'The Firebase Realtime Database returned data at the root path ' +
              'without any authentication. RTDB rules are configured with ' +
              '`".read": true` or `".read": "auth == null"` or similar. ' +
              'All data stored in RTDB is publicly accessible.',
            evidence:
              `GET ${rtdbUrl.replace(/\?.*/, '')} returned 200` +
              (keyCount > 0 ? ` (${keyCount} top-level keys)` : ''),
            recommendation:
              'Update RTDB Security Rules to require authentication: ' +
              '`".read": "auth != null"` at minimum. Review what data is stored ' +
              'in RTDB and assume it has been scraped if this rule was open.',
          });

          // Only need one RTDB URL to confirm — break
          break;
        }
        // 401 = "Permission denied" (good, rules are working)
        // 404 = RTDB not provisioned at this URL pattern
      } catch {
        // Timeout or network error — try the next URL pattern
        continue;
      }
    }

    // Also test RTDB write access
    try {
      const rtdbWriteUrl =
        `https://${detectedProjectId}-default-rtdb.firebaseio.com/vigile_probe_test.json`;
      const rtdbWriteRes = await fetchWithTimeout(rtdbWriteUrl, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ _vigile_probe: 'security_test' }),
      });

      if (rtdbWriteRes.ok) {
        rtdbPublicAccess = true;
        findings.push({
          id: 'FB-002',
          category: 'firebase-rules-issue',
          severity: 'critical',
          title: 'Realtime Database allows unauthenticated WRITE access',
          description:
            'Data was successfully written to Firebase Realtime Database without ' +
            'any authentication. Anyone can create, modify, or delete data.',
          evidence: `PUT to RTDB vigile_probe_test.json returned 200`,
          recommendation:
            'Immediately update RTDB Security Rules: `".write": "auth != null"`. ' +
            'Audit all existing data for tampering. Consider migrating sensitive ' +
            'data to Firestore with stricter per-document rules.',
        });
      }
    } catch {
      // Write probe failure is non-critical
    }
  }

  // ── Step 5: Firebase Storage bucket probe ───────────────
  if (detectedProjectId) {
    const storageBucket =
      bundleConfig.storageBucket ?? `${detectedProjectId}.appspot.com`;

    // Try listing objects in the default bucket
    const storageUrl =
      `https://firebasestorage.googleapis.com/v0/b/${storageBucket}/o`;

    try {
      const storageRes = await fetchWithTimeout(storageUrl);

      if (storageRes.ok) {
        let itemCount = 0;
        try {
          const body = (await storageRes.json()) as { items?: unknown[] };
          itemCount = body.items?.length ?? 0;
        } catch {
          // non-fatal
        }

        findings.push({
          id: 'FB-004',
          category: 'firebase-rules-issue',
          severity: 'high',
          title: 'Firebase Storage bucket is publicly listable',
          description:
            'The Firebase Storage bucket returned a file listing without ' +
            'authentication. Storage Security Rules allow public read access. ' +
            'All files in the bucket can be enumerated and downloaded by anyone.',
          evidence:
            `GET ${storageUrl} returned 200` +
            (itemCount > 0 ? ` (${itemCount} files visible)` : ''),
          recommendation:
            'Update Firebase Storage Security Rules to require authentication: ' +
            '`allow read: if request.auth != null;` — Review uploaded files for ' +
            'sensitive content (user uploads, profile pictures, documents).',
        });
      }
    } catch {
      // Storage probe failure is non-critical
    }
  }

  // ── Step 6: Hosting security headers ────────────────────
  try {
    const headRes = await fetchWithTimeout(baseUrl);
    const headers = headRes.headers;

    const missingHeaders: string[] = [];
    if (!headers.get('x-content-type-options')) {
      missingHeaders.push('X-Content-Type-Options');
    }
    if (!headers.get('x-frame-options') && !headers.get('content-security-policy')?.includes('frame-ancestors')) {
      missingHeaders.push('X-Frame-Options or CSP frame-ancestors');
    }
    if (!headers.get('strict-transport-security')) {
      missingHeaders.push('Strict-Transport-Security');
    }

    if (missingHeaders.length >= 2) {
      findings.push({
        id: 'FB-005',
        category: 'cors-misconfiguration',
        severity: 'medium',
        title: 'Firebase Hosting missing security headers',
        description:
          `The Firebase Hosting response is missing ${missingHeaders.length} ` +
          `recommended security headers: ${missingHeaders.join(', ')}. ` +
          'These headers protect against clickjacking, MIME sniffing, and ' +
          'protocol downgrade attacks.',
        evidence: `Missing: ${missingHeaders.join(', ')}`,
        recommendation:
          'Add security headers in firebase.json under hosting.headers: ' +
          '{"source": "**", "headers": [{"key": "X-Content-Type-Options", ' +
          '"value": "nosniff"}, {"key": "X-Frame-Options", "value": "DENY"}]}',
      });
    }
  } catch {
    // Header check is non-critical
  }

  return {
    projectUrl: baseUrl,
    projectId: detectedProjectId,
    findings,
    firestorePublicAccess,
    rtdbPublicAccess,
    configExposed,
    reachable,
    errors,
  };
}
