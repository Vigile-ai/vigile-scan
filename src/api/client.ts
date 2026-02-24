// ============================================================
// Vigile CLI — API Client
// ============================================================
// Lightweight HTTP client for communicating with the Vigile API.
// Uses Node 18+ native fetch. Graceful degradation: if the API
// is unreachable, the CLI continues in local-only mode.
//
// All methods return a discriminated union:
//   { ok: true, data: T } | { ok: false, error: string, status: number }
// This avoids thrown exceptions and makes error handling explicit.

const DEFAULT_API_URL = 'https://api.vigile.dev';
const API_TIMEOUT_MS = 15_000; // 15 seconds
const CLI_VERSION = '0.2.0';

// ──────────────────────────────────────────────────────────
// Response Types
// ──────────────────────────────────────────────────────────

export interface ApiUserInfo {
  id: number;
  email: string;
  name: string | null;
  tier: string; // 'free' | 'pro' (team/enterprise planned for future)
}

export interface ApiScanResponse {
  id: number;
  server_name: string;
  trust_score: number;
  trust_level: string;
  score_breakdown: Record<string, number> | null;
  findings: Array<Record<string, unknown>>;
  findings_count: number;
  critical_count: number;
  high_count: number;
  scanner_version: string;
  scanned_at: string;
}

export interface ApiSkillScanResponse {
  id: number;
  skill_name: string;
  file_type: string;
  platform: string;
  trust_score: number;
  trust_level: string;
  score_breakdown: Record<string, number> | null;
  findings: Array<Record<string, unknown>>;
  findings_count: number;
  critical_count: number;
  high_count: number;
  scanner_version: string;
  scanned_at: string;
}

export interface ApiSentinelSessionResponse {
  session_id: number;
  server_name: string;
  max_duration_seconds: number;
  status: string;
  created_at: string;
}

export interface ApiSentinelEventsResponse {
  status: string;
  events_received: number;
  total_events: number;
}

export interface ApiSentinelReportResponse {
  id: number;
  session_id: number;
  server_name: string;
  monitoring_duration: number;
  total_events: number;
  unique_destinations: string[];
  findings: Array<{
    id: string;
    category: string;
    severity: string;
    title: string;
    description: string;
    server_name: string;
    evidence_count: number;
    recommendation: string;
    confidence: number;
  }>;
  threat_level: string;
  threat_score: number;
  started_at: string;
  ended_at: string;
  user_tier: string;
}

/** Discriminated union result type */
export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status: number };

// ──────────────────────────────────────────────────────────
// API Client
// ──────────────────────────────────────────────────────────

export class VigileApiClient {
  private baseUrl: string;
  private token: string | null;

  constructor(baseUrl?: string, token?: string | null) {
    const rawUrl = (baseUrl || process.env.VIGILE_API_URL || DEFAULT_API_URL)
      .replace(/\/+$/, ''); // strip trailing slashes
    // Validate URL — must be HTTPS (unless localhost for development)
    try {
      const u = new URL(rawUrl);
      if (u.protocol !== 'https:' && u.hostname !== 'localhost' && u.hostname !== '127.0.0.1') {
        console.error(`[vigile] API URL must use HTTPS — falling back to default`);
        this.baseUrl = DEFAULT_API_URL;
      } else {
        this.baseUrl = rawUrl;
      }
    } catch {
      console.error(`[vigile] Invalid API URL — falling back to default`);
      this.baseUrl = DEFAULT_API_URL;
    }
    this.token = token || null;
  }

  get isAuthenticated(): boolean {
    return this.token !== null && this.token.length > 0;
  }

  // ── Private helpers ──

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<ApiResult<T>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': `vigile-cli/${CLI_VERSION}`,
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.text();
        let errorMessage: string;
        try {
          const parsed = JSON.parse(errorBody);
          errorMessage = typeof parsed.detail === 'string'
            ? parsed.detail
            : JSON.stringify(parsed.detail);
        } catch {
          errorMessage = errorBody || `HTTP ${response.status}`;
        }
        return { ok: false, error: errorMessage, status: response.status };
      }

      const data = (await response.json()) as T;
      return { ok: true, data };
    } catch (err) {
      clearTimeout(timeoutId);
      if (err instanceof Error && err.name === 'AbortError') {
        return { ok: false, error: 'Request timed out', status: 0 };
      }
      return {
        ok: false,
        error: err instanceof Error ? err.message : 'Network error',
        status: 0,
      };
    }
  }

  // ── Auth ──

  async getMe(): Promise<ApiResult<ApiUserInfo>> {
    return this.request<ApiUserInfo>('GET', '/api/v1/auth/me');
  }

  // ── Scanning ──

  async submitMCPScan(payload: {
    server_name: string;
    source?: string;
    package_url?: string;
    repo_url?: string;
    description?: string;
    readme?: string;
    tool_descriptions?: string[];
    maintainer?: string;
    license?: string;
    homepage?: string;
  }): Promise<ApiResult<ApiScanResponse>> {
    return this.request<ApiScanResponse>('POST', '/api/v1/scan/', payload);
  }

  async submitSkillScan(payload: {
    skill_name: string;
    content: string;
    file_type?: string;
    platform?: string;
    source?: string;
  }): Promise<ApiResult<ApiSkillScanResponse>> {
    return this.request<ApiSkillScanResponse>('POST', '/api/v1/scan/skill', payload);
  }

  // ── Sentinel ──

  async createSentinelSession(
    serverName: string,
    durationSeconds: number,
    client: string = 'cli',
  ): Promise<ApiResult<ApiSentinelSessionResponse>> {
    return this.request<ApiSentinelSessionResponse>('POST', '/api/v1/sentinel/sessions', {
      server_name: serverName,
      duration_seconds: durationSeconds,
      client,
    });
  }

  async submitSentinelEvents(
    sessionId: number,
    events: Array<{
      timestamp: number;
      server_name: string;
      method: string;
      url: string;
      destination_ip?: string | null;
      port: number;
      request_size: number;
      response_size?: number | null;
      status_code?: number | null;
      headers?: Record<string, string> | null;
      dns_query_type?: string | null;
      tls: boolean;
      body_hash?: string | null;
      body_entropy?: number | null;
    }>,
  ): Promise<ApiResult<ApiSentinelEventsResponse>> {
    return this.request<ApiSentinelEventsResponse>(
      'POST',
      `/api/v1/sentinel/sessions/${sessionId}/events`,
      { session_id: sessionId, events },
    );
  }

  async analyzeSentinelSession(
    sessionId: number,
  ): Promise<ApiResult<ApiSentinelReportResponse>> {
    return this.request<ApiSentinelReportResponse>(
      'POST',
      `/api/v1/sentinel/sessions/${sessionId}/analyze`,
    );
  }
}
