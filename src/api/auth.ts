// ============================================================
// Vigile CLI — Auth Management
// ============================================================
// Handles token resolution, persistent storage in ~/.vigile/config.json,
// and provides the auth login/status/logout logic.
//
// Token resolution priority:
//   1. VIGILE_TOKEN environment variable (CI/CD friendly)
//   2. ~/.vigile/config.json (persistent local config)

import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { VigileApiClient, type ApiUserInfo } from './client.js';

// ──────────────────────────────────────────────────────────
// Config file paths
// ──────────────────────────────────────────────────────────

const CONFIG_DIR = join(homedir(), '.vigile');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

// ──────────────────────────────────────────────────────────
// Config shape
// ──────────────────────────────────────────────────────────

interface VigileConfig {
  token?: string;
  api_url?: string;
  user?: {
    email: string;
    tier: string;
    name?: string;
  };
}

// ──────────────────────────────────────────────────────────
// Token & URL Resolution
// ──────────────────────────────────────────────────────────

/**
 * Resolve the API token.
 * Priority: VIGILE_TOKEN env var > ~/.vigile/config.json
 */
export async function resolveToken(): Promise<string | null> {
  // 1. Environment variable takes precedence
  const envToken = process.env.VIGILE_TOKEN;
  if (envToken && envToken.length > 0) {
    return envToken;
  }

  // 2. Config file
  const config = await loadConfig();
  return config.token || null;
}

/**
 * Resolve the API base URL.
 * Priority: VIGILE_API_URL env var > ~/.vigile/config.json > default
 */
export async function resolveApiUrl(): Promise<string> {
  const envUrl = process.env.VIGILE_API_URL;
  if (envUrl) return envUrl;

  const config = await loadConfig();
  return config.api_url || 'https://api.vigile.dev';
}

// ──────────────────────────────────────────────────────────
// Config File Operations
// ──────────────────────────────────────────────────────────

async function loadConfig(): Promise<VigileConfig> {
  try {
    const raw = await readFile(CONFIG_FILE, 'utf-8');
    return JSON.parse(raw) as VigileConfig;
  } catch {
    return {};
  }
}

async function saveConfig(config: VigileConfig): Promise<void> {
  await mkdir(CONFIG_DIR, { recursive: true });
  await writeFile(CONFIG_FILE, JSON.stringify(config, null, 2), {
    mode: 0o600, // Owner read/write only
  });
}

// ──────────────────────────────────────────────────────────
// Auth Actions
// ──────────────────────────────────────────────────────────

/**
 * Login: validate a token against the API and store it persistently.
 */
export async function authLogin(token: string): Promise<{
  success: boolean;
  user?: ApiUserInfo;
  error?: string;
}> {
  const apiUrl = await resolveApiUrl();
  const client = new VigileApiClient(apiUrl, token);
  const result = await client.getMe();

  if (!result.ok) {
    return { success: false, error: result.error };
  }

  // Persist token and user info
  const config = await loadConfig();
  config.token = token;
  config.user = {
    email: result.data.email,
    tier: result.data.tier,
    name: result.data.name || undefined,
  };
  await saveConfig(config);

  return { success: true, user: result.data };
}

/**
 * Check current authentication status.
 */
export async function authStatus(): Promise<{
  authenticated: boolean;
  source?: 'env' | 'config';
  user?: ApiUserInfo;
  error?: string;
}> {
  const envToken = process.env.VIGILE_TOKEN;
  const config = await loadConfig();
  const token = envToken || config.token;

  if (!token) {
    return { authenticated: false };
  }

  const source: 'env' | 'config' = envToken ? 'env' : 'config';
  const apiUrl = await resolveApiUrl();
  const client = new VigileApiClient(apiUrl, token);
  const result = await client.getMe();

  if (!result.ok) {
    return { authenticated: false, source, error: result.error };
  }

  return { authenticated: true, source, user: result.data };
}

/**
 * Logout: clear stored credentials from config file.
 */
export async function authLogout(): Promise<void> {
  const config = await loadConfig();
  delete config.token;
  delete config.user;
  await saveConfig(config);
}

// ──────────────────────────────────────────────────────────
// Convenience: get an authenticated client (or null)
// ──────────────────────────────────────────────────────────

/**
 * Create an authenticated API client, or return null if no token is available.
 * Used by the scan upload step and Sentinel API integration.
 */
export async function getAuthenticatedClient(): Promise<VigileApiClient | null> {
  const token = await resolveToken();
  if (!token) return null;

  const apiUrl = await resolveApiUrl();
  return new VigileApiClient(apiUrl, token);
}
