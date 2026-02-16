// ============================================================
// Vigil CLI — JSON Output Formatter
// ============================================================
// Outputs scan results as structured JSON for CI/CD integration,
// piping to other tools, or sending to the Vigil API.

import type { ScanSummary } from '../types/index.js';

/**
 * Format scan summary as JSON string.
 */
export function formatJSON(summary: ScanSummary): string {
  return JSON.stringify(summary, null, 2);
}

/**
 * Format scan summary as compact JSON (single line, for piping).
 */
export function formatJSONCompact(summary: ScanSummary): string {
  return JSON.stringify(summary);
}
