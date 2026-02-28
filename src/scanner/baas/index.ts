// ============================================================
// Vigile CLI — BaaS Scanner Module (barrel export)
// ============================================================

export { matchSecrets, SECRET_PATTERNS } from './secret-patterns.js';
export type { SecretPattern, SecretMatch } from './secret-patterns.js';

export { analyzeBundles } from './bundle-analyzer.js';
export type { BundleAnalysisResult } from './bundle-analyzer.js';

export { scanSupabase } from './supabase-scanner.js';
export type { SupabaseScanOptions, SupabaseScanResult } from './supabase-scanner.js';

export { scanFirebase } from './firebase-scanner.js';
export type { FirebaseScanOptions, FirebaseScanResult } from './firebase-scanner.js';

export { scanVibeApp } from './vibe-app-scanner.js';
export type { VibeAppScanOptions, VibeAppScanResult, BaaSPlatform } from './vibe-app-scanner.js';

export { detectCves, parseNpmPackages } from './cve-detector.js';
export type { DetectedPackage, CveMatch, CveDetectionResult } from './cve-detector.js';
