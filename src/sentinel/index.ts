// ============================================================
// Vigile Sentinel — Module Exports
// ============================================================

export { SentinelEngine, getSentinelFeatures, SENTINEL_MARKETING } from './sentinel.js';
export type { SubscriptionTier, SentinelFeatureGate } from './sentinel.js';

export {
  SUSPICIOUS_ENDPOINT_PATTERNS,
  BEHAVIORAL_PATTERNS,
  CREDENTIAL_EXFIL_PATTERNS,
  calculateThreatScore,
  threatLevelFromScore,
} from './sentinel-patterns.js';
export type {
  NetworkEvent,
  SentinelFinding,
  SentinelReport,
  SentinelThreatLevel,
  EndpointPattern,
  BehavioralPattern,
} from './sentinel-patterns.js';
