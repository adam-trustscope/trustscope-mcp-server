/**
 * Enforcement Module
 *
 * Detection and reporting of TrustScope enforcement coverage.
 */

export {
  detectEnforcement,
  detectEnforcementSync,
  getEnforcementDescription,
  type EnforcementCoverage,
  type EnforcementStatus,
} from './detector.js';
