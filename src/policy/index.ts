/**
 * Policy Module
 *
 * Provides policy definitions, defaults, and evaluation engine.
 */

// Types
export type {
  PolicyAction,
  PolicyConfig,
  PolicyPack,
  PolicyEvaluationResult,
  PolicyEvaluationResultSet,
  PolicyEvaluationInput,
} from './types.js';

// Defaults
export {
  DEFAULT_POLICY_CONFIGS,
  DEFAULT_POLICY_PACK,
  getDefaultPolicy,
  getAllDefaultPolicies,
  mergePolicies,
  createStrictPolicies,
  createPermissivePolicies,
} from './defaults.js';

// Engine
export {
  PolicyEngine,
  policyEngine,
  evaluateContent,
  checkPatterns,
  checkStatistical,
  shouldBlock,
} from './engine.js';

// Cache
export { PolicyCache, createPolicyCache, type PolicyCacheConfig, type CacheStats } from './cache.js';
