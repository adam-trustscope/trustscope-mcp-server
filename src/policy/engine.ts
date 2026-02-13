/**
 * Policy Evaluation Engine
 *
 * Evaluates content against policies using detection engines.
 * Combines detection results with policy actions to produce final decisions.
 */

import {
  allEngines,
  patternEngines,
  statisticalEngines,
  type DetectionContext,
  type DetectionConfig,
  type DetectionResult,
  type SessionState,
  type Severity,
} from '../detection/index.js';
import type {
  PolicyConfig,
  PolicyAction,
  PolicyEvaluationResult,
  PolicyEvaluationResultSet,
  PolicyEvaluationInput,
} from './types.js';
import { DEFAULT_POLICY_CONFIGS } from './defaults.js';
import { PolicyCache, type PolicyCacheConfig } from './cache.js';

/**
 * Severity ordering for comparison
 */
const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  warning: 1,
  high: 2,
  critical: 3,
};

/**
 * Action ordering for comparison (most restrictive wins)
 */
const ACTION_ORDER: Record<PolicyAction, number> = {
  allow: 0,
  alert: 1,
  redact: 2,
  block: 3,
};

/**
 * Compare two severities, return higher one
 */
function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

/**
 * Compare two actions, return more restrictive one
 */
function maxAction(a: PolicyAction, b: PolicyAction): PolicyAction {
  return ACTION_ORDER[a] >= ACTION_ORDER[b] ? a : b;
}

/**
 * Convert policy config to detection config
 */
function policyToDetectionConfig(policy: PolicyConfig): DetectionConfig {
  return {
    enabled: policy.enabled,
    ...policy.config,
  };
}

/**
 * Evaluate a single detection result against its policy
 */
function evaluatePolicy(
  engineName: string,
  result: DetectionResult,
  policy: PolicyConfig,
): PolicyEvaluationResult {
  // If not triggered, return clean result
  if (!result.triggered) {
    return {
      engine: engineName,
      triggered: false,
      action: 'allow',
      blocked: false,
      redacted: false,
      severity: 'info',
      details: result.details,
    };
  }

  // Triggered - apply policy action
  const severity = policy.severity || result.severity;
  const action = policy.action;
  const blocked = action === 'block';
  const redacted = action === 'redact';

  return {
    engine: engineName,
    triggered: true,
    action,
    blocked,
    redacted,
    severity,
    confidence: result.confidence,
    details: result.details,
    message: result.message,
  };
}

/**
 * Main policy evaluation engine
 */
export class PolicyEngine {
  private policies: Record<string, PolicyConfig>;
  private policyVersion: string;
  private cache: PolicyCache;

  constructor(
    policies?: Record<string, PolicyConfig>,
    options?: { policyVersion?: string; cacheConfig?: PolicyCacheConfig },
  ) {
    this.policies = policies || DEFAULT_POLICY_CONFIGS;
    this.policyVersion = options?.policyVersion || '1.0.0';
    this.cache = new PolicyCache(this.policyVersion, options?.cacheConfig);
  }

  /**
   * Update policies
   */
  setPolicies(policies: Record<string, PolicyConfig>, newVersion?: string): void {
    this.policies = policies;
    if (newVersion) {
      this.policyVersion = newVersion;
      this.cache.invalidateOnPolicyChange(newVersion);
    } else {
      // Auto-increment version to invalidate cache
      const currentVersion = parseInt(this.policyVersion.split('.').pop() || '0', 10);
      this.policyVersion = `1.0.${currentVersion + 1}`;
      this.cache.invalidateOnPolicyChange(this.policyVersion);
    }
  }

  /**
   * Get current policies
   */
  getPolicies(): Record<string, PolicyConfig> {
    return { ...this.policies };
  }

  /**
   * Get a specific policy
   */
  getPolicy(engineName: string): PolicyConfig | undefined {
    return this.policies[engineName];
  }

  /**
   * Get policy version
   */
  getPolicyVersion(): string {
    return this.policyVersion;
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { hits: number; misses: number; entries: number; hitRate: number } {
    return this.cache.getStats();
  }

  /**
   * Clear the cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Evaluate content against all policies
   */
  evaluate(
    input: PolicyEvaluationInput,
    sessionState?: SessionState,
  ): PolicyEvaluationResultSet {
    const { content, context } = input;

    const detectionContext: DetectionContext = {
      agentId: context?.agentId,
      sessionId: context?.sessionId,
      actionType: context?.actionType,
      toolName: context?.toolName,
      direction: context?.direction,
      source: context?.source,
    };

    const results: PolicyEvaluationResult[] = [];
    let anyTriggered = false;
    let anyBlocked = false;
    let anyRedacted = false;
    let highestSeverity: Severity = 'info';
    let finalAction: PolicyAction = 'allow';

    // Run all enabled detection engines
    for (const [engineName, engine] of Object.entries(allEngines)) {
      const policy = this.policies[engineName];
      if (!policy || !policy.enabled) {
        continue;
      }

      try {
        const detectionConfig = policyToDetectionConfig(policy);
        const detectionResult = engine.check(
          content,
          detectionContext,
          detectionConfig,
          sessionState,
        );

        const policyResult = evaluatePolicy(engineName, detectionResult, policy);
        results.push(policyResult);

        if (policyResult.triggered) {
          anyTriggered = true;
          highestSeverity = maxSeverity(highestSeverity, policyResult.severity);
          finalAction = maxAction(finalAction, policyResult.action);

          if (policyResult.blocked) {
            anyBlocked = true;
          }
          if (policyResult.redacted) {
            anyRedacted = true;
          }
        }
      } catch (error) {
        // Fail open - log error but don't block
        results.push({
          engine: engineName,
          triggered: false,
          action: 'allow',
          blocked: false,
          redacted: false,
          severity: 'info',
          details: {
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });
      }
    }

    // Build summary
    const triggeredEngines = results.filter((r) => r.triggered).map((r) => r.engine);
    const blockedEngines = results.filter((r) => r.blocked).map((r) => r.engine);

    let summary: string;
    if (anyBlocked) {
      summary = `Blocked by ${blockedEngines.length} policy(ies): ${blockedEngines.join(', ')}`;
    } else if (anyTriggered) {
      summary = `Alerts from ${triggeredEngines.length} policy(ies): ${triggeredEngines.join(', ')}`;
    } else {
      summary = 'All policies passed';
    }

    return {
      results,
      anyTriggered,
      anyBlocked,
      anyRedacted,
      highestSeverity,
      finalAction,
      summary,
    };
  }

  /**
   * Evaluate content against pattern policies only
   * Use this for content scanning without session state
   * Results are cached for identical inputs (deterministic)
   */
  evaluatePatterns(
    input: PolicyEvaluationInput,
    options?: { skipCache?: boolean },
  ): PolicyEvaluationResultSet {
    const { content, context } = input;

    // Check cache first (pattern evaluations are deterministic)
    const cacheKey = this.cache.generateKey(context?.actionType || 'pattern_check', input);
    if (!options?.skipCache) {
      const cached = this.cache.get(cacheKey);
      if (cached) {
        return cached;
      }
    }

    const detectionContext: DetectionContext = {
      agentId: context?.agentId,
      sessionId: context?.sessionId,
      actionType: context?.actionType,
      toolName: context?.toolName,
      direction: context?.direction,
      source: context?.source,
    };

    const results: PolicyEvaluationResult[] = [];
    let anyTriggered = false;
    let anyBlocked = false;
    let anyRedacted = false;
    let highestSeverity: Severity = 'info';
    let finalAction: PolicyAction = 'allow';

    // Only run pattern detection engines
    for (const [engineName, engine] of Object.entries(patternEngines)) {
      const policy = this.policies[engineName];
      if (!policy || !policy.enabled) {
        continue;
      }

      try {
        const detectionConfig = policyToDetectionConfig(policy);
        const detectionResult = engine.check(content, detectionContext, detectionConfig);

        const policyResult = evaluatePolicy(engineName, detectionResult, policy);
        results.push(policyResult);

        if (policyResult.triggered) {
          anyTriggered = true;
          highestSeverity = maxSeverity(highestSeverity, policyResult.severity);
          finalAction = maxAction(finalAction, policyResult.action);

          if (policyResult.blocked) {
            anyBlocked = true;
          }
          if (policyResult.redacted) {
            anyRedacted = true;
          }
        }
      } catch (error) {
        results.push({
          engine: engineName,
          triggered: false,
          action: 'allow',
          blocked: false,
          redacted: false,
          severity: 'info',
          details: {
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });
      }
    }

    const triggeredEngines = results.filter((r) => r.triggered).map((r) => r.engine);
    const blockedEngines = results.filter((r) => r.blocked).map((r) => r.engine);

    const result: PolicyEvaluationResultSet = {
      results,
      anyTriggered,
      anyBlocked,
      anyRedacted,
      highestSeverity,
      finalAction,
      summary: anyBlocked
        ? `Blocked by ${blockedEngines.join(', ')}`
        : anyTriggered
          ? `Alerts from ${triggeredEngines.join(', ')}`
          : 'All pattern policies passed',
    };

    // Cache the result
    if (!options?.skipCache) {
      this.cache.set(cacheKey, result);
    }

    return result;
  }

  /**
   * Evaluate content against statistical policies only
   * Use this for behavioral analysis with session state
   */
  evaluateStatistical(
    input: PolicyEvaluationInput,
    sessionState: SessionState,
  ): PolicyEvaluationResultSet {
    const { content, context } = input;

    const detectionContext: DetectionContext = {
      agentId: context?.agentId,
      sessionId: context?.sessionId,
      actionType: context?.actionType,
      toolName: context?.toolName,
      direction: context?.direction,
      source: context?.source,
    };

    const results: PolicyEvaluationResult[] = [];
    let anyTriggered = false;
    let anyBlocked = false;
    let anyRedacted = false;
    let highestSeverity: Severity = 'info';
    let finalAction: PolicyAction = 'allow';

    // Only run statistical detection engines
    for (const [engineName, engine] of Object.entries(statisticalEngines)) {
      const policy = this.policies[engineName];
      if (!policy || !policy.enabled) {
        continue;
      }

      try {
        const detectionConfig = policyToDetectionConfig(policy);
        const detectionResult = engine.check(
          content,
          detectionContext,
          detectionConfig,
          sessionState,
        );

        const policyResult = evaluatePolicy(engineName, detectionResult, policy);
        results.push(policyResult);

        if (policyResult.triggered) {
          anyTriggered = true;
          highestSeverity = maxSeverity(highestSeverity, policyResult.severity);
          finalAction = maxAction(finalAction, policyResult.action);

          if (policyResult.blocked) {
            anyBlocked = true;
          }
          if (policyResult.redacted) {
            anyRedacted = true;
          }
        }
      } catch (error) {
        results.push({
          engine: engineName,
          triggered: false,
          action: 'allow',
          blocked: false,
          redacted: false,
          severity: 'info',
          details: {
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });
      }
    }

    const triggeredEngines = results.filter((r) => r.triggered).map((r) => r.engine);
    const blockedEngines = results.filter((r) => r.blocked).map((r) => r.engine);

    return {
      results,
      anyTriggered,
      anyBlocked,
      anyRedacted,
      highestSeverity,
      finalAction,
      summary: anyBlocked
        ? `Blocked by ${blockedEngines.join(', ')}`
        : anyTriggered
          ? `Alerts from ${triggeredEngines.join(', ')}`
          : 'All statistical policies passed',
    };
  }

  /**
   * Quick check - does content trigger any blocking policies?
   */
  shouldBlock(content: string, context?: PolicyEvaluationInput['context']): boolean {
    const result = this.evaluatePatterns({ content, context });
    return result.anyBlocked;
  }

  /**
   * Quick check - does content trigger any policies?
   */
  triggers(content: string, context?: PolicyEvaluationInput['context']): boolean {
    const result = this.evaluatePatterns({ content, context });
    return result.anyTriggered;
  }

  /**
   * Get list of triggered policy names
   */
  getTriggeredPolicies(
    content: string,
    context?: PolicyEvaluationInput['context'],
  ): string[] {
    const result = this.evaluatePatterns({ content, context });
    return result.results.filter((r) => r.triggered).map((r) => r.engine);
  }
}

/**
 * Default policy engine instance
 */
export const policyEngine = new PolicyEngine();

/**
 * Quick evaluation function using default policies
 */
export function evaluateContent(
  content: string,
  context?: PolicyEvaluationInput['context'],
  sessionState?: SessionState,
): PolicyEvaluationResultSet {
  return policyEngine.evaluate({ content, context }, sessionState);
}

/**
 * Quick pattern check using default policies
 */
export function checkPatterns(
  content: string,
  context?: PolicyEvaluationInput['context'],
): PolicyEvaluationResultSet {
  return policyEngine.evaluatePatterns({ content, context });
}

/**
 * Quick statistical check using default policies
 */
export function checkStatistical(
  content: string,
  context: PolicyEvaluationInput['context'],
  sessionState: SessionState,
): PolicyEvaluationResultSet {
  return policyEngine.evaluateStatistical({ content, context }, sessionState);
}

/**
 * Quick block check using default policies
 */
export function shouldBlock(
  content: string,
  context?: PolicyEvaluationInput['context'],
): boolean {
  return policyEngine.shouldBlock(content, context);
}
