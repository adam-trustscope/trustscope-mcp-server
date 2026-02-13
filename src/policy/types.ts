/**
 * Policy Types
 *
 * Defines the structure for policies and their evaluation results.
 */

import type { Severity } from '../detection/types.js';

/**
 * Action to take when a policy triggers
 */
export type PolicyAction = 'allow' | 'alert' | 'block' | 'redact';

/**
 * Policy configuration for a single detection engine
 */
export interface PolicyConfig {
  /** Whether this policy is enabled */
  enabled: boolean;
  /** Action to take when triggered */
  action: PolicyAction;
  /** Override severity (if not specified, uses detection severity) */
  severity?: Severity;
  /** Engine-specific configuration */
  config?: Record<string, unknown>;
  /** Optional description */
  description?: string;
}

/**
 * Complete policy pack configuration
 */
export interface PolicyPack {
  /** Name of this policy pack */
  name: string;
  /** Version */
  version: string;
  /** Description */
  description?: string;
  /** Individual policy configurations keyed by engine name */
  policies: Record<string, PolicyConfig>;
}

/**
 * Result of evaluating a single policy
 */
export interface PolicyEvaluationResult {
  /** Engine name */
  engine: string;
  /** Whether the detection triggered */
  triggered: boolean;
  /** Action taken */
  action: PolicyAction;
  /** Whether the action blocked the request */
  blocked: boolean;
  /** Whether content was redacted */
  redacted: boolean;
  /** Severity level */
  severity: Severity;
  /** Confidence score (0-1) */
  confidence?: number;
  /** Detection details */
  details: Record<string, unknown>;
  /** Human-readable message */
  message?: string;
  /** Redacted version of content if applicable */
  redactedContent?: string;
}

/**
 * Result of evaluating all policies
 */
export interface PolicyEvaluationResultSet {
  /** Individual policy results */
  results: PolicyEvaluationResult[];
  /** Whether any policy was triggered */
  anyTriggered: boolean;
  /** Whether any policy blocked the request */
  anyBlocked: boolean;
  /** Whether any content was redacted */
  anyRedacted: boolean;
  /** Highest severity across all results */
  highestSeverity: Severity;
  /** Final action to take (most restrictive) */
  finalAction: PolicyAction;
  /** Summary message */
  summary: string;
  /** Safe/redacted version of the content */
  safeContent?: string;
}

/**
 * Input for policy evaluation
 */
export interface PolicyEvaluationInput {
  /** Content to evaluate */
  content: string;
  /** Context information */
  context?: {
    agentId?: string;
    sessionId?: string;
    actionType?: string;
    toolName?: string;
    direction?: 'input' | 'output';
    source?: string;
  };
}
