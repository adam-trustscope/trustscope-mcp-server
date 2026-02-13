/**
 * Action Label Mismatch - Detect when action labels don't match destructive parameters
 *
 * Example: An action labeled "read_file" that contains "rm -rf" in parameters
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
} from '../types.js';

const DEFAULT_DESTRUCTIVE_KEYWORDS = [
  'DELETE',
  'DROP',
  'TRUNCATE',
  'rm',
  'remove',
  'destroy',
  'erase',
  'wipe',
  'purge',
  'kill',
  'terminate',
  'shutdown',
  'halt',
  'force',
  'override',
  // Sprint 3 additions
  'nuke',
  'bypass',
  'disable',
  'revoke',
  'reset',
  'overwrite',
  'invalidate',
  'clear',
  'unset',
  'rollback',
];

// HTTP methods that are destructive (safe methods like GET/HEAD/OPTIONS not used for mismatch detection)
const DESTRUCTIVE_HTTP_METHODS = ['DELETE', 'PUT', 'PATCH', 'POST'];

const SAFE_ACTION_PATTERNS = [
  /^read/i,
  /^get/i,
  /^list/i,
  /^view/i,
  /^show/i,
  /^display/i,
  /^fetch/i,
  /^query/i,
  /^search/i,
  /^find/i,
  /^check/i,
  /^validate/i,
  /^verify/i,
  // Sprint 3 additions
  /^retrieve/i,
  /^calculate/i,
  /^compute/i,
  /^estimate/i,
  /^lookup/i,
  /^inspect/i,
  /^describe/i,
  /^preview/i,
];

export class ActionLabelMismatchDetector implements DetectionEngine {
  name = 'action_label_mismatch';

  check(
    content: string,
    context: DetectionContext,
    config: DetectionConfig,
  ): DetectionResult {
    if (!config.enabled) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: {},
      };
    }

    const destructiveKeywords = (config.destructiveKeywords as string[] | undefined) || DEFAULT_DESTRUCTIVE_KEYWORDS;
    const actionType = context.actionType || context.toolName || '';

    if (!actionType || !content) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'No action type or content provided' },
      };
    }

    // Check if action label looks safe
    const isSafeLabel = SAFE_ACTION_PATTERNS.some((p) => p.test(actionType));

    if (!isSafeLabel) {
      // Action doesn't claim to be safe, so no mismatch possible
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'Action label does not indicate safe operation' },
      };
    }

    // Check for HTTP method mismatch (Sprint 3)
    const httpMethod = (context.metadata?.httpMethod as string)?.toUpperCase();
    const httpMethodMismatch: boolean = !!httpMethod && DESTRUCTIVE_HTTP_METHODS.includes(httpMethod);

    // Check if content contains destructive keywords
    const foundKeywords: string[] = [];

    for (const keyword of destructiveKeywords) {
      // Use word boundary check (case-insensitive)
      const pattern = new RegExp(`\\b${keyword}\\b`, 'i');
      if (pattern.test(content)) {
        foundKeywords.push(keyword);
      }
    }

    const triggered = foundKeywords.length > 0 || httpMethodMismatch;

    // Determine reason for trigger
    let message: string | undefined;
    if (triggered) {
      const reasons: string[] = [];
      if (httpMethodMismatch) {
        reasons.push(`HTTP method ${httpMethod} is destructive`);
      }
      if (foundKeywords.length > 0) {
        reasons.push(`destructive keywords: ${foundKeywords.join(', ')}`);
      }
      message = `Action "${actionType}" claims to be safe but ${reasons.join(' and ')}`;
    }

    return {
      engine: this.name,
      triggered,
      blocked: triggered,
      severity: triggered ? 'critical' : 'info',
      confidence: triggered ? 0.95 : 0,
      details: {
        actionLabel: actionType,
        claimsSafe: true,
        destructiveKeywordsFound: foundKeywords,
        mismatchCount: foundKeywords.length,
        httpMethod: httpMethod || null,
        httpMethodMismatch: httpMethodMismatch || false,
      },
      message,
    };
  }
}

export const actionLabelMismatchDetector = new ActionLabelMismatchDetector();
