/**
 * Session Action Limit - Enforce maximum actions per session
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  SessionState,
} from '../types.js';

export class SessionActionLimitDetector implements DetectionEngine {
  name = 'session_action_limit';

  check(
    _content: string,
    _context: DetectionContext,
    config: DetectionConfig,
    sessionState?: SessionState,
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

    const maxActions = (config.maxActions as number | undefined) || 1000;

    if (!sessionState) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'No session state' },
      };
    }

    const actionCount = sessionState.actionCount;
    const triggered = actionCount >= maxActions;
    const warningThreshold = maxActions * 0.9;
    const isWarning = actionCount >= warningThreshold && !triggered;

    return {
      engine: this.name,
      triggered,
      blocked: triggered,
      severity: triggered ? 'warning' : 'info',
      confidence: triggered ? 1.0 : 0,
      details: {
        actionCount,
        maxActions,
        percentUsed: Math.round((actionCount / maxActions) * 100),
        remaining: Math.max(0, maxActions - actionCount),
      },
      message: triggered
        ? `Session action limit reached: ${actionCount}/${maxActions} actions`
        : isWarning
        ? `Session action warning: ${actionCount}/${maxActions} actions (${Math.round((actionCount / maxActions) * 100)}% used)`
        : undefined,
    };
  }
}

export const sessionActionLimitDetector = new SessionActionLimitDetector();
