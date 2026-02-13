/**
 * Budget Caps - Enforce cost limits per session/day/month
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  SessionState,
} from '../types.js';

export class BudgetCapsDetector implements DetectionEngine {
  name = 'budget_caps';

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

    const maxPerSession = (config.maxPerSession as number | undefined) || 10.0;
    const maxPerDay = (config.maxPerDay as number | undefined);
    const maxPerMonth = (config.maxPerMonth as number | undefined);

    if (!sessionState) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'No session state' },
      };
    }

    const violations: Array<{ type: string; current: number; limit: number }> = [];

    // Check session limit
    if (sessionState.totalCost >= maxPerSession) {
      violations.push({
        type: 'session',
        current: sessionState.totalCost,
        limit: maxPerSession,
      });
    }

    // Note: Daily and monthly limits would require persistent storage
    // For now, we only enforce session limits in local mode

    const triggered = violations.length > 0;
    const severity = triggered ? (sessionState.totalCost >= maxPerSession * 0.9 ? 'critical' : 'high') : 'info';

    return {
      engine: this.name,
      triggered,
      blocked: triggered,
      severity,
      confidence: triggered ? 1.0 : 0,
      details: {
        totalCost: sessionState.totalCost.toFixed(4),
        sessionLimit: maxPerSession,
        percentUsed: Math.round((sessionState.totalCost / maxPerSession) * 100),
        violations,
        dailyLimit: maxPerDay,
        monthlyLimit: maxPerMonth,
      },
      message: triggered
        ? `Budget exceeded: $${sessionState.totalCost.toFixed(2)} / $${maxPerSession.toFixed(2)} session limit`
        : undefined,
    };
  }
}

export const budgetCapsDetector = new BudgetCapsDetector();
