/**
 * Cost Velocity - Detect rapid cost accumulation
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  SessionState,
} from '../types.js';

export class CostVelocityDetector implements DetectionEngine {
  name = 'cost_velocity';

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

    const maxPerMinute = (config.maxPerMinute as number | undefined) || 5.0;

    if (!sessionState) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'No session state' },
      };
    }

    // Calculate cost velocity (cost per minute since session start)
    const sessionDurationMinutes = Math.max(1, (Date.now() - sessionState.startTime) / 60000);
    const costPerMinute = sessionState.totalCost / sessionDurationMinutes;

    const triggered = costPerMinute >= maxPerMinute;

    return {
      engine: this.name,
      triggered,
      blocked: false, // Alert only by default
      severity: triggered ? 'warning' : 'info',
      confidence: triggered ? 0.9 : 0,
      details: {
        totalCost: sessionState.totalCost.toFixed(4),
        sessionDurationMinutes: sessionDurationMinutes.toFixed(1),
        costPerMinute: costPerMinute.toFixed(4),
        limitPerMinute: maxPerMinute,
      },
      message: triggered
        ? `Cost velocity alert: $${costPerMinute.toFixed(2)}/min (limit: $${maxPerMinute}/min)`
        : undefined,
    };
  }
}

export const costVelocityDetector = new CostVelocityDetector();
