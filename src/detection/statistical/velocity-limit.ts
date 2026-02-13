/**
 * Velocity Limit - Detect excessive request rate
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  SessionState,
} from '../types.js';

export class VelocityLimitDetector implements DetectionEngine {
  name = 'velocity_limit';

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

    const maxCallsPerMinute = (config.maxCallsPerMinute as number | undefined) || 100;

    if (!sessionState) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'No session state' },
      };
    }

    const now = Date.now();
    const oneMinuteAgo = now - 60 * 1000;

    // Count requests in last minute
    const recentCount = sessionState.requestHashes.filter((h) => h.timestamp > oneMinuteAgo).length;

    const triggered = recentCount >= maxCallsPerMinute;

    return {
      engine: this.name,
      triggered,
      blocked: false, // Alert only by default
      severity: triggered ? 'warning' : 'info',
      confidence: triggered ? 1.0 : 0,
      details: {
        requestsPerMinute: recentCount,
        limit: maxCallsPerMinute,
        percentOfLimit: Math.round((recentCount / maxCallsPerMinute) * 100),
      },
      message: triggered
        ? `Velocity limit: ${recentCount}/${maxCallsPerMinute} requests/min`
        : undefined,
    };
  }
}

export const velocityLimitDetector = new VelocityLimitDetector();
