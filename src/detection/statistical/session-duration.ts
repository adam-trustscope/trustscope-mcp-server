/**
 * Session Duration - Detect excessively long sessions
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  SessionState,
} from '../types.js';

export class SessionDurationDetector implements DetectionEngine {
  name = 'session_duration';

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

    const maxHours = (config.maxHours as number | undefined) || 4;

    if (!sessionState) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'No session state' },
      };
    }

    const durationMs = Date.now() - sessionState.startTime;
    const durationHours = durationMs / (1000 * 60 * 60);
    const maxMs = maxHours * 60 * 60 * 1000;

    const triggered = durationMs >= maxMs;
    const warningThreshold = maxMs * 0.8;
    const isWarning = durationMs >= warningThreshold && !triggered;

    return {
      engine: this.name,
      triggered,
      blocked: triggered,
      severity: triggered ? 'warning' : isWarning ? 'info' : 'info',
      confidence: triggered ? 1.0 : 0,
      details: {
        durationHours: durationHours.toFixed(2),
        durationMinutes: Math.round(durationMs / 60000),
        maxHours,
        percentUsed: Math.round((durationHours / maxHours) * 100),
        startTime: new Date(sessionState.startTime).toISOString(),
      },
      message: triggered
        ? `Session duration exceeded: ${durationHours.toFixed(1)} hours (max: ${maxHours} hours)`
        : undefined,
    };
  }
}

export const sessionDurationDetector = new SessionDurationDetector();
