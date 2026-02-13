/**
 * Error Rate - Detect high error response rate
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  SessionState,
} from '../types.js';

export class ErrorRateDetector implements DetectionEngine {
  name = 'error_rate';

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

    const alertThresholdPercent = (config.alertThresholdPercent as number | undefined) || 30;
    const windowSize = (config.windowSize as number | undefined) || 10;

    if (!sessionState || sessionState.actionCount < windowSize) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'Insufficient data for error rate analysis' },
      };
    }

    // Calculate error rate
    const totalActions = sessionState.actionCount;
    const errorCount = sessionState.errorCount;
    const errorRate = (errorCount / totalActions) * 100;

    const triggered = errorRate >= alertThresholdPercent;

    return {
      engine: this.name,
      triggered,
      blocked: false, // Alert only by default
      severity: triggered ? 'warning' : 'info',
      confidence: triggered ? 0.85 : 0,
      details: {
        errorRate: errorRate.toFixed(1) + '%',
        errorCount,
        totalActions,
        threshold: alertThresholdPercent + '%',
        windowSize,
      },
      message: triggered
        ? `Error rate alert: ${errorRate.toFixed(0)}% errors (threshold: ${alertThresholdPercent}%)`
        : undefined,
    };
  }
}

export const errorRateDetector = new ErrorRateDetector();
