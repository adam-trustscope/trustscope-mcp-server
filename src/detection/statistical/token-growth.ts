/**
 * Token Growth - Detect exponential output token growth
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  SessionState,
} from '../types.js';

export class TokenGrowthDetector implements DetectionEngine {
  name = 'token_growth';

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

    const alertThresholdPercent = (config.alertThresholdPercent as number | undefined) || 50;
    const windowSize = (config.windowSize as number | undefined) || 3;

    if (!sessionState || sessionState.tokenCounts.length < windowSize) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'Insufficient data for token growth analysis' },
      };
    }

    const recentTokens = sessionState.tokenCounts.slice(-windowSize);

    // Calculate growth rates between consecutive requests
    const growthRates: number[] = [];
    for (let i = 1; i < recentTokens.length; i++) {
      const prev = recentTokens[i - 1];
      const curr = recentTokens[i];
      if (prev > 0) {
        const growth = ((curr - prev) / prev) * 100;
        growthRates.push(growth);
      }
    }

    // Check if all growth rates exceed threshold (exponential growth)
    const avgGrowth = growthRates.length > 0
      ? growthRates.reduce((a, b) => a + b, 0) / growthRates.length
      : 0;

    const triggered = avgGrowth >= alertThresholdPercent;

    return {
      engine: this.name,
      triggered,
      blocked: false, // Alert only by default
      severity: triggered ? 'warning' : 'info',
      confidence: triggered ? 0.8 : 0,
      details: {
        recentTokenCounts: recentTokens,
        growthRates: growthRates.map((r) => r.toFixed(1) + '%'),
        averageGrowth: avgGrowth.toFixed(1) + '%',
        threshold: alertThresholdPercent + '%',
        windowSize,
      },
      message: triggered
        ? `Token growth alert: ${avgGrowth.toFixed(0)}% average growth (threshold: ${alertThresholdPercent}%)`
        : undefined,
    };
  }
}

export const tokenGrowthDetector = new TokenGrowthDetector();
