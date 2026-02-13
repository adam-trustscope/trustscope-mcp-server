/**
 * Context Expansion - Detect rapid input context growth
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  SessionState,
} from '../types.js';

export class ContextExpansionDetector implements DetectionEngine {
  name = 'context_expansion';

  check(
    content: string,
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
    const maxTokens = (config.maxTokens as number | undefined) || 50000;

    // Estimate current token count (rough: ~4 chars per token)
    const currentTokens = Math.ceil(content.length / 4);

    // Check absolute limit
    if (currentTokens >= maxTokens) {
      return {
        engine: this.name,
        triggered: true,
        blocked: true,
        severity: 'critical',
        confidence: 1.0,
        details: {
          currentTokens,
          maxTokens,
          reason: 'Maximum context size exceeded',
        },
        message: `Context limit exceeded: ~${currentTokens.toLocaleString()} tokens (max: ${maxTokens.toLocaleString()})`,
      };
    }

    if (!sessionState || sessionState.contextSizes.length < 2) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: {
          currentTokens,
          maxTokens,
          percentUsed: Math.round((currentTokens / maxTokens) * 100),
        },
      };
    }

    const recentContexts = sessionState.contextSizes.slice(-3);
    const prevContext = recentContexts[recentContexts.length - 2];

    // Calculate growth rate
    const growthRate = prevContext > 0 ? ((currentTokens - prevContext) / prevContext) * 100 : 0;

    const triggered = growthRate >= alertThresholdPercent;

    return {
      engine: this.name,
      triggered,
      blocked: false, // Alert only by default
      severity: triggered ? 'warning' : 'info',
      confidence: triggered ? 0.8 : 0,
      details: {
        currentTokens,
        previousTokens: prevContext,
        growthRate: growthRate.toFixed(1) + '%',
        threshold: alertThresholdPercent + '%',
        maxTokens,
        percentUsed: Math.round((currentTokens / maxTokens) * 100),
      },
      message: triggered
        ? `Context expansion: ${growthRate.toFixed(0)}% growth (threshold: ${alertThresholdPercent}%)`
        : undefined,
    };
  }
}

export const contextExpansionDetector = new ContextExpansionDetector();
