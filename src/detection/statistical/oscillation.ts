/**
 * Oscillation - Detect flip-flopping agent behavior (A → B → A → B patterns)
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  SessionState,
} from '../types.js';

export class OscillationDetector implements DetectionEngine {
  name = 'oscillation';

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

    const windowSize = (config.windowSize as number | undefined) || 20;
    const cycleThreshold = (config.cycleThreshold as number | undefined) || 3;

    if (!sessionState || sessionState.recentActions.length < 4) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'Insufficient action history for oscillation detection' },
      };
    }

    const recentActions = sessionState.recentActions.slice(-windowSize);

    // Count alternations (A → B → A → B pattern)
    let oscillations = 0;
    for (let i = 0; i < recentActions.length - 3; i++) {
      if (
        recentActions[i] === recentActions[i + 2] &&
        recentActions[i + 1] === recentActions[i + 3] &&
        recentActions[i] !== recentActions[i + 1]
      ) {
        oscillations++;
      }
    }

    const triggered = oscillations >= cycleThreshold;

    // Find the oscillating pattern
    let pattern: string | undefined;
    if (triggered && recentActions.length >= 4) {
      for (let i = recentActions.length - 4; i >= 0; i--) {
        if (
          recentActions[i] === recentActions[i + 2] &&
          recentActions[i + 1] === recentActions[i + 3] &&
          recentActions[i] !== recentActions[i + 1]
        ) {
          pattern = `${recentActions[i]} ↔ ${recentActions[i + 1]}`;
          break;
        }
      }
    }

    return {
      engine: this.name,
      triggered,
      blocked: triggered,
      severity: triggered ? 'warning' : 'info',
      confidence: triggered ? 0.85 : 0,
      details: {
        oscillationCount: oscillations,
        threshold: cycleThreshold,
        windowSize,
        recentActions: recentActions.slice(-8), // Show last 8 for context
        pattern,
      },
      message: triggered
        ? `Oscillation detected: ${oscillations} cycles of ${pattern || 'alternating actions'} in last ${windowSize} requests`
        : undefined,
    };
  }
}

export const oscillationDetector = new OscillationDetector();
