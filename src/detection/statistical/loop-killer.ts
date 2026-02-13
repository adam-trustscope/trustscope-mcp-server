/**
 * Loop Killer - Detect identical requests repeating
 *
 * Algorithm: Hash request content, track in session, trigger if count > threshold in window
 */

import { createHash } from 'node:crypto';
import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  SessionState,
} from '../types.js';

export class LoopKillerDetector implements DetectionEngine {
  name = 'loop_killer';

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

    const maxIterations = (config.maxIterations as number | undefined) || 50;
    const windowSeconds = (config.windowSeconds as number | undefined) || 60;

    // Hash the content
    const requestHash = this.hashContent(content);

    if (!sessionState) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { requestHash, reason: 'No session state' },
      };
    }

    const now = Date.now();
    const cutoff = now - windowSeconds * 1000;

    // Get recent hashes within window
    const recentHashes = sessionState.requestHashes.filter((h) => h.timestamp > cutoff);

    // Count identical requests
    const identicalCount = recentHashes.filter((h) => h.hash === requestHash).length;

    const triggered = identicalCount >= maxIterations;

    return {
      engine: this.name,
      triggered,
      blocked: triggered,
      severity: triggered ? 'critical' : 'info',
      confidence: triggered ? 1.0 : 0,
      details: {
        requestHash: requestHash.slice(0, 16),
        identicalCount,
        threshold: maxIterations,
        windowSeconds,
        totalRecentRequests: recentHashes.length,
      },
      message: triggered
        ? `Loop detected: ${identicalCount} identical requests in ${windowSeconds}s (limit: ${maxIterations})`
        : undefined,
    };
  }

  private hashContent(content: string): string {
    const normalized = content.toLowerCase().replace(/\s+/g, ' ').trim();
    return createHash('sha256').update(normalized).digest('hex');
  }
}

export const loopKillerDetector = new LoopKillerDetector();
