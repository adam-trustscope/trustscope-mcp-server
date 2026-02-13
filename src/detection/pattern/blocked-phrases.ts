/**
 * Blocked Phrases - Configurable keyword/phrase blocklist
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  PatternMatch,
} from '../types.js';

export class BlockedPhrasesDetector implements DetectionEngine {
  name = 'blocked_phrases';

  check(
    content: string,
    _context: DetectionContext,
    config: DetectionConfig,
  ): DetectionResult {
    if (!config.enabled || !content) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: {},
      };
    }

    const phrases = (config.phrases as string[] | undefined) || [];
    if (phrases.length === 0) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { reason: 'No blocked phrases configured' },
      };
    }

    const matches: PatternMatch[] = [];
    const contentLower = content.toLowerCase();

    for (const phrase of phrases) {
      const phraseLower = phrase.toLowerCase();
      let index = contentLower.indexOf(phraseLower);

      while (index !== -1) {
        matches.push({
          patternName: phrase,
          matchedText: content.slice(index, index + phrase.length),
          start: index,
          end: index + phrase.length,
          confidence: 1.0,
        });

        index = contentLower.indexOf(phraseLower, index + 1);
      }
    }

    const triggered = matches.length > 0;
    const uniquePhrases = [...new Set(matches.map((m) => m.patternName))];

    return {
      engine: this.name,
      triggered,
      blocked: triggered,
      severity: triggered ? 'high' : 'info',
      confidence: triggered ? 1.0 : 0,
      details: {
        matches: matches.map((m) => ({
          phrase: m.patternName,
          position: m.start,
        })),
        matchCount: matches.length,
        uniquePhrases,
      },
      message: triggered
        ? `Found ${matches.length} blocked phrase(s): ${uniquePhrases.join(', ')}`
        : undefined,
    };
  }
}

export const blockedPhrasesDetector = new BlockedPhrasesDetector();
