/**
 * Jailbreak Detector - Detect known jailbreak attempts
 *
 * Categories:
 * - DAN Variants (DAN, STAN, DUDE, AIM, etc.)
 * - Persona Exploits
 * - Token Smuggling
 * - Emotional Manipulation
 * - Fiction Framing
 * - Obfuscation
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  JailbreakMatch,
  JailbreakCategory,
} from '../types.js';

interface JailbreakPattern {
  pattern: RegExp;
  confidence: number;
  knownJailbreak?: string;
}

const JAILBREAK_PATTERNS: Record<JailbreakCategory, Record<string, JailbreakPattern>> = {
  dan_variants: {
    dan_explicit: {
      pattern: /\bDAN\b(?:\s+(?:mode|version|v\d+|prompt))?/gi,
      confidence: 0.90,
      knownJailbreak: 'DAN (Do Anything Now)',
    },
    do_anything_now: {
      pattern: /do\s+anything\s+now/gi,
      confidence: 0.95,
      knownJailbreak: 'DAN',
    },
    stan: {
      pattern: /\bSTAN\b(?:\s+(?:mode|prompt))?/gi,
      confidence: 0.85,
      knownJailbreak: 'STAN (Strive To Avoid Norms)',
    },
    dude: {
      pattern: /\bDUDE\b(?:\s+(?:mode|prompt))?/gi,
      confidence: 0.80,
      knownJailbreak: 'DUDE',
    },
    aim: {
      pattern: /\bAIM\b(?:\s+(?:mode|machiavelli))?/gi,
      confidence: 0.75,
      knownJailbreak: 'AIM (Always Intelligent Machiavellian)',
    },
    jailbroken: {
      pattern: /jailbroken?\s+(?:mode|version|ai|assistant)/gi,
      confidence: 0.90,
    },
    omega: {
      pattern: /\bOMEGA\b(?:\s+(?:mode|prompt|ai))?/gi,
      confidence: 0.80,
      knownJailbreak: 'OMEGA',
    },
    maximum: {
      pattern: /maximum\s+(?:mode|output|power)/gi,
      confidence: 0.75,
      knownJailbreak: 'Maximum',
    },
    developer_mode_chatgpt: {
      pattern: /chatgpt\s+(?:with\s+)?developer\s+mode/gi,
      confidence: 0.90,
      knownJailbreak: 'Developer Mode',
    },
  },

  persona_exploits: {
    evil_variant: {
      pattern: /(?:your\s+)?evil\s+(?:twin|version|mode|alter\s*ego|self)/gi,
      confidence: 0.85,
    },
    opposite_day: {
      pattern: /opposite\s+(?:day|mode)|(?:it'?s|today\s+is)\s+opposite\s+day/gi,
      confidence: 0.80,
    },
    uncensored: {
      pattern: /(?:un)?censored\s+(?:mode|version|ai)/gi,
      confidence: 0.85,
    },
    unrestricted: {
      pattern: /unrestricted\s+(?:mode|version|ai|access)/gi,
      confidence: 0.85,
    },
    unfiltered: {
      pattern: /unfiltered\s+(?:mode|version|ai|responses?)/gi,
      confidence: 0.85,
    },
    no_ethics: {
      pattern: /(?:no|without|disable)\s+(?:ethics|morals?|restrictions?|limitations?|guidelines?)/gi,
      confidence: 0.80,
    },
    without_safety: {
      pattern: /(?:without|no|disable)\s+(?:safety|content)\s+(?:filters?|guidelines?|restrictions?)/gi,
      confidence: 0.90,
    },
    shadow_self: {
      pattern: /(?:your\s+)?shadow\s+(?:self|version|mode)/gi,
      confidence: 0.75,
    },
  },

  token_smuggling: {
    jailbreak_tag: {
      pattern: /\[\/?(jailbreak|unlock|bypass)\]/gi,
      confidence: 0.90,
    },
    slash_command: {
      pattern: /^\/(?:jailbreak|unlock|bypass|override|sudo)(?:\s|$)/gim,
      confidence: 0.85,
    },
    hash_tag: {
      pattern: /#(?:jailbreak|unlock|bypass|DAN)/gi,
      confidence: 0.80,
    },
    magic_word: {
      pattern: /(?:the\s+)?(?:magic|secret|special)\s+(?:word|phrase|code)\s+(?:is|:)\s*['"]?\w+['"]?/gi,
      confidence: 0.70,
    },
    token_injection: {
      pattern: /inject(?:ing)?\s+(?:token|prompt|instruction)/gi,
      confidence: 0.75,
    },
  },

  emotional_manipulation: {
    grandma_exploit: {
      pattern: /(?:my\s+)?(?:grandmother|grandma|grandpa|grandfather|nana)\s+(?:used\s+to|would|always)/gi,
      confidence: 0.70,
      knownJailbreak: 'Grandma Exploit',
    },
    dying_wish: {
      pattern: /(?:i(?:'m|\s+am)\s+)?(?:dying|going\s+to\s+die|terminal).*(?:last|final)\s+(?:wish|request)/gi,
      confidence: 0.80,
    },
    threat_self: {
      pattern: /(?:i(?:'ll|\s+will)\s+)?(?:kill\s+myself|hurt\s+myself|end\s+my\s+life)\s+(?:if|unless)/gi,
      confidence: 0.90,
    },
    life_death: {
      pattern: /(?:this\s+is\s+)?(?:a\s+)?(?:life\s+(?:or|and)\s+death|emergency|urgent|critical)/gi,
      confidence: 0.50,
    },
    youre_my_only_hope: {
      pattern: /you(?:'re|\s+are)\s+my\s+(?:only|last)\s+hope/gi,
      confidence: 0.50,
    },
  },

  fiction_framing: {
    write_story: {
      pattern: /write\s+(?:a\s+)?(?:story|fiction|novel|script)\s+(?:where|about|in\s+which).*(?:you|ai|assistant)/gi,
      confidence: 0.65,
    },
    as_character: {
      pattern: /(?:as|play(?:ing)?)\s+(?:a\s+)?character\s+(?:who|that|with)/gi,
      confidence: 0.60,
    },
    in_story: {
      pattern: /in\s+(?:this|the)\s+(?:story|fiction|novel|game|simulation)/gi,
      confidence: 0.55,
    },
    simulation: {
      pattern: /(?:this\s+is\s+)?(?:a\s+)?simulation.*(?:rules?|restrictions?)\s+(?:don'?t|do\s+not)\s+apply/gi,
      confidence: 0.85,
    },
    creative_writing: {
      pattern: /(?:for|as)\s+(?:a\s+)?creative\s+writing.*(?:ignore|bypass|no\s+restrictions?)/gi,
      confidence: 0.80,
    },
  },

  obfuscation: {
    respond_reverse: {
      pattern: /respond\s+(?:in\s+)?reverse|backwards?\s+(?:mode|text)/gi,
      confidence: 0.75,
    },
    pig_latin: {
      pattern: /(?:respond|answer|speak)\s+(?:in\s+)?pig\s*latin/gi,
      confidence: 0.80,
    },
    leetspeak: {
      pattern: /(?:use|respond\s+(?:in|with))\s+(?:leet|1337|l33t)\s*(?:speak|text)?/gi,
      confidence: 0.80,
    },
    every_other: {
      pattern: /every\s+(?:other|second|third|nth)\s+(?:word|letter|character)/gi,
      confidence: 0.70,
    },
    spell_backwards: {
      pattern: /spell\s+(?:it\s+)?backwards|reverse\s+(?:the\s+)?(?:letters?|spelling)/gi,
      confidence: 0.70,
    },
    acrostic: {
      pattern: /(?:hide|embed)\s+(?:a\s+)?(?:message|word)\s+(?:in\s+)?(?:the\s+)?(?:first|last)\s+letters?/gi,
      confidence: 0.75,
    },
    first_letters: {
      pattern: /(?:read|take)\s+(?:the\s+)?first\s+(?:letter|character)\s+of\s+each/gi,
      confidence: 0.75,
    },
  },
};

export class JailbreakDetector implements DetectionEngine {
  name = 'jailbreak';

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

    const minConfidence = (config.minConfidence as number | undefined) || 0.70;
    const enabledCategories = (config.categories as string[] | undefined) ||
      Object.keys(JAILBREAK_PATTERNS) as JailbreakCategory[];

    const matches: JailbreakMatch[] = [];
    let highestConfidence = 0;

    for (const category of enabledCategories) {
      const categoryPatterns = JAILBREAK_PATTERNS[category as JailbreakCategory];
      if (!categoryPatterns) continue;

      for (const [patternName, patternConfig] of Object.entries(categoryPatterns)) {
        if (patternConfig.confidence < minConfidence) continue;

        patternConfig.pattern.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = patternConfig.pattern.exec(content)) !== null) {
          matches.push({
            patternName,
            jailbreakCategory: category as JailbreakCategory,
            matchedText: match[0].slice(0, 100),
            start: match.index,
            end: match.index + match[0].length,
            confidence: patternConfig.confidence,
            knownJailbreak: patternConfig.knownJailbreak,
            category,
          });

          highestConfidence = Math.max(highestConfidence, patternConfig.confidence);
        }
      }
    }

    // Deduplicate overlapping matches
    const deduped = this.deduplicateMatches(matches);

    const triggered = deduped.length > 0;
    const knownJailbreaks = [...new Set(deduped.filter((m) => m.knownJailbreak).map((m) => m.knownJailbreak))];
    const categoriesFound = [...new Set(deduped.map((m) => m.jailbreakCategory))];

    let message = `Detected ${deduped.length} jailbreak attempt(s)`;
    if (knownJailbreaks.length > 0) {
      message += ` including known jailbreaks: ${knownJailbreaks.join(', ')}`;
    }

    return {
      engine: this.name,
      triggered,
      blocked: triggered && highestConfidence >= 0.85,
      severity: highestConfidence >= 0.9 ? 'critical' : highestConfidence >= 0.8 ? 'high' : 'warning',
      confidence: highestConfidence,
      details: {
        matches: deduped.map((m) => ({
          category: m.jailbreakCategory,
          pattern: m.patternName,
          text: m.matchedText,
          confidence: m.confidence,
          knownJailbreak: m.knownJailbreak,
        })),
        matchCount: deduped.length,
        categoriesFound,
        knownJailbreaks,
        highestConfidence,
      },
      message: triggered ? message : undefined,
    };
  }

  private deduplicateMatches(matches: JailbreakMatch[]): JailbreakMatch[] {
    if (matches.length <= 1) return matches;

    const sorted = [...matches].sort((a, b) => a.start - b.start || b.confidence - a.confidence);
    const result: JailbreakMatch[] = [];
    let lastEnd = -1;

    for (const match of sorted) {
      if (match.start >= lastEnd) {
        result.push(match);
        lastEnd = match.end;
      }
    }

    return result;
  }
}

export const jailbreakDetector = new JailbreakDetector();
