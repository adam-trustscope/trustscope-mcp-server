/**
 * Prompt Injection Detector - Detect attempts to manipulate LLM behavior
 *
 * Categories:
 * - Instruction Override
 * - System Extraction
 * - Role Manipulation
 * - Delimiter Attacks
 * - Encoding Attacks
 * - Hypothetical Framing
 * - Developer Mode
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  InjectionMatch,
  InjectionCategory,
} from '../types.js';

interface InjectionPattern {
  pattern: RegExp;
  confidence: number;
}

const INJECTION_PATTERNS: Record<InjectionCategory, Record<string, InjectionPattern>> = {
  instruction_override: {
    ignore_previous: {
      pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?|directions?)/gi,
      confidence: 0.95,
    },
    disregard: {
      pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier|your)/gi,
      confidence: 0.90,
    },
    forget_instructions: {
      pattern: /forget\s+(all\s+)?(previous|prior|your|everything|all)\s*(instructions?|rules?|prompts?)?/gi,
      confidence: 0.90,
    },
    override: {
      pattern: /override\s+(all\s+)?(previous|system|your|safety)/gi,
      confidence: 0.85,
    },
    new_instructions: {
      pattern: /(new|updated|revised|real)\s+instructions?\s*(are|follow|:)/gi,
      confidence: 0.80,
    },
    stop_being: {
      pattern: /stop\s+being\s+(an?\s+)?(ai|assistant|helpful|safe)/gi,
      confidence: 0.85,
    },
    do_not_follow: {
      pattern: /do\s+not\s+follow\s+(your|the|any)\s+(instructions?|rules?|guidelines?)/gi,
      confidence: 0.90,
    },
    cancel_instructions: {
      pattern: /(cancel|nullify|void|invalidate)\s+(all\s+)?(previous|prior|your)\s+(instructions?|rules?)/gi,
      confidence: 0.90,
    },
  },

  system_extraction: {
    show_system: {
      pattern: /(show|reveal|display|print|output|tell)\s+(me\s+)?(your|the)\s+(system|initial|original|hidden)\s+(prompt|instructions?|message|rules?)/gi,
      confidence: 0.95,
    },
    what_is_system: {
      pattern: /what\s+(are|is|were)\s+(your|the)\s+(system|initial|original|full)\s+(prompt|instructions?|rules?)/gi,
      confidence: 0.90,
    },
    repeat_system: {
      pattern: /repeat\s+(your|the)\s+(system|initial|original|exact)\s+(prompt|instructions?|message)/gi,
      confidence: 0.90,
    },
    beginning_message: {
      pattern: /(repeat|show|print)\s+(the\s+)?beginning\s+(of\s+)?(this\s+)?(conversation|chat|message)/gi,
      confidence: 0.75,
    },
    verbatim: {
      pattern: /(output|print|repeat)\s+(everything\s+)?(verbatim|word\s*for\s*word|exactly)/gi,
      confidence: 0.80,
    },
    leak_prompt: {
      pattern: /(leak|expose|dump|extract)\s+(your|the|system)\s+(prompt|instructions?)/gi,
      confidence: 0.95,
    },
  },

  role_manipulation: {
    you_are_now: {
      pattern: /you\s+are\s+now\s+(a\s+)?[A-Z][A-Za-z]*/gi,
      confidence: 0.70,
    },
    act_as: {
      pattern: /(act|behave|respond|function)\s+as\s+(if\s+)?(you\s+(are|were)\s+)?(a\s+)?/gi,
      confidence: 0.60,
    },
    pretend: {
      pattern: /pretend\s+(that\s+)?(you('?re|\s+are)\s+)?(a\s+)?/gi,
      confidence: 0.65,
    },
    roleplay: {
      pattern: /(roleplay|role-play|role\s+play)\s+(as|that)/gi,
      confidence: 0.70,
    },
    switch_mode: {
      pattern: /switch\s+(to|into)\s+.{1,30}\s+mode/gi,
      confidence: 0.75,
    },
    persona: {
      pattern: /(adopt|assume|take\s+on)\s+(the\s+)?(persona|personality|character|role)\s+of/gi,
      confidence: 0.75,
    },
  },

  delimiter_attack: {
    openai_delimiters: {
      pattern: /<\|(?:system|user|assistant|im_start|im_end|endoftext)\|>/g,
      confidence: 0.95,
    },
    llama_delimiters: {
      pattern: /\[\/?(INST|SYS)\]/g,
      confidence: 0.95,
    },
    markdown_system: {
      pattern: /```(?:system|instruction|prompt)/gi,
      confidence: 0.85,
    },
    hash_delimiters: {
      pattern: /###\s*(System|Instruction|Human|Assistant|User)(\s*:|$)/gi,
      confidence: 0.80,
    },
    xml_injection: {
      pattern: /<(?:system|instruction|prompt|rules?)>/gi,
      confidence: 0.85,
    },
    anthropic_delimiters: {
      pattern: /\\n\\n(?:Human|Assistant):/g,
      confidence: 0.80,
    },
    chat_ml: {
      pattern: /<\|(?:im_start|im_end)\|>/g,
      confidence: 0.90,
    },
  },

  encoding_attack: {
    base64_decode: {
      pattern: /(decode|decrypt|translate|convert)\s+(this|the|following)?\s*(from\s+)?(base64|b64)/gi,
      confidence: 0.80,
    },
    base64_string: {
      pattern: /base64\s*[:=]\s*[A-Za-z0-9+/=]{20,}/gi,
      confidence: 0.75,
    },
    hex_decode: {
      pattern: /(decode|decrypt|translate|convert)\s+(this|the|following)?\s*(from\s+)?hex/gi,
      confidence: 0.75,
    },
    rot13: {
      pattern: /(decode|decrypt|apply)\s+(this|the|following)?\s*(from\s+)?rot13/gi,
      confidence: 0.80,
    },
    unicode_escape: {
      pattern: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}/g,
      confidence: 0.70,
    },
    url_encoded: {
      pattern: /(?:%[0-9a-fA-F]{2}){5,}/g,
      confidence: 0.70,
    },
  },

  hypothetical_framing: {
    hypothetically: {
      pattern: /hypothetically\s+(speaking\s+)?(if|what|how|could)/gi,
      confidence: 0.50,
    },
    fictional: {
      pattern: /in\s+a\s+(fictional|hypothetical|imaginary)\s+(scenario|world|story|setting)/gi,
      confidence: 0.55,
    },
    no_restrictions: {
      pattern: /imagine\s+(you\s+)?(had\s+no|didn'?t\s+have|without)\s+(restrictions?|rules?|limits?|guidelines?)/gi,
      confidence: 0.85,
    },
    educational_purposes: {
      pattern: /for\s+(educational|research|academic|learning)\s+purposes?\s+only/gi,
      confidence: 0.60,
    },
  },

  developer_mode: {
    enable_dev_mode: {
      pattern: /enable\s+(developer|dev|debug|admin|maintenance|god)\s+mode/gi,
      confidence: 0.90,
    },
    dev_mode_on: {
      pattern: /(developer|dev|debug|admin|maintenance|god)\s+mode\s+(on|enabled|activated|engaged)/gi,
      confidence: 0.90,
    },
    sudo: {
      pattern: /sudo\s+mode|sudo\s+enable|enable\s+sudo/gi,
      confidence: 0.85,
    },
    jailbreak_command: {
      pattern: /\/?(jailbreak|unlock|bypass|override)/gi,
      confidence: 0.85,
    },
    secret_code: {
      pattern: /(secret|hidden|special)\s+(code|password|phrase)\s*(is|:)/gi,
      confidence: 0.70,
    },
    admin_access: {
      pattern: /(grant|give|enable)\s+(me\s+)?(admin|root|superuser)\s+(access|privileges?)/gi,
      confidence: 0.85,
    },
  },
};

// Multi-language patterns
const MULTI_LANG_PATTERNS: Record<string, RegExp> = {
  ignore_german: /ignorieren?\s+sie\s+(alle\s+)?(vorherigen?|früheren?)/gi,
  ignore_french: /ignorer?\s+(tous?\s+)?(les\s+)?(précédentes?|instructions?)/gi,
  ignore_spanish: /ignorar?\s+(todas?\s+)?(las\s+)?(instrucciones?|anteriores?)/gi,
  ignore_chinese: /忽略|无视|不理会/g,
  ignore_russian: /игнорир|забудь|пренебреги/gi,
  ignore_japanese: /無視|忘れて|前の指示/g,
  ignore_korean: /무시|이전.*지시/g,
};

export class PromptInjectionDetector implements DetectionEngine {
  name = 'prompt_injection';

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
      Object.keys(INJECTION_PATTERNS) as InjectionCategory[];
    const checkMultiLang = config.checkMultiLang !== false;

    const matches: InjectionMatch[] = [];
    let highestConfidence = 0;

    // Check main patterns
    for (const category of enabledCategories) {
      const categoryPatterns = INJECTION_PATTERNS[category as InjectionCategory];
      if (!categoryPatterns) continue;

      for (const [patternName, patternConfig] of Object.entries(categoryPatterns)) {
        if (patternConfig.confidence < minConfidence) continue;

        patternConfig.pattern.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = patternConfig.pattern.exec(content)) !== null) {
          matches.push({
            patternName,
            injectionCategory: category as InjectionCategory,
            matchedText: match[0].slice(0, 100),
            start: match.index,
            end: match.index + match[0].length,
            confidence: patternConfig.confidence,
            category,
          });

          highestConfidence = Math.max(highestConfidence, patternConfig.confidence);
        }
      }
    }

    // Check multi-language patterns
    if (checkMultiLang) {
      for (const [patternName, pattern] of Object.entries(MULTI_LANG_PATTERNS)) {
        pattern.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          matches.push({
            patternName,
            injectionCategory: 'instruction_override',
            matchedText: match[0].slice(0, 100),
            start: match.index,
            end: match.index + match[0].length,
            confidence: 0.85,
            category: 'instruction_override',
          });

          highestConfidence = Math.max(highestConfidence, 0.85);
        }
      }
    }

    // Deduplicate overlapping matches
    const deduped = this.deduplicateMatches(matches);

    const triggered = deduped.length > 0;
    const categoriesFound = [...new Set(deduped.map((m) => m.injectionCategory))];

    return {
      engine: this.name,
      triggered,
      blocked: triggered && highestConfidence >= 0.85,
      severity: highestConfidence >= 0.9 ? 'critical' : highestConfidence >= 0.8 ? 'high' : 'warning',
      confidence: highestConfidence,
      details: {
        matches: deduped.map((m) => ({
          category: m.injectionCategory,
          pattern: m.patternName,
          text: m.matchedText,
          confidence: m.confidence,
        })),
        matchCount: deduped.length,
        categoriesFound,
        highestConfidence,
      },
      message: triggered
        ? `Detected ${deduped.length} injection attempt(s) in categories: ${categoriesFound.join(', ')}`
        : undefined,
    };
  }

  private deduplicateMatches(matches: InjectionMatch[]): InjectionMatch[] {
    if (matches.length <= 1) return matches;

    const sorted = [...matches].sort((a, b) => a.start - b.start || b.confidence - a.confidence);
    const result: InjectionMatch[] = [];
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

export const promptInjectionDetector = new PromptInjectionDetector();
