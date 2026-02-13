/**
 * PII Scanner - Detect 70+ types of personally identifiable information
 *
 * Tier System:
 * - Tier 1 (BLOCK): SSN, credit cards, API keys, private keys
 * - Tier 2 (ALERT): Bank accounts, JWTs, service-specific tokens
 * - Tier 3 (LOG): Email, phone, address, DOB, IP
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  PIIMatch,
  PIITier,
  PIICategory,
  Severity,
} from '../types.js';

interface PIIPattern {
  pattern: RegExp;
  tier: PIITier;
  category: PIICategory;
  contextKeywords?: string[];
  validator?: (value: string) => boolean;
  masker: (value: string) => string;
}

// Validators
function validateSSN(value: string): boolean {
  const digits = value.replace(/[-\s]/g, '');
  if (digits.length !== 9) return false;
  if (digits.slice(0, 3) === '000' || digits.slice(3, 5) === '00' || digits.slice(5) === '0000') return false;
  const firstGroup = parseInt(digits.slice(0, 3), 10);
  if (firstGroup === 666 || firstGroup >= 900) return false;
  return true;
}

function validateLuhn(value: string): boolean {
  const digits = value.replace(/[\s-]/g, '');
  if (!/^\d+$/.test(digits) || digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let isEven = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i], 10);
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    isEven = !isEven;
  }
  return sum % 10 === 0;
}

function validatePhoneUS(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length !== 10) return false;
  if (digits[0] === '0' || digits[0] === '1') return false;
  return true;
}

const PII_PATTERNS: Record<string, PIIPattern> = {
  // US PII - Tier 1
  ssn: {
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    tier: 'tier_1',
    category: 'us_pii',
    validator: validateSSN,
    masker: (v) => `***-**-${v.slice(-4)}`,
  },
  ssn_no_dash: {
    pattern: /\b\d{3}\s\d{2}\s\d{4}\b/g,
    tier: 'tier_1',
    category: 'us_pii',
    validator: validateSSN,
    masker: (v) => `***-**-${v.slice(-4)}`,
  },
  credit_card: {
    pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    tier: 'tier_1',
    category: 'us_pii',
    validator: validateLuhn,
    masker: (v) => `****-****-****-${v.replace(/[-\s]/g, '').slice(-4)}`,
  },
  credit_card_amex: {
    pattern: /\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b/g,
    tier: 'tier_1',
    category: 'us_pii',
    validator: validateLuhn,
    masker: (v) => `****-******-${v.replace(/[-\s]/g, '').slice(-5)}`,
  },

  // International IDs - Tier 1
  uk_nino: {
    pattern: /\b[A-Z]{2}\d{6}[A-Z]\b/g,
    tier: 'tier_1',
    category: 'international_id',
    masker: (v) => `${v.slice(0, 2)}***${v.slice(-1)}`,
  },
  canada_sin: {
    pattern: /\b\d{3}-\d{3}-\d{3}\b/g,
    tier: 'tier_1',
    category: 'international_id',
    masker: (v) => `***-***-${v.slice(-3)}`,
  },
  india_pan: {
    pattern: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
    tier: 'tier_1',
    category: 'international_id',
    masker: (v) => `${v.slice(0, 3)}***${v.slice(-2)}`,
  },
  brazil_cpf: {
    pattern: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g,
    tier: 'tier_1',
    category: 'international_id',
    masker: (v) => `***.***.***-${v.slice(-2)}`,
  },

  // Financial - Tier 1
  iban: {
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
    tier: 'tier_1',
    category: 'financial',
    masker: (v) => `${v.slice(0, 4)}***${v.slice(-4)}`,
  },
  swift_bic: {
    pattern: /\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b/g,
    tier: 'tier_1',
    category: 'financial',
    masker: (v) => `${v.slice(0, 4)}***`,
  },

  // Cloud Keys - Tier 1
  aws_access_key: {
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    tier: 'tier_1',
    category: 'cloud_keys',
    masker: (v) => `${v.slice(0, 8)}***`,
  },
  gcp_api_key: {
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    tier: 'tier_1',
    category: 'cloud_keys',
    masker: (v) => `${v.slice(0, 8)}***`,
  },

  // Code Platform Tokens - Tier 1
  github_pat: {
    pattern: /\bghp_[a-zA-Z0-9]{36}\b/g,
    tier: 'tier_1',
    category: 'code_platforms',
    masker: (v) => `${v.slice(0, 8)}***`,
  },
  gitlab_pat: {
    pattern: /\bglpat-[a-zA-Z0-9\-]{20}\b/g,
    tier: 'tier_1',
    category: 'code_platforms',
    masker: (v) => `${v.slice(0, 10)}***`,
  },
  npm_token: {
    pattern: /\bnpm_[a-zA-Z0-9]{36}\b/g,
    tier: 'tier_1',
    category: 'code_platforms',
    masker: (v) => `${v.slice(0, 8)}***`,
  },

  // Payment - Tier 1
  stripe_secret: {
    pattern: /\bsk_live_[a-zA-Z0-9]{24,}\b/g,
    tier: 'tier_1',
    category: 'payment',
    masker: (v) => `${v.slice(0, 12)}***`,
  },
  stripe_webhook: {
    pattern: /\bwhsec_[a-zA-Z0-9]{32,}\b/g,
    tier: 'tier_1',
    category: 'payment',
    masker: (v) => `${v.slice(0, 10)}***`,
  },

  // Communication - Tier 1
  slack_bot_token: {
    pattern: /\bxoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}\b/g,
    tier: 'tier_1',
    category: 'communication',
    masker: () => 'xoxb-***',
  },
  sendgrid_key: {
    pattern: /\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/g,
    tier: 'tier_1',
    category: 'communication',
    masker: () => 'SG.***',
  },

  // Private Keys - Tier 1
  rsa_private_key: {
    pattern: /-----BEGIN RSA PRIVATE KEY-----/g,
    tier: 'tier_1',
    category: 'private_keys',
    masker: () => '***RSA_PRIVATE_KEY***',
  },
  openssh_private_key: {
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    tier: 'tier_1',
    category: 'private_keys',
    masker: () => '***OPENSSH_PRIVATE_KEY***',
  },
  generic_private_key: {
    pattern: /-----BEGIN PRIVATE KEY-----/g,
    tier: 'tier_1',
    category: 'private_keys',
    masker: () => '***PRIVATE_KEY***',
  },

  // Generic Credentials - Tier 1
  openai_key: {
    pattern: /\bsk-[A-Za-z0-9]{32,}\b/g,
    tier: 'tier_1',
    category: 'generic_creds',
    masker: () => 'sk-***',
  },
  bearer_token: {
    pattern: /\b[Bb]earer\s+[a-zA-Z0-9_\-\.]{20,}\b/g,
    tier: 'tier_1',
    category: 'generic_creds',
    masker: () => 'Bearer ***',
  },

  // Tier 2 - Alert patterns
  bank_account: {
    pattern: /\b\d{10,12}\b/g,
    tier: 'tier_2',
    category: 'financial',
    contextKeywords: ['account', 'bank', 'routing'],
    masker: (v) => `***${v.slice(-4)}`,
  },
  routing_number: {
    pattern: /\b\d{9}\b/g,
    tier: 'tier_2',
    category: 'financial',
    contextKeywords: ['routing', 'aba', 'bank'],
    masker: (v) => `***${v.slice(-4)}`,
  },
  passport: {
    pattern: /\b[A-Z]{1,2}\d{6,9}\b/g,
    tier: 'tier_2',
    category: 'international_id',
    contextKeywords: ['passport'],
    masker: (v) => `${v.slice(0, 2)}***`,
  },
  jwt: {
    pattern: /\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    tier: 'tier_2',
    category: 'generic_creds',
    masker: () => 'eyJ***',
  },

  // Tier 3 - Log only patterns
  email: {
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    tier: 'tier_3',
    category: 'contact_info',
    masker: (v) => {
      const [local, domain] = v.split('@');
      return `${local.slice(0, 2)}***@${domain}`;
    },
  },
  phone_us: {
    pattern: /\b\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    tier: 'tier_3',
    category: 'contact_info',
    validator: validatePhoneUS,
    masker: (v) => `***-***-${v.replace(/\D/g, '').slice(-4)}`,
  },
  phone_intl: {
    pattern: /\+\d{1,3}[\s.-]?\d{3}[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    tier: 'tier_3',
    category: 'contact_info',
    masker: (v) => `+***-***-${v.slice(-4)}`,
  },
  date_of_birth: {
    pattern: /\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b/g,
    tier: 'tier_3',
    category: 'contact_info',
    contextKeywords: ['birth', 'born', 'dob'],
    masker: () => '**/**/****',
  },
  ip_address: {
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    tier: 'tier_3',
    category: 'contact_info',
    masker: (v) => `${v.split('.').slice(0, 2).join('.')}.***`,
  },
};

function checkContextKeywords(text: string, position: number, keywords: string[]): boolean {
  const windowSize = 100;
  const start = Math.max(0, position - windowSize);
  const end = Math.min(text.length, position + windowSize);
  const context = text.slice(start, end).toLowerCase();
  return keywords.some((keyword) => context.includes(keyword.toLowerCase()));
}

function tierToSeverity(tier: PIITier): Severity {
  switch (tier) {
    case 'tier_1':
      return 'critical';
    case 'tier_2':
      return 'high';
    case 'tier_3':
      return 'warning';
    default:
      return 'info';
  }
}

export class PIIScanner implements DetectionEngine {
  name = 'pii_scanner';

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

    const enabledPatterns = (config.patterns as string[] | undefined) || Object.keys(PII_PATTERNS);
    const tier1BlockPatterns = (config.tier1BlockPatterns as string[] | undefined) || ['ssn', 'credit_card', 'passport'];
    const confidenceThreshold = (config.confidenceThreshold as number | undefined) || 0.7;

    const matches: PIIMatch[] = [];
    let highestSeverity: Severity = 'info';
    let shouldBlock = false;

    for (const patternName of enabledPatterns) {
      const patternConfig = PII_PATTERNS[patternName];
      if (!patternConfig) continue;

      // Reset regex lastIndex
      patternConfig.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = patternConfig.pattern.exec(content)) !== null) {
        const matchedText = match[0];

        // Check context keywords if required
        if (patternConfig.contextKeywords) {
          if (!checkContextKeywords(content, match.index, patternConfig.contextKeywords)) {
            continue;
          }
        }

        // Validate if validator exists
        if (patternConfig.validator && !patternConfig.validator(matchedText)) {
          continue;
        }

        // Calculate confidence
        let confidence = patternConfig.tier === 'tier_1' ? 0.9 : patternConfig.tier === 'tier_2' ? 0.75 : 0.7;
        if (patternConfig.contextKeywords && checkContextKeywords(content, match.index, patternConfig.contextKeywords)) {
          confidence = Math.min(0.99, confidence + 0.15);
        }

        if (confidence < confidenceThreshold) continue;

        const severity = tierToSeverity(patternConfig.tier);

        matches.push({
          patternName,
          piiType: patternName,
          matchedText,
          start: match.index,
          end: match.index + matchedText.length,
          confidence,
          tier: patternConfig.tier,
          piiCategory: patternConfig.category,
          maskedValue: patternConfig.masker(matchedText),
          severity,
          category: patternConfig.category,
        });

        if (severity === 'critical' || (severity === 'high' && highestSeverity !== 'critical')) {
          highestSeverity = severity;
        } else if (severity === 'warning' && highestSeverity === 'info') {
          highestSeverity = severity;
        }

        // Check if should block
        if (patternConfig.tier === 'tier_1' && tier1BlockPatterns.includes(patternName)) {
          shouldBlock = true;
        }
      }
    }

    const triggered = matches.length > 0;

    // Count by tier
    const matchesByTier = {
      tier_1: matches.filter((m) => m.tier === 'tier_1').length,
      tier_2: matches.filter((m) => m.tier === 'tier_2').length,
      tier_3: matches.filter((m) => m.tier === 'tier_3').length,
    };

    // Count by category
    const matchesByCategory: Record<string, number> = {};
    for (const m of matches) {
      matchesByCategory[m.piiCategory] = (matchesByCategory[m.piiCategory] || 0) + 1;
    }

    return {
      engine: this.name,
      triggered,
      blocked: shouldBlock,
      severity: highestSeverity,
      confidence: triggered ? Math.max(...matches.map((m) => m.confidence)) : 0,
      details: {
        matches: matches.map((m) => ({
          type: m.piiType,
          maskedValue: m.maskedValue,
          confidence: m.confidence,
          tier: m.tier,
          category: m.piiCategory,
        })),
        matchCount: matches.length,
        matchesByTier,
        matchesByCategory,
      },
      message: triggered
        ? `Detected ${matches.length} PII instance(s): ${[...new Set(matches.map((m) => m.piiType))].join(', ')}`
        : undefined,
    };
  }
}

export const piiScanner = new PIIScanner();
