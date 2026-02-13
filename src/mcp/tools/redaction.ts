/**
 * Redaction and Guidance Generation
 *
 * Provides utilities for redacting sensitive data and generating
 * actionable guidance for policy violations.
 */

/**
 * Redaction match info
 */
export interface RedactionMatch {
  type: string;
  original: string;
  redacted: string;
  field?: string;
}

/**
 * Redaction result
 */
export interface RedactionResult {
  content: string;
  matches: RedactionMatch[];
  hasRedactions: boolean;
}

/**
 * PII patterns for redaction
 */
const PII_PATTERNS = {
  ssn: {
    pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
    replacement: '[REDACTED-SSN]',
    label: 'SSN',
  },
  creditCard: {
    pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    replacement: '[REDACTED-CC]',
    label: 'Credit Card',
  },
  email: {
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    replacement: '[REDACTED-EMAIL]',
    label: 'Email',
  },
  phone: {
    pattern: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
    replacement: '[REDACTED-PHONE]',
    label: 'Phone',
  },
  ipAddress: {
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    replacement: '[REDACTED-IP]',
    label: 'IP Address',
  },
};

/**
 * Secret patterns for redaction
 */
const SECRET_PATTERNS = {
  apiKey: {
    pattern: /\b(?:api[_-]?key|apikey|api_secret)[=:]\s*['"]?[A-Za-z0-9_-]{20,}['"]?/gi,
    replacement: '[REDACTED-API-KEY]',
    label: 'API Key',
  },
  awsKey: {
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    replacement: '[REDACTED-AWS-KEY]',
    label: 'AWS Access Key',
  },
  awsSecret: {
    pattern: /\b[A-Za-z0-9/+=]{40}\b/g,
    replacement: '[REDACTED-AWS-SECRET]',
    label: 'AWS Secret',
  },
  jwt: {
    pattern: /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    replacement: '[REDACTED-JWT]',
    label: 'JWT Token',
  },
  privateKey: {
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    replacement: '[REDACTED-PRIVATE-KEY]',
    label: 'Private Key',
  },
  password: {
    pattern: /\b(?:password|passwd|pwd)[=:]\s*['"]?[^\s'"]{8,}['"]?/gi,
    replacement: '[REDACTED-PASSWORD]',
    label: 'Password',
  },
};

/**
 * Redact PII from content
 */
export function redactPII(content: string): RedactionResult {
  let result = content;
  const matches: RedactionMatch[] = [];

  for (const [type, config] of Object.entries(PII_PATTERNS)) {
    const found = content.match(config.pattern);
    if (found) {
      for (const original of found) {
        matches.push({
          type: config.label,
          original: original.slice(0, 4) + '***', // Partial mask in log
          redacted: config.replacement,
        });
      }
      result = result.replace(config.pattern, config.replacement);
    }
  }

  return {
    content: result,
    matches,
    hasRedactions: matches.length > 0,
  };
}

/**
 * Redact secrets from content
 */
export function redactSecrets(content: string): RedactionResult {
  let result = content;
  const matches: RedactionMatch[] = [];

  for (const [type, config] of Object.entries(SECRET_PATTERNS)) {
    const found = content.match(config.pattern);
    if (found) {
      for (const original of found) {
        matches.push({
          type: config.label,
          original: original.slice(0, 8) + '***', // Partial mask in log
          redacted: config.replacement,
        });
      }
      result = result.replace(config.pattern, config.replacement);
    }
  }

  return {
    content: result,
    matches,
    hasRedactions: matches.length > 0,
  };
}

/**
 * Redact all sensitive data
 */
export function redactAll(content: string): RedactionResult {
  const piiResult = redactPII(content);
  const secretResult = redactSecrets(piiResult.content);

  return {
    content: secretResult.content,
    matches: [...piiResult.matches, ...secretResult.matches],
    hasRedactions: piiResult.hasRedactions || secretResult.hasRedactions,
  };
}

/**
 * Redact tool arguments
 */
export function redactToolArgs(
  args: Record<string, unknown>,
): { safe_args: Record<string, unknown>; redactions: RedactionMatch[] } {
  const safeArgs: Record<string, unknown> = {};
  const allRedactions: RedactionMatch[] = [];

  for (const [key, value] of Object.entries(args)) {
    if (typeof value === 'string') {
      const result = redactAll(value);
      safeArgs[key] = result.content;
      for (const match of result.matches) {
        allRedactions.push({ ...match, field: key });
      }
    } else if (typeof value === 'object' && value !== null) {
      // Recursively redact nested objects
      const nested = redactToolArgs(value as Record<string, unknown>);
      safeArgs[key] = nested.safe_args;
      allRedactions.push(...nested.redactions.map((r) => ({ ...r, field: `${key}.${r.field || ''}` })));
    } else {
      safeArgs[key] = value;
    }
  }

  return { safe_args: safeArgs, redactions: allRedactions };
}

/**
 * Generate guidance message from detections
 */
export function generateGuidance(
  detections: Array<{ engine: string; triggered: boolean; details?: Record<string, unknown> }>,
  redactions: RedactionMatch[],
): string {
  const parts: string[] = [];

  // Group redactions by type
  const redactionCounts: Record<string, number> = {};
  for (const r of redactions) {
    redactionCounts[r.type] = (redactionCounts[r.type] || 0) + 1;
  }

  // Generate PII/secret guidance
  const redactionParts: string[] = [];
  for (const [type, count] of Object.entries(redactionCounts)) {
    redactionParts.push(`${count} ${type}`);
  }

  if (redactionParts.length > 0) {
    parts.push(`Detected: ${redactionParts.join(', ')}.`);
    parts.push('Use safe_args for redacted version.');
  }

  // Generate detection guidance
  const triggeredEngines = detections
    .filter((d) => d.triggered)
    .map((d) => d.engine);

  if (triggeredEngines.length > 0) {
    const uniqueEngines = [...new Set(triggeredEngines)];
    parts.push(`Triggered policies: ${uniqueEngines.join(', ')}.`);
  }

  return parts.join(' ') || 'No issues detected.';
}

/**
 * Estimate cost from content
 */
export function estimateCost(
  content: string,
  modelCostPerMillionTokens: number = 3.0, // Default Claude pricing
): { estimated_tokens: number; estimated_cost_usd: number } {
  // Rough estimate: 4 characters per token
  const estimatedTokens = Math.ceil(content.length / 4);
  const estimatedCostUsd = (estimatedTokens / 1_000_000) * modelCostPerMillionTokens;

  return {
    estimated_tokens: estimatedTokens,
    estimated_cost_usd: Math.round(estimatedCostUsd * 1000000) / 1000000, // 6 decimal places
  };
}
