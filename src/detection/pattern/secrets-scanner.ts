/**
 * Secrets Scanner - Detect API keys, tokens, and credentials
 *
 * Patterns: 50+
 * Categories: Cloud providers, AI/ML, Version control, Payment, Communication, Database, Auth
 */

import type { DetectionEngine, DetectionResult, DetectionContext, DetectionConfig, SecretMatch, Severity } from '../types.js';

interface SecretPattern {
  pattern: RegExp;
  severity: Severity;
  description: string;
}

const SECRET_PATTERNS: Record<string, SecretPattern> = {
  // Cloud Providers
  aws_access_key: {
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    description: 'AWS Access Key ID',
  },
  aws_secret_key: {
    pattern: /(?:aws[_\-\s]*secret[_\-\s]*(?:access)?[_\-\s]*key['"]?\s*[:=]\s*['"]?)([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: 'critical',
    description: 'AWS Secret Access Key',
  },
  gcp_api_key: {
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    severity: 'critical',
    description: 'Google Cloud API Key',
  },
  gcp_service_account: {
    pattern: /"type"\s*:\s*"service_account"/g,
    severity: 'critical',
    description: 'GCP Service Account JSON',
  },
  azure_storage: {
    pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/g,
    severity: 'critical',
    description: 'Azure Storage Connection String',
  },

  // AI/ML APIs
  openai_api_key: {
    pattern: /sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}/g,
    severity: 'critical',
    description: 'OpenAI API Key (legacy)',
  },
  openai_api_key_new: {
    pattern: /sk-proj-[a-zA-Z0-9_-]{48,}/g,
    severity: 'critical',
    description: 'OpenAI API Key (project)',
  },
  anthropic_api_key: {
    pattern: /sk-ant-api[a-zA-Z0-9-]{90,}/g,
    severity: 'critical',
    description: 'Anthropic API Key',
  },
  huggingface_token: {
    pattern: /hf_[a-zA-Z0-9]{34}/g,
    severity: 'high',
    description: 'Hugging Face Token',
  },
  replicate_token: {
    pattern: /r8_[a-zA-Z0-9]{40}/g,
    severity: 'high',
    description: 'Replicate API Token',
  },

  // Version Control
  github_pat: {
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'high',
    description: 'GitHub Personal Access Token',
  },
  github_oauth: {
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    severity: 'high',
    description: 'GitHub OAuth Token',
  },
  github_app: {
    pattern: /ghu_[a-zA-Z0-9]{36}/g,
    severity: 'high',
    description: 'GitHub App Token',
  },
  github_refresh: {
    pattern: /ghr_[a-zA-Z0-9]{36}/g,
    severity: 'warning',
    description: 'GitHub Refresh Token',
  },
  github_fine_grained: {
    pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,
    severity: 'high',
    description: 'GitHub Fine-Grained PAT',
  },
  gitlab_pat: {
    pattern: /glpat-[a-zA-Z0-9_-]{20,}/g,
    severity: 'high',
    description: 'GitLab Personal Access Token',
  },
  gitlab_runner: {
    pattern: /GR1348941[a-zA-Z0-9_-]{20}/g,
    severity: 'high',
    description: 'GitLab Runner Token',
  },
  npm_token: {
    pattern: /npm_[a-zA-Z0-9]{36}/g,
    severity: 'high',
    description: 'NPM Token',
  },

  // Payment
  stripe_live_secret: {
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'critical',
    description: 'Stripe Live Secret Key',
  },
  stripe_test_secret: {
    pattern: /sk_test_[a-zA-Z0-9]{24,}/g,
    severity: 'warning',
    description: 'Stripe Test Secret Key',
  },
  stripe_restricted: {
    pattern: /rk_(live|test)_[a-zA-Z0-9]{24,}/g,
    severity: 'high',
    description: 'Stripe Restricted Key',
  },
  stripe_webhook: {
    pattern: /whsec_[a-zA-Z0-9]{32,}/g,
    severity: 'high',
    description: 'Stripe Webhook Secret',
  },
  square_access: {
    pattern: /sq0atp-[a-zA-Z0-9_-]{22}/g,
    severity: 'critical',
    description: 'Square Access Token',
  },
  square_oauth: {
    pattern: /sq0csp-[a-zA-Z0-9_-]{43}/g,
    severity: 'critical',
    description: 'Square OAuth Secret',
  },

  // Communication
  twilio_sid: {
    pattern: /AC[a-f0-9]{32}/g,
    severity: 'high',
    description: 'Twilio Account SID',
  },
  sendgrid_key: {
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: 'high',
    description: 'SendGrid API Key',
  },
  mailchimp_key: {
    pattern: /[a-f0-9]{32}-us[0-9]{1,2}/g,
    severity: 'high',
    description: 'Mailchimp API Key',
  },
  mailgun_key: {
    pattern: /key-[a-zA-Z0-9]{32}/g,
    severity: 'high',
    description: 'Mailgun API Key',
  },
  slack_token: {
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    severity: 'high',
    description: 'Slack Token',
  },
  slack_webhook: {
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
    severity: 'warning',
    description: 'Slack Webhook URL',
  },
  discord_webhook: {
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g,
    severity: 'warning',
    description: 'Discord Webhook URL',
  },
  discord_bot_token: {
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
    severity: 'high',
    description: 'Discord Bot Token',
  },
  telegram_token: {
    pattern: /[0-9]{9,10}:[a-zA-Z0-9_-]{35}/g,
    severity: 'high',
    description: 'Telegram Bot Token',
  },

  // Database
  mongodb_uri: {
    pattern: /mongodb(?:\+srv)?:\/\/[^\s"'<>]+/g,
    severity: 'critical',
    description: 'MongoDB Connection String',
  },
  postgres_uri: {
    pattern: /postgres(?:ql)?:\/\/[^\s"'<>]+/g,
    severity: 'critical',
    description: 'PostgreSQL Connection String',
  },
  mysql_uri: {
    pattern: /mysql:\/\/[^\s"'<>]+/g,
    severity: 'critical',
    description: 'MySQL Connection String',
  },
  redis_uri: {
    pattern: /rediss?:\/\/[^\s"'<>]+/g,
    severity: 'high',
    description: 'Redis Connection String',
  },

  // Auth Tokens
  jwt_token: {
    pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    severity: 'warning',
    description: 'JWT Token',
  },
  basic_auth_header: {
    pattern: /authorization\s*:\s*basic\s+[A-Za-z0-9+/=]+/gi,
    severity: 'high',
    description: 'Basic Auth Header',
  },
  bearer_token: {
    pattern: /authorization\s*:\s*bearer\s+[A-Za-z0-9._-]+/gi,
    severity: 'high',
    description: 'Bearer Token',
  },

  // Private Keys
  rsa_private_key: {
    pattern: /-----BEGIN RSA PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'RSA Private Key',
  },
  openssh_private_key: {
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'OpenSSH Private Key',
  },
  ec_private_key: {
    pattern: /-----BEGIN EC PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'EC Private Key',
  },
  pgp_private_key: {
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    severity: 'critical',
    description: 'PGP Private Key',
  },
  generic_private_key: {
    pattern: /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'Private Key',
  },
  dsa_private_key: {
    pattern: /-----BEGIN DSA PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'DSA Private Key',
  },

  // Generic patterns (higher false positive risk)
  generic_api_key: {
    pattern: /(?:api[_-]?key|apikey)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
    severity: 'info',
    description: 'Generic API Key',
  },
  generic_secret: {
    pattern: /(?:secret|password|passwd|pwd)['"]?\s*[:=]\s*['"]?([^\s'"]{12,})['"]?/gi,
    severity: 'info',
    description: 'Generic Secret/Password',
  },
};

function redactSecret(value: string): string {
  if (value.length > 12) {
    return `${value.slice(0, 4)}...${value.slice(-4)}`;
  }
  return '***REDACTED***';
}

function getSeverityLevel(severity: Severity): number {
  const levels: Record<Severity, number> = {
    info: 0,
    warning: 1,
    high: 2,
    critical: 3,
  };
  return levels[severity] ?? 0;
}

export class SecretsScanner implements DetectionEngine {
  name = 'secrets_scanner';

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

    const enabledPatterns = (config.patterns as string[] | undefined) || Object.keys(SECRET_PATTERNS);
    const matches: SecretMatch[] = [];
    let highestSeverity: Severity = 'info';

    for (const patternName of enabledPatterns) {
      const patternConfig = SECRET_PATTERNS[patternName];
      if (!patternConfig) continue;

      // Reset regex lastIndex for global patterns
      patternConfig.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = patternConfig.pattern.exec(content)) !== null) {
        const matchedText = match[0];

        matches.push({
          patternName,
          matchedText,
          start: match.index,
          end: match.index + matchedText.length,
          confidence: 0.9,
          severity: patternConfig.severity,
          description: patternConfig.description,
          redacted: redactSecret(matchedText),
        });

        if (getSeverityLevel(patternConfig.severity) > getSeverityLevel(highestSeverity)) {
          highestSeverity = patternConfig.severity;
        }
      }
    }

    const triggered = matches.length > 0;

    return {
      engine: this.name,
      triggered,
      blocked: triggered && highestSeverity === 'critical',
      severity: highestSeverity,
      confidence: triggered ? 0.9 : 0,
      details: {
        matches: matches.map((m) => ({
          pattern: m.patternName,
          redacted: m.redacted,
          severity: m.severity,
          description: m.description,
        })),
        matchCount: matches.length,
      },
      message: triggered
        ? `Found ${matches.length} potential secret(s): ${[...new Set(matches.map((m) => m.patternName))].join(', ')}`
        : undefined,
    };
  }

  redact(content: string, config: DetectionConfig): string {
    const result = this.check(content, {}, config);
    if (!result.triggered) return content;

    let redacted = content;
    const matches = result.details.matches as Array<{ pattern: string }>;

    // Sort by position descending to replace from end
    for (const patternName of [...new Set(matches.map((m) => m.pattern))]) {
      const patternConfig = SECRET_PATTERNS[patternName];
      if (patternConfig) {
        redacted = redacted.replace(patternConfig.pattern, '[REDACTED]');
      }
    }

    return redacted;
  }
}

export const secretsScanner = new SecretsScanner();
