/**
 * Default Policy Pack
 *
 * Zero-config defaults that provide immediate protection:
 * - Block: Unambiguously dangerous (secrets, loops, command execution)
 * - Alert: Everything else (PII, injection, jailbreak)
 *
 * Philosophy: Don't break workflows, but catch the worst offenders.
 */

import type { PolicyPack, PolicyConfig } from './types.js';

/**
 * Default policy configurations for each detection engine
 */
export const DEFAULT_POLICY_CONFIGS: Record<string, PolicyConfig> = {
  // ==========================================
  // Pattern Engines - Content Scanning
  // ==========================================

  /**
   * PII Scanner - Alert on sensitive personal information
   * Action: alert (not block - PII may be intentional in some contexts)
   */
  pii_scanner: {
    enabled: true,
    action: 'alert',
    description: 'Detect personally identifiable information (SSN, credit cards, phone, email, etc.)',
    config: {
      categories: ['us_pii', 'financial', 'international_id', 'contact'],
      // Patterns to look for (defaults to all)
      patterns: ['ssn', 'credit_card', 'phone', 'email', 'passport', 'dob'],
    },
  },

  /**
   * Secrets Scanner - BLOCK on exposed credentials
   * Action: block (secrets exposure is almost never intentional)
   */
  secrets_scanner: {
    enabled: true,
    action: 'block',
    severity: 'critical',
    description: 'Block exposed API keys, tokens, and credentials',
    config: {
      // Patterns to look for (defaults to all)
      patterns: [
        'aws_access_key',
        'aws_secret_key',
        'github_token',
        'github_pat',
        'openai_api_key',
        'openai_api_key_new',
        'anthropic_api_key',
        'stripe_api_key',
        'private_key',
        'jwt_token',
      ],
    },
  },

  /**
   * Command Firewall - BLOCK dangerous shell/SQL commands
   * Action: block (rm -rf, DROP TABLE, etc. are never acceptable)
   */
  command_firewall: {
    enabled: true,
    action: 'block',
    severity: 'critical',
    description: 'Block dangerous shell, SQL, and code execution patterns',
    config: {
      categories: ['shell', 'sql', 'code_exec'],
    },
  },

  /**
   * Prompt Injection Detection - Alert on injection attempts
   * Action: alert (may have false positives in legitimate prompts)
   */
  prompt_injection: {
    enabled: true,
    action: 'alert',
    description: 'Detect prompt injection attempts',
    config: {
      categories: [
        'ignore_instructions',
        'role_play',
        'system_prompt_leak',
        'encoding_tricks',
        'multilingual',
      ],
    },
  },

  /**
   * Jailbreak Detection - Alert on jailbreak attempts
   * Action: alert (may have false positives)
   */
  jailbreak: {
    enabled: true,
    action: 'alert',
    description: 'Detect jailbreak attempts (DAN, STAN, etc.)',
    config: {
      categories: [
        'dan_variants',
        'persona_exploits',
        'token_smuggling',
        'emotional_manipulation',
      ],
    },
  },

  /**
   * Data Exfiltration - Alert on bulk data transfers
   * Action: alert (some legitimate uses exist)
   */
  data_exfiltration: {
    enabled: true,
    action: 'alert',
    description: 'Detect potential data exfiltration patterns',
    config: {
      minRecords: 10,
      checkBase64: true,
      checkUrls: true,
    },
  },

  /**
   * Blocked Phrases - Configurable blocklist
   * Action: block (user-defined dangerous phrases)
   */
  blocked_phrases: {
    enabled: false, // Disabled by default - user must configure
    action: 'block',
    description: 'Block user-configured phrases',
    config: {
      phrases: [],
      caseSensitive: false,
    },
  },

  /**
   * Action Label Mismatch - BLOCK mismatched labels
   * Action: block (indicates potential deception)
   */
  action_label_mismatch: {
    enabled: true,
    action: 'block',
    severity: 'critical',
    description: 'Block actions where label contradicts destructive parameters',
  },

  // ==========================================
  // Statistical Engines - Behavioral Analysis
  // ==========================================

  /**
   * Loop Killer - BLOCK infinite loops
   * Action: block (loops waste resources and indicate bugs)
   */
  loop_killer: {
    enabled: true,
    action: 'block',
    severity: 'critical',
    description: 'Block infinite loop patterns',
    config: {
      maxIterations: 50,
      windowSeconds: 60,
    },
  },

  /**
   * Velocity Limit - Alert on high call rates
   * Action: alert (may indicate automation, not necessarily bad)
   */
  velocity_limit: {
    enabled: true,
    action: 'alert',
    description: 'Alert on high request velocity',
    config: {
      maxCallsPerMinute: 100,
    },
  },

  /**
   * Cost Velocity - Alert on spending acceleration
   * Action: alert (track spending patterns)
   */
  cost_velocity: {
    enabled: true,
    action: 'alert',
    description: 'Alert on accelerating cost velocity',
    config: {
      accelerationThreshold: 2.0, // 2x acceleration triggers alert
      windowMinutes: 5,
    },
  },

  /**
   * Budget Caps - BLOCK when budget exceeded
   * Action: block (hard stop on spending)
   */
  budget_caps: {
    enabled: true,
    action: 'block',
    description: 'Block requests when session budget exceeded',
    config: {
      maxPerSession: 10.0, // $10 per session default
      maxPerHour: 50.0, // $50 per hour default
    },
  },

  /**
   * Token Growth - Alert on exponential output growth
   * Action: alert (may indicate runaway generation)
   */
  token_growth: {
    enabled: true,
    action: 'alert',
    description: 'Alert on exponential token growth',
    config: {
      growthThreshold: 2.0, // 2x growth triggers alert
      windowSize: 5, // Look at last 5 requests
    },
  },

  /**
   * Context Expansion - Alert on rapid context growth
   * Action: alert (may indicate context stuffing)
   */
  context_expansion: {
    enabled: true,
    action: 'alert',
    description: 'Alert on rapid context expansion',
    config: {
      maxGrowthRatePercent: 50, // 50% growth per request
      windowSize: 5,
    },
  },

  /**
   * Oscillation Detection - Alert on A-B-A-B patterns
   * Action: alert (indicates stuck behavior)
   */
  oscillation: {
    enabled: true,
    action: 'alert',
    description: 'Alert on oscillating request patterns',
    config: {
      windowSize: 20,
      minOscillations: 3,
    },
  },

  /**
   * Error Rate - Alert on high error rates
   * Action: alert (indicates problems)
   */
  error_rate: {
    enabled: true,
    action: 'alert',
    description: 'Alert on high error response rates',
    config: {
      threshold: 0.3, // 30% error rate
      windowSize: 10,
    },
  },

  /**
   * Session Duration - Alert on long sessions
   * Action: alert (may indicate stuck process)
   */
  session_duration: {
    enabled: true,
    action: 'alert',
    description: 'Alert on excessively long sessions',
    config: {
      maxHours: 4, // 4 hour sessions trigger alert
    },
  },

  /**
   * Session Action Limit - BLOCK after too many actions
   * Action: block (hard stop on runaway agents)
   */
  session_action_limit: {
    enabled: true,
    action: 'block',
    description: 'Block after exceeding session action limit',
    config: {
      maxActions: 1000,
    },
  },
};

/**
 * Default policy pack
 */
export const DEFAULT_POLICY_PACK: PolicyPack = {
  name: 'trustscope-defaults',
  version: '1.0.0',
  description: 'Default TrustScope policy pack with balanced protection',
  policies: DEFAULT_POLICY_CONFIGS,
};

/**
 * Get a specific policy configuration by engine name
 */
export function getDefaultPolicy(engineName: string): PolicyConfig | undefined {
  return DEFAULT_POLICY_CONFIGS[engineName];
}

/**
 * Get all default policy configurations
 */
export function getAllDefaultPolicies(): Record<string, PolicyConfig> {
  return { ...DEFAULT_POLICY_CONFIGS };
}

/**
 * Merge custom policies with defaults
 */
export function mergePolicies(
  custom: Partial<Record<string, Partial<PolicyConfig>>>,
): Record<string, PolicyConfig> {
  const merged: Record<string, PolicyConfig> = { ...DEFAULT_POLICY_CONFIGS };

  for (const [engineName, customConfig] of Object.entries(custom)) {
    if (customConfig) {
      const defaultConfig = merged[engineName];
      if (defaultConfig) {
        // Merge with defaults
        merged[engineName] = {
          ...defaultConfig,
          ...customConfig,
          config: {
            ...defaultConfig.config,
            ...customConfig.config,
          },
        };
      } else {
        // New policy not in defaults
        merged[engineName] = customConfig as PolicyConfig;
      }
    }
  }

  return merged;
}

/**
 * Create a strict policy pack (blocks on everything)
 */
export function createStrictPolicies(): Record<string, PolicyConfig> {
  const strict: Record<string, PolicyConfig> = {};

  for (const [engineName, config] of Object.entries(DEFAULT_POLICY_CONFIGS)) {
    strict[engineName] = {
      ...config,
      action: 'block', // Block on everything
    };
  }

  return strict;
}

/**
 * Create a permissive policy pack (alerts on everything, blocks nothing)
 */
export function createPermissivePolicies(): Record<string, PolicyConfig> {
  const permissive: Record<string, PolicyConfig> = {};

  for (const [engineName, config] of Object.entries(DEFAULT_POLICY_CONFIGS)) {
    permissive[engineName] = {
      ...config,
      action: 'alert', // Alert only, never block
    };
  }

  return permissive;
}
