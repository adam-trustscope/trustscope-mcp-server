/**
 * Default Configuration Values
 *
 * Philosophy: Block what's unambiguously dangerous (secrets, loops).
 * Alert on everything else.
 */

import type { TrustScopeConfig, DetectionConfig, PolicyConfig } from './types.js';

export const DEFAULT_DETECTION_CONFIG: DetectionConfig = {
  // Statistical engines
  loop_killer: {
    enabled: true,
    maxIterations: 50,
    windowSeconds: 60,
  },
  velocity_limit: {
    enabled: true,
    maxCallsPerMinute: 100,
  },
  cost_velocity: {
    enabled: true,
    maxPerMinute: 5.0,
  },
  budget_caps: {
    enabled: true,
    maxPerSession: 10.0,
    maxPerDay: 100.0,
    maxPerMonth: 1000.0,
  },
  token_growth: {
    enabled: true,
    alertThresholdPercent: 50,
    windowSize: 3,
  },
  context_expansion: {
    enabled: true,
    alertThresholdPercent: 50,
    maxTokens: 50000,
  },
  oscillation: {
    enabled: true,
    windowSize: 20,
    cycleThreshold: 3,
  },
  error_rate: {
    enabled: true,
    alertThresholdPercent: 30,
    windowSize: 10,
  },
  session_duration: {
    enabled: true,
    maxHours: 4,
  },
  session_action_limit: {
    enabled: true,
    maxActions: 1000,
  },

  // Pattern engines
  pii_scanner: {
    enabled: true,
    patterns: ['ssn', 'credit_card', 'phone', 'email', 'passport', 'dob', 'address'],
    tier1BlockPatterns: ['ssn', 'credit_card', 'passport'],
    tier2AlertPatterns: ['phone', 'email', 'dob', 'address'],
  },
  secrets_scanner: {
    enabled: true,
    patterns: [
      'aws_key',
      'aws_secret',
      'github_token',
      'api_key',
      'private_key',
      'jwt',
      'openai_key',
      'anthropic_key',
    ],
  },
  command_firewall: {
    enabled: true,
    blockedPatterns: [],
    categories: ['shell_dangerous', 'sql_injection', 'code_execution'],
  },
  blocked_phrases: {
    enabled: true,
    phrases: [],
  },
  data_exfiltration: {
    enabled: true,
    allowedDomains: [],
    blockedDomains: ['pastebin.com', 'hastebin.com', 'requestbin.com'],
    maxPayloadBytes: 100000,
  },
  prompt_injection: {
    enabled: true,
    patterns: [],
  },
  jailbreak: {
    enabled: true,
    patterns: [],
  },
  action_label_mismatch: {
    enabled: true,
    destructiveKeywords: ['DELETE', 'DROP', 'TRUNCATE', 'rm', 'remove', 'destroy'],
  },
};

export const DEFAULT_POLICY_CONFIG: PolicyConfig = {
  pii_scanner: {
    action: 'alert',
    patterns: ['ssn', 'credit_card', 'phone', 'email', 'passport', 'dob'],
  },
  secrets_scanner: {
    action: 'block',
    patterns: ['aws_key', 'github_token', 'api_key', 'private_key', 'jwt'],
  },
  loop_killer: {
    action: 'block',
    threshold: 50,
  },
  velocity_limit: {
    action: 'alert',
    threshold: 100,
  },
  cost_limit: {
    action: 'alert',
    threshold: 10.0,
  },
  data_exfiltration: {
    action: 'alert',
  },
  prompt_injection: {
    action: 'alert',
  },
  jailbreak: {
    action: 'alert',
  },
};

export const DEFAULT_CONFIG: TrustScopeConfig = {
  version: 1,

  // No API key by default (local mode)
  apiKey: undefined,
  baseUrl: 'https://api.trustscope.ai',

  // No default project/agent IDs
  projectId: undefined,
  agentId: undefined,

  // Default database path
  dbPath: '.trustscope/evidence.db',

  // Detection defaults
  detection: DEFAULT_DETECTION_CONFIG,

  // Policy defaults
  policies: DEFAULT_POLICY_CONFIG,

  // Watch mode defaults
  watch: {
    port: 4000,
    timeout: 10,
    maxRpm: 60,
    maxCost: 10.0,
    loopThreshold: 3,
    loopDetection: true,
  },

  // Cache defaults
  cache: {
    enabled: true,
    ttlMinutes: 5,
    maxEntries: 100,
  },
};

/**
 * Risk weights for participation scoring
 */
export const RISK_WEIGHTS: Record<string, number> = {
  read_only_query: 0.1,
  internal_compute: 0.1,
  data_read: 0.3,
  external_api_call: 0.5,
  data_mutation: 0.7,
  pii_handling: 0.8,
  financial_action: 0.9,
  data_deletion: 1.0,
  cross_agent_delegation: 1.0,
};

/**
 * Model cost table (per 1K tokens)
 */
export const MODEL_COSTS: Record<string, { input: number; output: number }> = {
  // OpenAI
  'gpt-4': { input: 0.03, output: 0.06 },
  'gpt-4-turbo': { input: 0.01, output: 0.03 },
  'gpt-4o': { input: 0.005, output: 0.015 },
  'gpt-4o-mini': { input: 0.00015, output: 0.0006 },
  'gpt-3.5-turbo': { input: 0.0005, output: 0.0015 },
  'o1': { input: 0.015, output: 0.06 },
  'o1-mini': { input: 0.003, output: 0.012 },
  'o3-mini': { input: 0.0011, output: 0.0044 },

  // Anthropic
  'claude-3-opus': { input: 0.015, output: 0.075 },
  'claude-3-5-sonnet': { input: 0.003, output: 0.015 },
  'claude-3-sonnet': { input: 0.003, output: 0.015 },
  'claude-3-5-haiku': { input: 0.0008, output: 0.004 },
  'claude-3-haiku': { input: 0.00025, output: 0.00125 },

  // Google
  'gemini-1.5-pro': { input: 0.00125, output: 0.005 },
  'gemini-1.5-flash': { input: 0.000075, output: 0.0003 },
  'gemini-2.0-flash': { input: 0.0001, output: 0.0004 },
  'gemini-1.0-pro': { input: 0.0005, output: 0.0015 },

  // Mistral
  'mistral-large': { input: 0.004, output: 0.012 },
  'mistral-medium': { input: 0.0027, output: 0.0081 },
  'mistral-small': { input: 0.001, output: 0.003 },
  codestral: { input: 0.001, output: 0.003 },

  // Cohere
  'command-r-plus': { input: 0.003, output: 0.015 },
  'command-r': { input: 0.0005, output: 0.0015 },

  // Groq
  'llama-3.1-70b': { input: 0.00059, output: 0.00079 },
  'llama-3.1-8b': { input: 0.00005, output: 0.00008 },
  'mixtral-8x7b': { input: 0.00024, output: 0.00024 },

  // Together AI
  'llama-3.1-405b': { input: 0.005, output: 0.015 },

  // AWS Bedrock
  'amazon.titan-text': { input: 0.0008, output: 0.0016 },
};
