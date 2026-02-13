/**
 * Configuration Type Definitions
 */

export interface TrustScopeConfig {
  // Version
  version?: number;

  // Authentication
  apiKey?: string;
  baseUrl?: string;

  // Identity
  projectId?: string;
  agentId?: string;

  // Storage
  dbPath?: string;

  // Detection settings
  detection?: Partial<DetectionConfig>;

  // Policy settings
  policies?: Partial<PolicyConfig>;

  // Watch mode settings
  watch?: Partial<WatchConfig>;

  // Cache settings
  cache?: Partial<CacheConfig>;
}

export interface DetectionConfig {
  // Statistical engines
  loop_killer: LoopKillerConfig;
  velocity_limit: VelocityLimitConfig;
  cost_velocity: CostVelocityConfig;
  budget_caps: BudgetCapsConfig;
  token_growth: TokenGrowthConfig;
  context_expansion: ContextExpansionConfig;
  oscillation: OscillationConfig;
  error_rate: ErrorRateConfig;
  session_duration: SessionDurationConfig;
  session_action_limit: SessionActionLimitConfig;

  // Pattern engines
  pii_scanner: PIIScannerConfig;
  secrets_scanner: SecretsScannerConfig;
  command_firewall: CommandFirewallConfig;
  blocked_phrases: BlockedPhrasesConfig;
  data_exfiltration: DataExfiltrationConfig;
  prompt_injection: PromptInjectionConfig;
  jailbreak: JailbreakConfig;
  action_label_mismatch: ActionLabelMismatchConfig;
}

export interface PolicyConfig {
  pii_scanner: PolicyActionConfig;
  secrets_scanner: PolicyActionConfig;
  loop_killer: PolicyActionConfig;
  velocity_limit: PolicyActionConfig;
  cost_limit: PolicyActionConfig;
  data_exfiltration: PolicyActionConfig;
  prompt_injection: PolicyActionConfig;
  jailbreak: PolicyActionConfig;
}

export interface WatchConfig {
  port: number;
  timeout: number;
  maxRpm: number;
  maxCost: number;
  loopThreshold: number;
  loopDetection: boolean;
}

export interface CacheConfig {
  enabled: boolean;
  ttlMinutes: number;
  maxEntries: number;
}

// Individual engine configs
export interface LoopKillerConfig {
  enabled: boolean;
  maxIterations: number;
  windowSeconds: number;
}

export interface VelocityLimitConfig {
  enabled: boolean;
  maxCallsPerMinute: number;
}

export interface CostVelocityConfig {
  enabled: boolean;
  maxPerMinute: number;
}

export interface BudgetCapsConfig {
  enabled: boolean;
  maxPerSession: number;
  maxPerDay?: number;
  maxPerMonth?: number;
}

export interface TokenGrowthConfig {
  enabled: boolean;
  alertThresholdPercent: number;
  windowSize: number;
}

export interface ContextExpansionConfig {
  enabled: boolean;
  alertThresholdPercent: number;
  maxTokens: number;
}

export interface OscillationConfig {
  enabled: boolean;
  windowSize: number;
  cycleThreshold: number;
}

export interface ErrorRateConfig {
  enabled: boolean;
  alertThresholdPercent: number;
  windowSize: number;
}

export interface SessionDurationConfig {
  enabled: boolean;
  maxHours: number;
}

export interface SessionActionLimitConfig {
  enabled: boolean;
  maxActions: number;
}

export interface PIIScannerConfig {
  enabled: boolean;
  patterns: string[];
  tier1BlockPatterns: string[];
  tier2AlertPatterns: string[];
}

export interface SecretsScannerConfig {
  enabled: boolean;
  patterns: string[];
}

export interface CommandFirewallConfig {
  enabled: boolean;
  blockedPatterns: string[];
  categories: string[];
}

export interface BlockedPhrasesConfig {
  enabled: boolean;
  phrases: string[];
}

export interface DataExfiltrationConfig {
  enabled: boolean;
  allowedDomains: string[];
  blockedDomains: string[];
  maxPayloadBytes: number;
}

export interface PromptInjectionConfig {
  enabled: boolean;
  patterns: string[];
}

export interface JailbreakConfig {
  enabled: boolean;
  patterns: string[];
}

export interface ActionLabelMismatchConfig {
  enabled: boolean;
  destructiveKeywords: string[];
}

export interface PolicyActionConfig {
  action: 'allow' | 'alert' | 'block';
  patterns?: string[];
  threshold?: number;
}
