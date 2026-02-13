/**
 * Detection Engine Types
 */

export type Severity = 'info' | 'warning' | 'high' | 'critical';
export type DetectionAction = 'allow' | 'alert' | 'block';

export interface DetectionResult {
  engine: string;
  triggered: boolean;
  blocked: boolean;
  severity: Severity;
  confidence?: number;
  details: Record<string, unknown>;
  message?: string;
}

export interface DetectionContext {
  sessionId?: string;
  agentId?: string;
  actionType?: string;
  toolName?: string;
  requestContent?: string;
  responseContent?: string;
  timestamp?: string;
  direction?: 'input' | 'output';
  source?: string;
  metadata?: Record<string, unknown>;
}

export interface SessionState {
  requestHashes: Array<{ hash: string; timestamp: number }>;
  recentActions: string[];
  totalCost: number;
  actionCount: number;
  errorCount: number;
  startTime: number;
  tokenCounts: number[];
  contextSizes: number[];
}

export interface DetectionConfig {
  enabled: boolean;
  [key: string]: unknown;
}

export interface DetectionEngine {
  name: string;
  check(
    content: string,
    context: DetectionContext,
    config: DetectionConfig,
    sessionState?: SessionState
  ): DetectionResult;
}

// Pattern match result
export interface PatternMatch {
  patternName: string;
  matchedText: string;
  start: number;
  end: number;
  confidence: number;
  category?: string;
  severity?: Severity;
  redacted?: string;
}

// PII-specific types
export type PIITier = 'tier_1' | 'tier_2' | 'tier_3';
export type PIICategory =
  | 'us_pii'
  | 'international_id'
  | 'financial'
  | 'cloud_keys'
  | 'code_platforms'
  | 'payment'
  | 'communication'
  | 'private_keys'
  | 'generic_creds'
  | 'contact_info';

export interface PIIMatch extends PatternMatch {
  piiType: string;
  tier: PIITier;
  piiCategory: PIICategory;
  maskedValue: string;
}

// Secrets-specific types
export interface SecretMatch extends PatternMatch {
  description: string;
}

// Injection-specific types
export type InjectionCategory =
  | 'instruction_override'
  | 'system_extraction'
  | 'role_manipulation'
  | 'delimiter_attack'
  | 'encoding_attack'
  | 'hypothetical_framing'
  | 'developer_mode';

export interface InjectionMatch extends PatternMatch {
  injectionCategory: InjectionCategory;
}

// Jailbreak-specific types
export type JailbreakCategory =
  | 'dan_variants'
  | 'persona_exploits'
  | 'token_smuggling'
  | 'emotional_manipulation'
  | 'fiction_framing'
  | 'obfuscation';

export interface JailbreakMatch extends PatternMatch {
  jailbreakCategory: JailbreakCategory;
  knownJailbreak?: string;
}

// Command firewall types
export type CommandCategory = 'shell' | 'sql' | 'code_exec' | 'secrets';

export interface CommandMatch extends PatternMatch {
  commandCategory: CommandCategory;
  description: string;
}

// Aggregated detection results
export interface DetectionResultSet {
  results: DetectionResult[];
  anyTriggered: boolean;
  anyBlocked: boolean;
  highestSeverity: Severity;
  summary: string;
}
