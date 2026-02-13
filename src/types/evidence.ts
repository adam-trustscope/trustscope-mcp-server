// Evidence Store Types

export type TraceSource = 'scan' | 'gateway' | 'mcp';

export interface Trace {
  id: string;
  source: TraceSource;
  agent_id: string | null;
  session_id: string | null;
  action_type: string | null;
  tool_name: string | null;
  request_summary: string | null;
  response_summary: string | null;
  blocked: boolean;
  simulated: boolean;
  cached: boolean;
  original_trace: string | null;
  detection_results: DetectionResultSet | null;
  policies_checked: PolicyCheckResult[] | null;
  risk_weight: number | null;
  prev_hash: string;
  audit_hash: string;
  timestamp: string;
}

export interface TraceInput {
  source: TraceSource;
  agent_id?: string;
  session_id?: string;
  action_type?: string;
  tool_name?: string;
  request_summary?: string;
  response_summary?: string;
  blocked?: boolean;
  simulated?: boolean;
  cached?: boolean;
  original_trace?: string;
  detection_results?: DetectionResultSet;
  policies_checked?: PolicyCheckResult[];
  risk_weight?: number;
}

export interface TraceFilter {
  agent_id?: string;
  session_id?: string;
  source?: TraceSource;
  limit?: number;
  offset?: number;
}

// Detection types
export type DetectionSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type DetectionMode = 'alert' | 'block';

export interface DetectionResult {
  engine: string;
  triggered: boolean;
  blocked: boolean;
  confidence: number;
  severity: DetectionSeverity;
  mode: DetectionMode;
  detail: string;
  matches?: DetectionMatch[];
}

export interface DetectionMatch {
  type: string;
  value?: string;
  location?: string;
  redacted?: string;
}

export interface DetectionResultSet {
  results: DetectionResult[];
  summary: {
    total_engines: number;
    triggered_count: number;
    blocked_count: number;
    highest_severity: DetectionSeverity | null;
  };
}

// Policy types
export interface PolicyCheckResult {
  policy_id: string;
  policy_name: string;
  action: 'allow' | 'alert' | 'block';
  triggered: boolean;
  message?: string;
}

// Agent DNA types
export interface AgentDNA {
  agent_id: string;
  computed_at: string;
  strand_data: AgentDNAStrands;
  trace_count: number;
}

export interface AgentDNAStrands {
  tool_repertoire: string[];
  token_patterns: TokenPatternStats;
  timing_patterns: TimingPatternStats;
  error_rates: ErrorRateStats;
  cost_patterns: CostPatternStats;
  session_patterns: SessionPatternStats;
  action_sequences: string[][];
  interaction_patterns: InteractionPatternStats;
}

export interface TokenPatternStats {
  avg_input_tokens: number;
  avg_output_tokens: number;
  std_dev_input: number;
  std_dev_output: number;
}

export interface TimingPatternStats {
  avg_latency_ms: number;
  std_dev_latency: number;
  avg_time_between_actions_ms: number;
}

export interface ErrorRateStats {
  total_actions: number;
  error_count: number;
  error_rate: number;
}

export interface CostPatternStats {
  total_cost: number;
  avg_cost_per_action: number;
  std_dev_cost: number;
}

export interface SessionPatternStats {
  avg_session_duration_ms: number;
  avg_actions_per_session: number;
}

export interface InteractionPatternStats {
  common_tool_sequences: string[][];
  delegation_targets: string[];
}

// Participation types
export interface Participation {
  agent_id: string;
  session_id: string;
  governance_calls: number;
  risk_boundary_actions: number;
  weighted_score: number;
  computed_at: string;
}

// Attestation types
export interface Attestation {
  id: string;
  agent_id: string;
  window_start: string;
  window_end: string;
  claims: AttestationClaims;
  evidence_root: string;
  signed: boolean;
  signature: string | null;
  created_at: string;
}

export interface AttestationClaims {
  trace_count: number;
  governance_call_count: number;
  blocked_action_count: number;
  unique_tools_used: string[];
  risk_summary: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

export interface AttestationInput {
  agent_id: string;
  window_start: string;
  window_end: string;
  claims: AttestationClaims;
  evidence_root: string;
}

// Chain anchor types
export interface ChainAnchor {
  id: number;
  first_trace_id: string;
  last_trace_id: string;
  trace_count: number;
  root_hash: string;
  created_at: string;
}

// Chain verification types
export interface ChainVerificationResult {
  valid: boolean;
  checked: number;
  broken_at?: string;
  expected_hash?: string;
  actual_hash?: string;
}

export interface ChainStats {
  total_traces: number;
  latest_hash: string | null;
  first_trace_id: string | null;
  last_trace_id: string | null;
  is_valid: boolean;
}

// Risk weights for participation scoring
export const RISK_WEIGHTS: Record<string, number> = {
  'read_only_query': 0.1,
  'internal_compute': 0.1,
  'data_read': 0.3,
  'external_api_call': 0.5,
  'data_mutation': 0.7,
  'pii_handling': 0.8,
  'financial_action': 0.9,
  'data_deletion': 1.0,
  'cross_agent_delegation': 1.0,
};
