// Tool Input Types
export interface PolicyCheckInput {
  agent_id: string;
  action: string;
  resource?: string;
  context?: {
    user_id?: string;
    session_id?: string;
    metadata?: Record<string, unknown>;
  };
}

export interface LogActionInput {
  agent_id: string;
  action: string;
  result: 'success' | 'failure' | 'blocked';
  tool?: string;
  input_data?: Record<string, unknown>;
  output_data?: Record<string, unknown>;
  session_id?: string;
}

export interface GetTracesInput {
  agent_id?: string;
  limit?: number;
  outcome_status?: 'pending' | 'completed' | 'blocked' | 'error';
}

export interface GetPoliciesInput {
  agent_id?: string;
  enabled_only?: boolean;
}

export interface CreateApprovalInput {
  agent_id: string;
  action_type: string;
  parameters?: Record<string, unknown>;
  context?: string;
  expires_in_hours?: number;
}

export interface GetApprovalsInput {
  status?: 'pending' | 'approved' | 'rejected';
  agent_id?: string;
}

export interface GetAgentDNAInput {
  agent_id: string;
}

export interface RunDetectionInput {
  detection_type: 'prompt_injection' | 'pii' | 'secrets' | 'dangerous_commands' | 'jailbreak';
  content: string;
  agent_id?: string;
}

export interface ComplianceStatusInput {
  framework: 'NIST_AI_RMF' | 'EU_AI_ACT' | 'SOC2' | 'ISO42001' | 'HIPAA';
  agent_id?: string;
}

// Tool Output Types
export interface PolicyCheckResult {
  allowed: boolean;
  reason: string;
  policy_id?: string;
  violations: Array<{ policy: string; message: string }>;
  evaluated_at: string;
  entry_point: 'mcp';
  error?: string;
}

export interface LogActionResult {
  event_id: string;
  hash: string;
  chain_position: number;
  prev_hash: string;
  bitcoin_anchor_pending: boolean;
  logged_at: string;
  entry_point: 'mcp';
  error?: string;
}

export interface TraceItem {
  trace_id: string;
  agent_id: string;
  action: { type: string; request: Record<string, unknown> };
  outcome: { status: string; response: Record<string, unknown> };
  blocked_by_policy: boolean;
  timestamp: string;
  audit_hash: string;
}

export interface GetTracesResult {
  traces: TraceItem[];
  count: number;
  has_more: boolean;
  queried_at: string;
  entry_point: 'mcp';
  error?: string;
}

export interface PolicyItem {
  id: string;
  name: string;
  policy_type: string;
  enabled: boolean;
  agent_id?: string;
  description: string;
  config: Record<string, unknown>;
  created_at: string;
}

export interface GetPoliciesResult {
  policies: PolicyItem[];
  count: number;
  agent_filter?: string;
  queried_at: string;
  entry_point: 'mcp';
  error?: string;
}

export interface ApprovalItem {
  id: string;
  status: string;
  agent_id: string;
  action_type: string;
  context?: string;
  expires_at: string;
  created_at: string;
  resolved_by?: string;
  resolved_at?: string;
}

export interface CreateApprovalResult {
  id: string;
  status: 'pending';
  agent_id: string;
  action_type: string;
  parameters?: Record<string, unknown>;
  context?: string;
  expires_at: string;
  created_at: string;
  entry_point: 'mcp';
  error?: string;
}

export interface GetApprovalsResult {
  requests: ApprovalItem[];
  count: number;
  status_filter: string;
  queried_at: string;
  entry_point: 'mcp';
  error?: string;
}

export interface AgentDNAStrands {
  model: string;
  tools: string[];
  system_prompt_hash: string;
  temperature: number;
  behavioral: Record<string, unknown>;
}

export interface GetAgentDNAResult {
  agent_id: string;
  fingerprint: string;
  strands: AgentDNAStrands;
  drift_detected: boolean;
  drift_score: number;
  drift_details: string[];
  baseline_established: boolean;
  last_updated: string;
  entry_point: 'mcp';
  error?: string;
}

export interface DetectionMatch {
  pattern?: string;
  category?: string;
  known_jailbreak?: string;
  redacted?: string;
}

export interface RunDetectionResult {
  detection_type: string;
  triggered: boolean;
  blocked: boolean;
  confidence: number;
  severity: 'info' | 'warning' | 'critical';
  matches: DetectionMatch[];
  message: string;
  analyzed_at: string;
  entry_point: 'mcp';
  error?: string;
}

export interface ComplianceCategory {
  id: string;
  name: string;
  description: string;
  coverage_percent: number;
  status: 'compliant' | 'partial' | 'gap';
  gaps: string[];
}

export interface ComplianceStatusResult {
  framework: string;
  framework_name: string;
  overall_coverage_percent: number;
  overall_status: 'compliant' | 'partial' | 'non_compliant';
  categories: ComplianceCategory[];
  agent_specific: boolean;
  agent_id?: string;
  recommendations: string[];
  checked_at: string;
  entry_point: 'mcp';
  error?: string;
}

// API Client Types
export interface TrustScopeConfig {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
}

// MCP Types
export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

export type ToolHandler<TInput, TOutput> = (input: TInput) => Promise<TOutput>;
