/**
 * MCP Types
 */

export type MCPMode = 'local' | 'connected';

export interface MCPServerOptions {
  /** TrustScope API key (enables connected mode) */
  apiKey?: string;
  /** Use HTTP transport instead of stdio */
  http?: boolean;
  /** HTTP port */
  port?: number;
  /** HTTP host */
  host?: string;
  /** Base URL for connected mode */
  baseUrl?: string;
  /** Custom server name */
  serverName?: string;
  /** Custom server version */
  serverVersion?: string;
}

// Tool input types
export interface CheckPolicyInput {
  agent_id: string;
  session_id?: string;
  action_type: string;
  tool_name?: string;
  tool_args?: Record<string, unknown>;
  content?: string;
}

export interface CheckDetectionInput {
  content: string;
  context?: {
    agent_id?: string;
    session_id?: string;
    action_type?: string;
    tool_name?: string;
    direction?: 'input' | 'output';
  };
  engines?: string[];
}

export interface LogActionInput {
  agent_id: string;
  session_id?: string;
  action_type: string;
  tool_name?: string;
  request_summary?: string;
  response_summary?: string;
  blocked?: boolean;
  simulated?: boolean;
  metadata?: Record<string, unknown>;
}

export interface ListTracesInput {
  agent_id?: string;
  session_id?: string;
  limit?: number;
  offset?: number;
  blocked_only?: boolean;
}

export interface ListPoliciesInput {
  engine?: string;
}

export interface ListApprovalsInput {
  agent_id?: string;
  status?: 'pending' | 'approved' | 'rejected';
  limit?: number;
}

export interface ApproveInput {
  approval_id: string;
  approved: boolean;
  reason?: string;
}

export interface GetAgentDNAInput {
  agent_id: string;
}

export interface GetComplianceInput {
  agent_id?: string;
  session_id?: string;
}

export interface ExplainBehaviorInput {
  agent_id: string;
  session_id?: string;
  window_hours?: number;
}

export interface GetAttestationInput {
  agent_id: string;
  window_start?: string;
  window_end?: string;
  sign?: boolean;  // Sprint 3: Request Ed25519 signature (requires protect_plus tier)
}

// Tool definitions
export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}
