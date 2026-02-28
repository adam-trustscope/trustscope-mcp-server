import type { ApiClient } from '../../utils/api-client.js';
import type { PolicyCheckInput, PolicyCheckResult } from '../../types/mcp.js';

export const policyCheckDefinition = {
  name: 'trustscope_policy_check',
  description: 'Evaluate an action against TrustScope governance policies before execution. Returns whether the action is allowed and any policy violations.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      agent_id: {
        type: 'string',
        description: 'The unique identifier of the AI agent',
      },
      action: {
        type: 'string',
        description: 'The action type being performed (e.g., "llm_call", "tool_use", "file_write")',
      },
      resource: {
        type: 'string',
        description: 'Optional resource being accessed',
      },
      context: {
        type: 'object',
        description: 'Optional context including user_id, session_id, and metadata',
        properties: {
          user_id: { type: 'string' },
          session_id: { type: 'string' },
          metadata: { type: 'object' },
        },
      },
    },
    required: ['agent_id', 'action'],
  },
};

export async function policyCheck(
  apiClient: ApiClient,
  input: PolicyCheckInput
): Promise<PolicyCheckResult> {
  const now = new Date().toISOString();

  try {
    const response = await apiClient.post<PolicyCheckResult>(
      '/api/v1/mcp/policy-check',
      input
    );

    if (!response.success || !response.data) {
      return {
        allowed: true, // Fail open by default
        reason: response.error || 'Policy check failed',
        violations: [],
        evaluated_at: now,
        entry_point: 'mcp',
        error: response.error,
      };
    }

    return {
      ...response.data,
      entry_point: 'mcp',
    };
  } catch (error) {
    return {
      allowed: true, // Fail open on error
      reason: 'Policy check error - allowing action',
      violations: [],
      evaluated_at: now,
      entry_point: 'mcp',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
