import type { ApiClient } from '../../utils/api-client.js';
import type { GetPoliciesInput, GetPoliciesResult } from '../../types/mcp.js';

export const getPoliciesDefinition = {
  name: 'trustscope_get_policies',
  description: 'List active governance policies for your organization. Returns policy configurations for agents.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      agent_id: {
        type: 'string',
        description: 'Optional filter by specific agent ID',
      },
      enabled_only: {
        type: 'boolean',
        description: 'Only return enabled policies (default true)',
      },
    },
    required: [],
  },
};

export async function getPolicies(
  apiClient: ApiClient,
  input: GetPoliciesInput
): Promise<GetPoliciesResult> {
  const now = new Date().toISOString();

  try {
    const params: Record<string, unknown> = {
      enabled_only: input.enabled_only ?? true,
    };
    if (input.agent_id) params.agent_id = input.agent_id;

    const response = await apiClient.get<GetPoliciesResult>(
      '/api/v1/mcp/policies',
      params
    );

    if (!response.success || !response.data) {
      return {
        policies: [],
        count: 0,
        queried_at: now,
        entry_point: 'mcp',
        error: response.error || 'Failed to get policies',
      };
    }

    return {
      ...response.data,
      entry_point: 'mcp',
    };
  } catch (error) {
    return {
      policies: [],
      count: 0,
      queried_at: now,
      entry_point: 'mcp',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
