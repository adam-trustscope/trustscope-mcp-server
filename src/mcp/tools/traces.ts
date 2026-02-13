import type { ApiClient } from '../../utils/api-client.js';
import type { GetTracesInput, GetTracesResult } from '../../types/mcp.js';

export const getTracesDefinition = {
  name: 'trustscope_get_traces',
  description: 'Query the audit trail history for AI agent actions. Returns traces with hash chain verification for compliance audits.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      agent_id: {
        type: 'string',
        description: 'Optional filter by specific agent ID',
      },
      limit: {
        type: 'number',
        description: 'Maximum number of traces to return (default 50, max 100)',
        minimum: 1,
        maximum: 100,
      },
      outcome_status: {
        type: 'string',
        enum: ['pending', 'completed', 'blocked', 'error'],
        description: 'Optional filter by outcome status',
      },
    },
    required: [],
  },
};

export async function getTraces(
  apiClient: ApiClient,
  input: GetTracesInput
): Promise<GetTracesResult> {
  const now = new Date().toISOString();

  try {
    const params: Record<string, unknown> = {};
    if (input.agent_id) params.agent_id = input.agent_id;
    if (input.limit) params.limit = Math.min(input.limit, 100);
    if (input.outcome_status) params.outcome_status = input.outcome_status;

    const response = await apiClient.get<GetTracesResult>(
      '/api/v1/mcp/traces',
      params
    );

    if (!response.success || !response.data) {
      return {
        traces: [],
        count: 0,
        has_more: false,
        queried_at: now,
        entry_point: 'mcp',
        error: response.error || 'Failed to get traces',
      };
    }

    return {
      ...response.data,
      entry_point: 'mcp',
    };
  } catch (error) {
    return {
      traces: [],
      count: 0,
      has_more: false,
      queried_at: now,
      entry_point: 'mcp',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
