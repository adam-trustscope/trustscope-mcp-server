import type { ApiClient } from '../../utils/api-client.js';
import type { LogActionInput, LogActionResult } from '../../types/mcp.js';

export const logActionDefinition = {
  name: 'trustscope_log_action',
  description: 'Log an AI agent action to the immutable audit trail with cryptographic hash chain proof. Used for compliance and governance tracking.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      agent_id: {
        type: 'string',
        description: 'The unique identifier of the AI agent',
      },
      action: {
        type: 'string',
        description: 'The action type performed (e.g., "llm_call", "tool_use", "file_write")',
      },
      result: {
        type: 'string',
        enum: ['success', 'failure', 'blocked'],
        description: 'The outcome of the action',
      },
      tool: {
        type: 'string',
        description: 'Optional name of the tool used',
      },
      input_data: {
        type: 'object',
        description: 'Optional input data (will be hashed for privacy)',
      },
      output_data: {
        type: 'object',
        description: 'Optional output data (will be hashed for privacy)',
      },
      session_id: {
        type: 'string',
        description: 'Optional session identifier for grouping related actions',
      },
    },
    required: ['agent_id', 'action', 'result'],
  },
};

export async function logAction(
  apiClient: ApiClient,
  input: LogActionInput
): Promise<LogActionResult> {
  const now = new Date().toISOString();

  try {
    const response = await apiClient.post<LogActionResult>(
      '/api/v1/mcp/log-action',
      input
    );

    if (!response.success || !response.data) {
      return {
        event_id: '',
        hash: '',
        chain_position: -1,
        prev_hash: '',
        bitcoin_anchor_pending: false,
        logged_at: now,
        entry_point: 'mcp',
        error: response.error || 'Failed to log action',
      };
    }

    return {
      ...response.data,
      entry_point: 'mcp',
    };
  } catch (error) {
    return {
      event_id: '',
      hash: '',
      chain_position: -1,
      prev_hash: '',
      bitcoin_anchor_pending: false,
      logged_at: now,
      entry_point: 'mcp',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
