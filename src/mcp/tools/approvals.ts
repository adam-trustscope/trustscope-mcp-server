import type { ApiClient } from '../../utils/api-client.js';
import type {
  CreateApprovalInput,
  CreateApprovalResult,
  GetApprovalsInput,
  GetApprovalsResult,
} from '../../types/mcp.js';

export const createApprovalDefinition = {
  name: 'trustscope_create_approval',
  description: 'Request human approval for a sensitive AI agent action. The action will be paused until approved or rejected by an authorized human.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      agent_id: {
        type: 'string',
        description: 'The unique identifier of the AI agent',
      },
      action_type: {
        type: 'string',
        description: 'The type of action requiring approval',
      },
      parameters: {
        type: 'object',
        description: 'Optional parameters for the action',
      },
      context: {
        type: 'string',
        description: 'Optional human-readable context explaining why approval is needed',
      },
      expires_in_hours: {
        type: 'number',
        description: 'Hours until the approval request expires (default 24)',
        minimum: 1,
        maximum: 168,
      },
    },
    required: ['agent_id', 'action_type'],
  },
};

export const getApprovalsDefinition = {
  name: 'trustscope_get_approvals',
  description: 'Check the status of human approval requests. Use to poll for approval decisions.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      status: {
        type: 'string',
        enum: ['pending', 'approved', 'rejected'],
        description: 'Filter by approval status (default "pending")',
      },
      agent_id: {
        type: 'string',
        description: 'Optional filter by specific agent ID',
      },
    },
    required: [],
  },
};

export async function createApproval(
  apiClient: ApiClient,
  input: CreateApprovalInput
): Promise<CreateApprovalResult> {
  const now = new Date().toISOString();

  try {
    const response = await apiClient.post<CreateApprovalResult>(
      '/api/v1/mcp/approvals',
      {
        ...input,
        expires_in_hours: input.expires_in_hours ?? 24,
      }
    );

    if (!response.success || !response.data) {
      return {
        id: '',
        status: 'pending',
        agent_id: input.agent_id,
        action_type: input.action_type,
        parameters: input.parameters,
        context: input.context,
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        created_at: now,
        entry_point: 'mcp',
        error: response.error || 'Failed to create approval request',
      };
    }

    return {
      ...response.data,
      entry_point: 'mcp',
    };
  } catch (error) {
    return {
      id: '',
      status: 'pending',
      agent_id: input.agent_id,
      action_type: input.action_type,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      created_at: now,
      entry_point: 'mcp',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

export async function getApprovals(
  apiClient: ApiClient,
  input: GetApprovalsInput
): Promise<GetApprovalsResult> {
  const now = new Date().toISOString();

  try {
    const params: Record<string, unknown> = {
      status: input.status ?? 'pending',
    };
    if (input.agent_id) params.agent_id = input.agent_id;

    const response = await apiClient.get<GetApprovalsResult>(
      '/api/v1/mcp/approvals',
      params
    );

    if (!response.success || !response.data) {
      return {
        requests: [],
        count: 0,
        status_filter: input.status ?? 'pending',
        queried_at: now,
        entry_point: 'mcp',
        error: response.error || 'Failed to get approvals',
      };
    }

    return {
      ...response.data,
      entry_point: 'mcp',
    };
  } catch (error) {
    return {
      requests: [],
      count: 0,
      status_filter: input.status ?? 'pending',
      queried_at: now,
      entry_point: 'mcp',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
