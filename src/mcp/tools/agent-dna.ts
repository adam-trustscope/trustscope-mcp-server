import type { ApiClient } from '../../utils/api-client.js';
import type { GetAgentDNAInput, GetAgentDNAResult } from '../../types/mcp.js';

export const getAgentDNADefinition = {
  name: 'trustscope_get_agent_dna',
  description: 'Get the behavioral fingerprint (Agent DNA) for an AI agent. Used for identity verification and behavioral drift detection.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      agent_id: {
        type: 'string',
        description: 'The unique identifier of the AI agent',
      },
    },
    required: ['agent_id'],
  },
};

export async function getAgentDNA(
  apiClient: ApiClient,
  input: GetAgentDNAInput
): Promise<GetAgentDNAResult> {
  const now = new Date().toISOString();

  try {
    const response = await apiClient.get<GetAgentDNAResult>(
      `/api/v1/mcp/agents/${input.agent_id}/dna`
    );

    if (!response.success || !response.data) {
      return {
        agent_id: input.agent_id,
        fingerprint: '',
        strands: {
          model: '',
          tools: [],
          system_prompt_hash: '',
          temperature: 0,
          behavioral: {},
        },
        drift_detected: false,
        drift_score: 0,
        drift_details: [],
        baseline_established: false,
        last_updated: now,
        entry_point: 'mcp',
        error: response.error || 'Failed to get agent DNA',
      };
    }

    return {
      ...response.data,
      entry_point: 'mcp',
    };
  } catch (error) {
    return {
      agent_id: input.agent_id,
      fingerprint: '',
      strands: {
        model: '',
        tools: [],
        system_prompt_hash: '',
        temperature: 0,
        behavioral: {},
      },
      drift_detected: false,
      drift_score: 0,
      drift_details: [],
      baseline_established: false,
      last_updated: now,
      entry_point: 'mcp',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
