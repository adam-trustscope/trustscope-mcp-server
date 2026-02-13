import type { ApiClient } from '../../utils/api-client.js';
import type { ComplianceStatusInput, ComplianceStatusResult } from '../../types/mcp.js';

export const complianceStatusDefinition = {
  name: 'trustscope_compliance_status',
  description: 'Check compliance status against regulatory frameworks. Supports NIST AI RMF, EU AI Act, SOC2, ISO42001, and HIPAA.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      framework: {
        type: 'string',
        enum: ['NIST_AI_RMF', 'EU_AI_ACT', 'SOC2', 'ISO42001', 'HIPAA'],
        description: 'The compliance framework to check against',
      },
      agent_id: {
        type: 'string',
        description: 'Optional agent ID for agent-specific compliance check',
      },
    },
    required: ['framework'],
  },
};

const FRAMEWORK_NAMES: Record<string, string> = {
  NIST_AI_RMF: 'NIST AI Risk Management Framework',
  EU_AI_ACT: 'EU AI Act',
  SOC2: 'SOC 2 Type II',
  ISO42001: 'ISO/IEC 42001 AI Management System',
  HIPAA: 'Health Insurance Portability and Accountability Act',
};

export async function complianceStatus(
  apiClient: ApiClient,
  input: ComplianceStatusInput
): Promise<ComplianceStatusResult> {
  const now = new Date().toISOString();

  try {
    const params: Record<string, unknown> = {
      framework: input.framework,
    };
    if (input.agent_id) params.agent_id = input.agent_id;

    const response = await apiClient.get<ComplianceStatusResult>(
      '/api/v1/mcp/compliance',
      params
    );

    if (!response.success || !response.data) {
      return {
        framework: input.framework,
        framework_name: FRAMEWORK_NAMES[input.framework] || input.framework,
        overall_coverage_percent: 0,
        overall_status: 'non_compliant',
        categories: [],
        agent_specific: !!input.agent_id,
        agent_id: input.agent_id,
        recommendations: ['Unable to fetch compliance data. Please try again.'],
        checked_at: now,
        entry_point: 'mcp',
        error: response.error || 'Failed to get compliance status',
      };
    }

    return {
      ...response.data,
      framework_name: FRAMEWORK_NAMES[input.framework] || input.framework,
      entry_point: 'mcp',
    };
  } catch (error) {
    return {
      framework: input.framework,
      framework_name: FRAMEWORK_NAMES[input.framework] || input.framework,
      overall_coverage_percent: 0,
      overall_status: 'non_compliant',
      categories: [],
      agent_specific: !!input.agent_id,
      agent_id: input.agent_id,
      recommendations: ['Unable to fetch compliance data. Please try again.'],
      checked_at: now,
      entry_point: 'mcp',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
