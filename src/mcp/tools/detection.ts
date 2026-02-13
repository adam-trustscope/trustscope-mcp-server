import type { ApiClient } from '../../utils/api-client.js';
import type { RunDetectionInput, RunDetectionResult } from '../../types/mcp.js';

export const runDetectionDefinition = {
  name: 'trustscope_run_detection',
  description: 'Run security detection engines on content. Detects prompt injection, PII, secrets, dangerous commands, and jailbreak attempts.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      detection_type: {
        type: 'string',
        enum: ['prompt_injection', 'pii', 'secrets', 'dangerous_commands', 'jailbreak'],
        description: 'Type of detection to run: prompt_injection (40+ patterns), pii (88 patterns), secrets (50+ patterns), dangerous_commands (55+ patterns), jailbreak (30+ patterns)',
      },
      content: {
        type: 'string',
        description: 'The content to analyze',
      },
      agent_id: {
        type: 'string',
        description: 'Optional agent ID for context-aware detection',
      },
    },
    required: ['detection_type', 'content'],
  },
};

export async function runDetection(
  apiClient: ApiClient,
  input: RunDetectionInput
): Promise<RunDetectionResult> {
  const now = new Date().toISOString();

  try {
    const response = await apiClient.post<RunDetectionInput, RunDetectionResult>(
      '/api/v1/mcp/detection',
      input
    );

    if (!response.success || !response.data) {
      return {
        detection_type: input.detection_type,
        triggered: false,
        blocked: false,
        confidence: 0,
        severity: 'info',
        matches: [],
        message: response.error || 'Detection failed',
        analyzed_at: now,
        entry_point: 'mcp',
        error: response.error || 'Failed to run detection',
      };
    }

    return {
      ...response.data,
      entry_point: 'mcp',
    };
  } catch (error) {
    return {
      detection_type: input.detection_type,
      triggered: false,
      blocked: false,
      confidence: 0,
      severity: 'info',
      matches: [],
      message: 'Detection error',
      analyzed_at: now,
      entry_point: 'mcp',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
