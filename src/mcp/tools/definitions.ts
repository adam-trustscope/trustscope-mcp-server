/**
 * MCP Tool Definitions
 *
 * 11 tools for TrustScope governance
 */

import type { ToolDefinition } from '../types.js';

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  // Core governance tools
  {
    name: 'trustscope_check_policy',
    description:
      'Check content or action against TrustScope policies. Returns policy decision (allow/alert/block) and any detected issues. Use before executing actions.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Unique identifier for the agent making the request',
        },
        session_id: {
          type: 'string',
          description: 'Session identifier for tracking related actions',
        },
        action_type: {
          type: 'string',
          description: 'Type of action being performed (e.g., "file_write", "api_call")',
        },
        tool_name: {
          type: 'string',
          description: 'Name of the tool being invoked',
        },
        tool_args: {
          type: 'object',
          description: 'Arguments being passed to the tool',
        },
        content: {
          type: 'string',
          description: 'Content to check against policies',
        },
      },
      required: ['agent_id', 'action_type'],
    },
  },
  {
    name: 'trustscope_check_detection',
    description:
      'Run detection engines against content. Returns detection results from 18 engines (PII, secrets, injection, etc.).',
    inputSchema: {
      type: 'object',
      properties: {
        content: {
          type: 'string',
          description: 'Content to scan with detection engines',
        },
        context: {
          type: 'object',
          description: 'Optional context information',
          properties: {
            agent_id: { type: 'string' },
            session_id: { type: 'string' },
            action_type: { type: 'string' },
            tool_name: { type: 'string' },
            direction: { type: 'string', enum: ['input', 'output'] },
          },
        },
        engines: {
          type: 'array',
          items: { type: 'string' },
          description: 'Specific engines to run (defaults to all)',
        },
      },
      required: ['content'],
    },
  },
  {
    name: 'trustscope_log_action',
    description:
      'Log an action to the evidence store. Creates an auditable trace with hash chain integrity.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Agent that performed the action',
        },
        session_id: {
          type: 'string',
          description: 'Session identifier',
        },
        action_type: {
          type: 'string',
          description: 'Type of action performed',
        },
        tool_name: {
          type: 'string',
          description: 'Tool that was invoked',
        },
        request_summary: {
          type: 'string',
          description: 'Summary of the request',
        },
        response_summary: {
          type: 'string',
          description: 'Summary of the response',
        },
        blocked: {
          type: 'boolean',
          description: 'Whether the action was blocked',
        },
        simulated: {
          type: 'boolean',
          description: 'Whether this was a simulation/dry-run',
        },
        metadata: {
          type: 'object',
          description: 'Additional metadata to store',
        },
      },
      required: ['agent_id', 'action_type'],
    },
  },
  {
    name: 'trustscope_list_traces',
    description: 'List action traces from the evidence store with optional filters.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Filter by agent ID',
        },
        session_id: {
          type: 'string',
          description: 'Filter by session ID',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of traces to return (default: 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination',
        },
        blocked_only: {
          type: 'boolean',
          description: 'Only return blocked traces',
        },
      },
    },
  },
  {
    name: 'trustscope_list_policies',
    description: 'List configured policies and their settings.',
    inputSchema: {
      type: 'object',
      properties: {
        engine: {
          type: 'string',
          description: 'Filter by specific engine name',
        },
      },
    },
  },
  {
    name: 'trustscope_list_approvals',
    description: 'List pending or historical approval requests.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Filter by agent ID',
        },
        status: {
          type: 'string',
          enum: ['pending', 'approved', 'rejected'],
          description: 'Filter by approval status',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of approvals to return',
        },
      },
    },
  },
  {
    name: 'trustscope_approve',
    description: 'Approve or reject a pending action.',
    inputSchema: {
      type: 'object',
      properties: {
        approval_id: {
          type: 'string',
          description: 'ID of the approval request',
        },
        approved: {
          type: 'boolean',
          description: 'Whether to approve (true) or reject (false)',
        },
        reason: {
          type: 'string',
          description: 'Reason for the decision',
        },
      },
      required: ['approval_id', 'approved'],
    },
  },
  {
    name: 'trustscope_get_agent_dna',
    description:
      'Get Agent DNA profile - behavioral fingerprint computed from action history.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Agent ID to get DNA for',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'trustscope_get_compliance',
    description:
      'Get compliance status including evidence chain integrity and detection summary.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Filter by agent ID',
        },
        session_id: {
          type: 'string',
          description: 'Filter by session ID',
        },
      },
    },
  },
  {
    name: 'trustscope_explain_behavior',
    description:
      'Statistical analysis of agent behavior: z-scores, tool patterns, risk scoring.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Agent ID to analyze',
        },
        session_id: {
          type: 'string',
          description: 'Optional session ID to focus analysis',
        },
        window_hours: {
          type: 'number',
          description: 'Analysis window in hours (default: 24)',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'trustscope_get_attestation',
    description:
      'Generate an unsigned attestation from the evidence chain for external verification.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Agent ID to generate attestation for',
        },
        window_start: {
          type: 'string',
          description: 'Start of attestation window (ISO 8601)',
        },
        window_end: {
          type: 'string',
          description: 'End of attestation window (ISO 8601)',
        },
      },
      required: ['agent_id'],
    },
  },
];

/**
 * Get all tool names
 */
export function getToolNames(): string[] {
  return TOOL_DEFINITIONS.map((d) => d.name);
}

/**
 * Get a tool definition by name
 */
export function getToolDefinition(name: string): ToolDefinition | undefined {
  return TOOL_DEFINITIONS.find((d) => d.name === name);
}
