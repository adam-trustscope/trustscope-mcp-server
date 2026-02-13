/**
 * TrustScope Cloud Import
 *
 * Batch import local traces to cloud with PII redaction.
 */

import chalk from 'chalk';
import { getCredentials } from '../auth/index.js';
import { EvidenceStore } from '../evidence/store.js';
import { redactPII, redactSecrets } from '../mcp/tools/redaction.js';

const API_BASE_URL = process.env.TRUSTSCOPE_API_URL || 'https://api.trustscope.ai';

export interface ImportOptions {
  batchSize?: number;
  verbose?: boolean;
}

export interface ImportResult {
  imported: number;
  failed: number;
  skipped: number;
}

/**
 * Transform local trace format to API TraceCreateRequest format
 */
function transformTraceForAPI(trace: Record<string, unknown>): Record<string, unknown> {
  return {
    agent_id: (trace.agent_id as string) || 'unknown',
    source: (trace.source as string) || 'mcp',
    session_id: trace.session_id as string | undefined,
    timestamp: trace.timestamp as string | undefined,
    trigger: {
      type: (trace.action_type as string) || 'action',
      tool_name: trace.tool_name as string | undefined,
    },
    action: {
      type: (trace.action_type as string) || 'action',
      tool_name: trace.tool_name as string | undefined,
      input: trace.request_summary as string | undefined,
    },
    outcome: {
      status: trace.blocked ? 'blocked' : 'success',
      output: trace.response_summary as string | undefined,
      detections: trace.detection_results as unknown[] | undefined,
    },
    policies_checked: trace.policies_checked as unknown[] | undefined,
  };
}

/**
 * Redact sensitive data from a trace before cloud sync
 */
function redactTrace(trace: Record<string, unknown>): Record<string, unknown> {
  const redacted = { ...trace };

  // Redact PII and secrets from summary fields
  if (typeof redacted.request_summary === 'string') {
    const piiRedacted = redactPII(redacted.request_summary);
    const secretsRedacted = redactSecrets(piiRedacted.content);
    redacted.request_summary = secretsRedacted.content;
  }
  if (typeof redacted.response_summary === 'string') {
    const piiRedacted = redactPII(redacted.response_summary);
    const secretsRedacted = redactSecrets(piiRedacted.content);
    redacted.response_summary = secretsRedacted.content;
  }

  // Never send raw request/response bodies
  delete redacted.request_body;
  delete redacted.response_body;

  return redacted;
}

/**
 * Import local traces to TrustScope cloud
 */
export async function importTracesToCloud(options?: ImportOptions): Promise<ImportResult> {
  const batchSize = options?.batchSize ?? 100;
  const verbose = options?.verbose ?? false;

  const credentials = getCredentials();
  if (!credentials) {
    throw new Error('Not logged in. Run "trustscope login" first.');
  }

  const store = new EvidenceStore();
  store.init();

  const result: ImportResult = {
    imported: 0,
    failed: 0,
    skipped: 0,
  };

  let offset = 0;

  while (true) {
    // Get batch of traces
    const traces = store.listTraces({ limit: batchSize, offset });
    if (traces.length === 0) break;

    // Redact PII before sending
    const redactedTraces = traces.map(t => redactTrace(t as unknown as Record<string, unknown>));

    try {
      // Send traces individually to POST /api/v1/traces/
      let batchSuccess = true;
      for (const trace of redactedTraces) {
        const apiTrace = transformTraceForAPI(trace);
        const traceResponse = await fetch(`${API_BASE_URL}/api/v1/traces/`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${credentials.accessToken}`,
          },
          body: JSON.stringify(apiTrace),
        });
        if (!traceResponse.ok) {
          batchSuccess = false;
        }
      }
      const response = { ok: batchSuccess, status: batchSuccess ? 200 : 500 } as Response;

      if (response.ok) {
        result.imported += traces.length;
        if (verbose) {
          console.log(chalk.dim(`  Imported ${result.imported} traces...`));
        }
      } else if (response.status === 409) {
        // Conflict - traces already exist
        result.skipped += traces.length;
        if (verbose) {
          console.log(chalk.dim(`  Skipped ${traces.length} existing traces...`));
        }
      } else {
        result.failed += traces.length;
        if (verbose) {
          console.log(chalk.yellow(`  Failed to import batch: ${response.status}`));
        }
      }
    } catch (error) {
      result.failed += traces.length;
      if (verbose) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        console.log(chalk.yellow(`  Import error: ${message}`));
      }
    }

    offset += batchSize;
  }

  return result;
}

/**
 * Count local traces that haven't been synced
 */
export function countLocalTraces(): number {
  try {
    const store = new EvidenceStore();
    store.init();
    const stats = store.getChainStats();
    return stats.total_traces;
  } catch {
    return 0;
  }
}
