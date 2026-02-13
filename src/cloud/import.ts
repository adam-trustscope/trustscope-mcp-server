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
      const response = await fetch(`${API_BASE_URL}/api/v1/traces/batch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${credentials.accessToken}`,
        },
        body: JSON.stringify({ traces: redactedTraces }),
      });

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
