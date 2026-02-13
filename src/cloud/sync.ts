/**
 * TrustScope Cloud Sync Manager
 *
 * Background queue with exponential backoff for cloud trace sync.
 */

import { getCredentials } from '../auth/index.js';
import { redactPII, redactSecrets } from '../mcp/tools/redaction.js';
import { TraceQueue } from './queue.js';

const API_BASE_URL = process.env.TRUSTSCOPE_API_URL || 'https://api.trustscope.ai';

export interface SyncStats {
  queued: number;
  synced: number;
  failed: number;
  lastSyncAt: string | null;
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
 * Check if an error is retryable
 */
function isRetryableError(error: unknown): boolean {
  if (error instanceof Error) {
    // Network errors
    if (error.message.includes('fetch') || error.message.includes('ECONNREFUSED')) {
      return true;
    }
  }
  return false;
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
 * Cloud Sync Manager
 *
 * Manages async trace upload to TrustScope cloud with:
 * - Fire-and-forget enqueueing
 * - Background processing
 * - Exponential backoff on failures
 * - PII redaction before sync
 */
export class CloudSyncManager {
  private queue: TraceQueue;
  private processing = false;
  private retryDelay = 1000; // Start at 1s
  private maxRetryDelay = 60000; // Cap at 60s
  private syncedCount = 0;
  private lastSyncAt: string | null = null;

  constructor() {
    this.queue = new TraceQueue();
  }

  /**
   * Enqueue a trace for cloud sync (fire and forget)
   */
  enqueue(trace: Record<string, unknown>): void {
    // Redact PII before queueing (raw PII never leaves local)
    const redacted = redactTrace(trace);
    this.queue.add(redacted);

    // Trigger async processing
    if (!this.processing) {
      this.processQueue().catch(() => {
        // Silently fail - traces stay in queue for retry
      });
    }
  }

  /**
   * Process the sync queue
   */
  async processQueue(): Promise<void> {
    if (this.processing) return;
    this.processing = true;

    const credentials = getCredentials();
    if (!credentials) {
      // Not connected to cloud - skip sync
      this.processing = false;
      return;
    }

    // Reset any failed traces that are ready for retry
    this.queue.resetFailed();

    try {
      while (this.queue.size() > 0) {
        const batch = this.queue.peek(100);
        if (batch.length === 0) break;

        const ids = batch.map(b => b.id);
        const traces = batch.map(b => b.trace);

        try {
          // Send traces individually to POST /api/v1/traces/
          // API expects TraceCreateRequest format
          for (const trace of traces) {
            const apiTrace = transformTraceForAPI(trace);
            await fetch(`${API_BASE_URL}/api/v1/traces/`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${credentials.accessToken}`,
              },
              body: JSON.stringify(apiTrace),
            });
          }

          // Treat batch as successful if we got here
          const response = { ok: true, status: 200 } as Response;

          if (response.ok) {
            // Success - remove from queue
            this.queue.remove(ids);
            this.syncedCount += traces.length;
            this.lastSyncAt = new Date().toISOString();
            this.retryDelay = 1000; // Reset backoff on success
          } else if (response.status === 401 || response.status === 403) {
            // Auth error - don't retry
            this.processing = false;
            return;
          } else if (response.status >= 500) {
            // Server error - mark for retry with backoff
            this.queue.markFailed(ids);
            await this.sleep(this.retryDelay);
            this.retryDelay = Math.min(this.retryDelay * 2, this.maxRetryDelay);
          } else {
            // Other error (4xx) - don't retry
            this.queue.remove(ids);
          }
        } catch (error) {
          if (isRetryableError(error)) {
            // Network error - mark for retry with backoff
            this.queue.markFailed(ids);
            await this.sleep(this.retryDelay);
            this.retryDelay = Math.min(this.retryDelay * 2, this.maxRetryDelay);
          } else {
            // Unknown error - remove to prevent infinite loop
            this.queue.remove(ids);
          }
        }
      }
    } finally {
      this.processing = false;
    }
  }

  /**
   * Get sync statistics
   */
  getStats(): SyncStats {
    return {
      queued: this.queue.size(),
      synced: this.syncedCount,
      failed: this.queue.failedCount(),
      lastSyncAt: this.lastSyncAt,
    };
  }

  /**
   * Check if sync is enabled (user is logged in)
   */
  isEnabled(): boolean {
    return getCredentials() !== null;
  }

  /**
   * Force immediate sync (for manual trigger)
   */
  async forceSync(): Promise<void> {
    // Reset failed traces
    this.queue.resetFailed(Infinity);
    // Process queue
    await this.processQueue();
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Singleton instance for fire-and-forget usage
let _cloudSyncInstance: CloudSyncManager | null = null;

export function getCloudSync(): CloudSyncManager {
  if (!_cloudSyncInstance) {
    _cloudSyncInstance = new CloudSyncManager();
  }
  return _cloudSyncInstance;
}

/**
 * Enqueue a trace for cloud sync (convenience function)
 */
export function enqueueForSync(trace: Record<string, unknown>): void {
  getCloudSync().enqueue(trace);
}
