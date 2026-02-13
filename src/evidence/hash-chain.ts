/**
 * SHA-256 Hash Chain Implementation
 *
 * Provides tamper-evident hash chain for evidence traces.
 *
 * Hash computation:
 *   audit_hash = SHA256(
 *     id + source + agent_id + action_type +
 *     request_summary + response_summary + timestamp +
 *     prev_hash
 *   )
 *
 * TODO: Implement full functionality (TASK 3)
 */

import { createHash } from 'node:crypto';
import type { Trace, ChainVerificationResult } from '../types/evidence.js';
import type { EvidenceStore } from './store.js';

export const GENESIS_HASH = 'genesis';

export interface HashableTrace {
  id: string;
  source: string;
  agent_id: string | null;
  action_type: string | null;
  request_summary: string | null;
  response_summary: string | null;
  timestamp: string;
  prev_hash: string;
}

/**
 * Compute the audit hash for a trace
 */
export function computeTraceHash(trace: HashableTrace): string {
  const canonical = [
    trace.id,
    trace.source,
    trace.agent_id || '',
    trace.action_type || '',
    trace.request_summary || '',
    trace.response_summary || '',
    trace.timestamp,
    trace.prev_hash,
  ].join('|');

  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Verify that a trace's hash is correct
 */
export function verifyTraceHash(trace: Trace): boolean {
  const expectedHash = computeTraceHash({
    id: trace.id,
    source: trace.source,
    agent_id: trace.agent_id,
    action_type: trace.action_type,
    request_summary: trace.request_summary,
    response_summary: trace.response_summary,
    timestamp: trace.timestamp,
    prev_hash: trace.prev_hash,
  });

  return expectedHash === trace.audit_hash;
}

/**
 * Verify the entire hash chain from the evidence store
 */
export function verifyChain(store: EvidenceStore): ChainVerificationResult {
  // TODO: Implement full chain verification (TASK 3)
  // For now, return a placeholder result

  const traces = store.listTraces({ limit: 1000 });

  if (traces.length === 0) {
    return {
      valid: true,
      checked: 0,
    };
  }

  let prevHash = GENESIS_HASH;

  for (let i = 0; i < traces.length; i++) {
    const trace = traces[i];

    // Check prev_hash links correctly
    if (trace.prev_hash !== prevHash) {
      return {
        valid: false,
        checked: i,
        broken_at: trace.id,
        expected_hash: prevHash,
        actual_hash: trace.prev_hash,
      };
    }

    // Check audit_hash is correct
    if (!verifyTraceHash(trace)) {
      return {
        valid: false,
        checked: i,
        broken_at: trace.id,
        expected_hash: computeTraceHash({
          id: trace.id,
          source: trace.source,
          agent_id: trace.agent_id,
          action_type: trace.action_type,
          request_summary: trace.request_summary,
          response_summary: trace.response_summary,
          timestamp: trace.timestamp,
          prev_hash: trace.prev_hash,
        }),
        actual_hash: trace.audit_hash,
      };
    }

    prevHash = trace.audit_hash;
  }

  return {
    valid: true,
    checked: traces.length,
  };
}

/**
 * Compute a Merkle root for a set of traces (for anchoring)
 */
export function computeMerkleRoot(hashes: string[]): string {
  if (hashes.length === 0) {
    return createHash('sha256').update('empty').digest('hex');
  }

  if (hashes.length === 1) {
    return hashes[0];
  }

  // Pad to even number if needed
  const paddedHashes = hashes.length % 2 === 1 ? [...hashes, hashes[hashes.length - 1]] : hashes;

  const nextLevel: string[] = [];
  for (let i = 0; i < paddedHashes.length; i += 2) {
    const combined = paddedHashes[i] + paddedHashes[i + 1];
    nextLevel.push(createHash('sha256').update(combined).digest('hex'));
  }

  return computeMerkleRoot(nextLevel);
}
