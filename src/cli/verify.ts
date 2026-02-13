/**
 * TrustScope Verify Command
 *
 * Verifies evidence chain integrity using SHA-256 hash chain.
 * Optionally verifies Ed25519 attestation signatures.
 */

import chalk from 'chalk';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { EvidenceStore } from '../evidence/store.js';
import { verifyAttestation, getPublicKey } from '../crypto/signing.js';

export interface VerifyOptions {
  verbose?: boolean;
  quick?: boolean;
  signature?: string;  // Attestation JSON file to verify signature
}

/**
 * Verify attestation signature
 */
async function verifySignature(attestationFile: string, verbose: boolean): Promise<void> {
  console.log('');
  console.log(chalk.bold('  Attestation Signature Verification'));
  console.log(chalk.dim('  ────────────────────────────────────'));
  console.log('');

  if (!existsSync(attestationFile)) {
    console.log(`  ${chalk.red('✗')} Attestation file not found: ${attestationFile}`);
    console.log('');
    process.exit(1);
    return;
  }

  try {
    const content = readFileSync(attestationFile, 'utf-8');
    const attestation = JSON.parse(content) as Record<string, unknown>;

    if (!attestation.signed) {
      console.log(`  ${chalk.yellow('⚠')} Attestation is not signed`);
      console.log(chalk.dim('  Use sign:true when calling trustscope_get_attestation to request a signature.'));
      console.log('');
      process.exit(0);
      return;
    }

    const signature = attestation.signature as string;
    const publicKey = attestation.public_key as string;
    const claims = attestation.claims as Record<string, unknown>;

    if (!signature || !publicKey || !claims) {
      console.log(`  ${chalk.red('✗')} Invalid attestation format - missing signature, public_key, or claims`);
      console.log('');
      process.exit(1);
      return;
    }

    console.log(chalk.dim(`  Attestation ID: ${attestation.id}`));
    console.log(chalk.dim(`  Agent ID: ${attestation.agent_id}`));
    console.log(chalk.dim(`  Public Key: ${publicKey.substring(0, 32)}...`));
    console.log('');

    const isValid = verifyAttestation(claims, signature, publicKey);

    if (isValid) {
      console.log(`  ${chalk.green('✓')} Signature is VALID`);

      // Check if public key matches local key
      const localPubKey = getPublicKey();
      if (localPubKey === publicKey) {
        console.log(`  ${chalk.green('✓')} Public key matches local signing key`);
      } else if (localPubKey) {
        console.log(`  ${chalk.yellow('⚠')} Public key differs from local signing key`);
        console.log(chalk.dim('    Attestation may have been signed on a different machine.'));
      }

      console.log('');

      if (verbose) {
        console.log(chalk.bold('  Claims'));
        console.log(chalk.dim('  ──────'));
        for (const [key, value] of Object.entries(claims)) {
          console.log(`    ${key}: ${JSON.stringify(value)}`);
        }
        console.log('');
      }

      process.exit(0);
    } else {
      console.log(`  ${chalk.red('✗')} Signature is INVALID`);
      console.log('');
      console.log(chalk.yellow('  Warning: The attestation signature does not match the claims.'));
      console.log(chalk.dim('  This may indicate the attestation has been tampered with.'));
      console.log('');
      process.exit(1);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log(`  ${chalk.red('✗')} Verification failed: ${message}`);
    console.log('');
    process.exit(1);
  }
}

/**
 * Verify evidence chain integrity
 */
export async function runVerify(options?: VerifyOptions): Promise<void> {
  const verbose = options?.verbose || false;
  const quick = options?.quick || false;

  // Sprint 3 TASK 9: Signature verification mode
  if (options?.signature) {
    await verifySignature(options.signature, verbose);
    return;
  }

  const dbPath = join(process.cwd(), '.trustscope', 'evidence.db');

  console.log('');
  console.log(chalk.bold('  Evidence Chain Verification'));
  console.log(chalk.dim('  ───────────────────────────'));
  console.log('');

  // Check if evidence store exists
  if (!existsSync(dbPath)) {
    console.log(`  ${chalk.yellow('⚠')}  No evidence store found at .trustscope/evidence.db`);
    console.log('');
    console.log(chalk.dim('  Run trustscope mcp or trustscope watch to start generating evidence.'));
    console.log('');
    process.exit(0);
    return;
  }

  try {
    const store = new EvidenceStore();
    const startTime = Date.now();

    // Get chain stats first
    const stats = store.getChainStats();

    if (stats.total_traces === 0) {
      console.log(`  ${chalk.yellow('⚠')}  Evidence store is empty`);
      console.log('');
      console.log(chalk.dim('  No traces to verify.'));
      console.log('');
      process.exit(0);
      return;
    }

    console.log(chalk.dim(`  Verifying ${stats.total_traces.toLocaleString()} traces...`));
    console.log('');

    // Verify the chain
    const limit = quick ? 100 : undefined;
    const result = store.verifyChain(limit);
    const duration = Date.now() - startTime;

    if (result.valid) {
      console.log(`  ${chalk.green('✓')} Chain integrity verified`);
      console.log(chalk.dim(`    Checked: ${result.checked.toLocaleString()} traces`));
      console.log(chalk.dim(`    Duration: ${duration}ms`));

      if (quick && stats.total_traces > 100) {
        console.log(chalk.dim(`    Note: Quick mode - only checked last ${limit} traces`));
      }

      console.log('');

      if (verbose) {
        console.log(chalk.bold('  Chain Details'));
        console.log(chalk.dim('  ─────────────'));
        console.log(`    Total traces:    ${stats.total_traces.toLocaleString()}`);
        console.log(`    First trace:     ${stats.first_trace_id || 'n/a'}`);
        console.log(`    Last trace:      ${stats.last_trace_id || 'n/a'}`);
        console.log(`    Latest hash:     ${stats.latest_hash?.substring(0, 32) || 'n/a'}...`);
        console.log('');
      }

      process.exit(0);
    } else {
      console.log(`  ${chalk.red('✗')} Chain integrity BROKEN`);
      console.log(chalk.red(`    Broken at: ${result.broken_at || 'unknown'}`));

      if (result.expected_hash && result.actual_hash) {
        console.log(chalk.dim(`    Expected: ${result.expected_hash.substring(0, 32)}...`));
        console.log(chalk.dim(`    Actual:   ${result.actual_hash.substring(0, 32)}...`));
      }

      console.log('');
      console.log(chalk.yellow('  Warning: Evidence chain has been tampered with or corrupted.'));
      console.log(chalk.dim('  This may indicate unauthorized modifications to the evidence store.'));
      console.log('');

      process.exit(1);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log(`  ${chalk.red('✗')} Verification failed: ${message}`);
    console.log('');
    process.exit(1);
  }
}
