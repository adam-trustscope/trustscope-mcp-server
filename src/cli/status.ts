/**
 * TrustScope Status Command
 *
 * Shows current state: mode, evidence, chain integrity, discovered agents, etc.
 */

import chalk from 'chalk';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { EvidenceStore } from '../evidence/store.js';
import { loadConfig } from '../config/index.js';
import { getEngineNames } from '../detection/index.js';

export interface StatusOptions {
  verbose?: boolean;
}

/**
 * Format relative time
 */
function formatRelativeTime(timestamp: string): string {
  const date = new Date(timestamp);
  const now = Date.now();
  const diff = now - date.getTime();

  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return 'just now';
}

/**
 * Check if MCP server is running
 */
function checkMCPRunning(): { running: boolean; pid?: number } {
  // Check for common MCP process indicators
  // In a real implementation, this would check for actual process
  // For now, we check if stdio is connected to MCP
  return { running: false };
}

/**
 * Check if watch mode is running
 */
function checkWatchRunning(): { running: boolean; port?: number; pid?: number } {
  // Check for watch process
  return { running: false };
}

/**
 * Show current TrustScope state
 */
export async function runStatus(options?: StatusOptions): Promise<void> {
  const verbose = options?.verbose || false;

  // Load configuration
  const config = loadConfig();
  const mode = config.apiKey ? 'connected' : 'local';

  // Check evidence store
  const dbPath = join(process.cwd(), '.trustscope', 'evidence.db');
  const hasEvidence = existsSync(dbPath);

  let traceCount = 0;
  let blockedCount = 0;
  let agentIds: string[] = [];
  let chainValid = true;
  let chainBrokenAt: string | undefined;
  let lastTrace: string | undefined;
  let lastVerified: string | undefined;

  if (hasEvidence) {
    try {
      const store = new EvidenceStore();
      const traces = store.listTraces({ limit: 10000 });
      traceCount = traces.length;
      blockedCount = traces.filter((t) => t.blocked === 1).length;

      // Get unique agent IDs
      const uniqueAgents = new Set<string>();
      for (const trace of traces) {
        if (trace.agent_id) {
          uniqueAgents.add(trace.agent_id as string);
        }
      }
      agentIds = Array.from(uniqueAgents);

      // Get last trace timestamp
      if (traces.length > 0) {
        lastTrace = traces[0]?.timestamp as string;
      }

      // Verify chain
      const chainStatus = store.verifyChain();
      chainValid = chainStatus.valid;
      chainBrokenAt = chainStatus.broken_at;
      lastVerified = new Date().toISOString();
    } catch {
      // Evidence store exists but failed to read
    }
  }

  // Check running processes
  const mcpStatus = checkMCPRunning();
  const watchStatus = checkWatchRunning();

  // Get detection engine count
  const engineCount = getEngineNames().length;

  // Output status
  console.log('');
  console.log(chalk.bold('  TrustScope Status'));
  console.log(chalk.dim('  ─────────────────'));
  console.log('');

  // Mode
  if (mode === 'connected') {
    console.log(`  Mode:        ${chalk.green('connected')} (account linked)`);
  } else {
    console.log(`  Mode:        ${chalk.yellow('local')} (no account)`);
  }

  // Evidence
  if (hasEvidence && traceCount > 0) {
    const blockedPct = traceCount > 0 ? Math.round((blockedCount / traceCount) * 100) : 0;
    console.log(
      `  Evidence:    ${chalk.cyan(traceCount.toLocaleString())} traces in .trustscope/evidence.db` +
        (blockedCount > 0 ? chalk.dim(` (${blockedCount} blocked, ${blockedPct}%)`) : ''),
    );
  } else if (hasEvidence) {
    console.log(`  Evidence:    ${chalk.dim('0 traces')} in .trustscope/evidence.db`);
  } else {
    console.log(`  Evidence:    ${chalk.dim('not initialized')}`);
  }

  // Chain
  if (hasEvidence && traceCount > 0) {
    if (chainValid) {
      const verifiedAgo = lastVerified ? formatRelativeTime(lastVerified) : 'never';
      console.log(`  Chain:       ${chalk.green('intact')} (last verified ${verifiedAgo})`);
    } else {
      console.log(
        `  Chain:       ${chalk.red('BROKEN')} at ${chainBrokenAt || 'unknown position'}`,
      );
    }
  } else {
    console.log(`  Chain:       ${chalk.dim('not initialized')}`);
  }

  // Agents
  if (agentIds.length > 0) {
    const agentList =
      agentIds.length <= 3
        ? agentIds.join(', ')
        : `${agentIds.slice(0, 3).join(', ')} +${agentIds.length - 3} more`;
    console.log(`  Agents:      ${chalk.cyan(agentIds.length)} discovered (${agentList})`);
  } else {
    console.log(`  Agents:      ${chalk.dim('none discovered')}`);
  }

  // MCP Server
  if (mcpStatus.running) {
    console.log(
      `  MCP:         ${chalk.green('running')} (pid ${mcpStatus.pid}, 11 tools)`,
    );
  } else {
    console.log(`  MCP:         ${chalk.dim('not running')}`);
  }

  // Watch Mode
  if (watchStatus.running) {
    console.log(
      `  Watch:       ${chalk.green('running')} on port ${watchStatus.port} (pid ${watchStatus.pid})`,
    );
  } else {
    console.log(`  Watch:       ${chalk.dim('not running')}`);
  }

  // Detection Engines
  console.log(`  Detections:  ${chalk.cyan(engineCount)} engines active`);

  console.log('');

  // Verbose output
  if (verbose && agentIds.length > 0) {
    console.log(chalk.bold('  Discovered Agents'));
    console.log(chalk.dim('  ─────────────────'));
    for (const agentId of agentIds) {
      console.log(`    - ${agentId}`);
    }
    console.log('');
  }

  if (verbose && hasEvidence) {
    console.log(chalk.bold('  Evidence Details'));
    console.log(chalk.dim('  ────────────────'));
    console.log(`    Database:     ${dbPath}`);
    console.log(`    Total traces: ${traceCount}`);
    console.log(`    Blocked:      ${blockedCount}`);
    console.log(`    Unique agents: ${agentIds.length}`);
    if (lastTrace) {
      console.log(`    Last activity: ${formatRelativeTime(lastTrace)}`);
    }
    console.log('');
  }

  // Hint for connecting
  if (mode === 'local') {
    console.log(chalk.dim('  ℹ Run trustscope connect for dashboard + team features'));
    console.log('');
  }
}
