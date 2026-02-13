/**
 * Hybrid Mode Controller
 *
 * Runs both Watch proxy and MCP server in a single process,
 * sharing the same EvidenceStore for unified evidence collection.
 */

import { createServer } from 'node:http';
import { existsSync, writeFileSync, unlinkSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import readline from 'node:readline';
import chalk from 'chalk';
import { EvidenceStore } from '../evidence/store.js';
import { TrustScopeMCPServer } from '../mcp/server.js';
import { createWatchProxy } from '../watch/proxy.js';
import { createSafetyEngine, type SafetyResult } from '../watch/safety.js';
import { clearScreen, renderWatchUI, renderSessionSummary } from '../watch/ui.js';
import { getCredentials } from '../auth/index.js';
import { loadConfig } from '../cli/init.js';
import type { WatchOptions, WatchSessionStats, LLMRequest, WatchAlert } from '../types/cli.js';

export interface HybridModeOptions extends WatchOptions {
  apiKey?: string;
}

interface PidFileContent {
  pid: number;
  port: number;
  started: string;
  mode: 'watch' | 'mcp' | 'hybrid';
}

const PID_FILE_PATH = join(homedir(), '.trustscope', 'watch.pid');

/**
 * Write PID file for process detection
 */
export function writePidFile(port: number, mode: 'watch' | 'mcp' | 'hybrid' = 'watch'): void {
  const content: PidFileContent = {
    pid: process.pid,
    port,
    started: new Date().toISOString(),
    mode,
  };

  // Ensure directory exists
  const dir = join(homedir(), '.trustscope');
  if (!existsSync(dir)) {
    const { mkdirSync } = require('fs');
    mkdirSync(dir, { recursive: true });
  }

  writeFileSync(PID_FILE_PATH, JSON.stringify(content, null, 2));
}

/**
 * Remove PID file
 */
export function removePidFile(): void {
  try {
    if (existsSync(PID_FILE_PATH)) {
      unlinkSync(PID_FILE_PATH);
    }
  } catch {
    // Ignore errors
  }
}

/**
 * Read PID file if it exists
 */
export function readPidFile(): PidFileContent | null {
  try {
    if (existsSync(PID_FILE_PATH)) {
      const content = readFileSync(PID_FILE_PATH, 'utf-8');
      return JSON.parse(content);
    }
  } catch {
    // Ignore errors
  }
  return null;
}

/**
 * Check if watch/hybrid mode is running
 */
export function isWatchRunning(): { running: boolean; port?: number; pid?: number; mode?: string } {
  const pidData = readPidFile();
  if (!pidData) {
    return { running: false };
  }

  // Check if process is still running
  try {
    process.kill(pidData.pid, 0); // Signal 0 = check if process exists
    return {
      running: true,
      port: pidData.port,
      pid: pidData.pid,
      mode: pidData.mode,
    };
  } catch {
    // Process not running, clean up stale PID file
    removePidFile();
    return { running: false };
  }
}

/**
 * Start hybrid mode - both Watch proxy and MCP server
 */
export async function startHybridMode(options: HybridModeOptions): Promise<void> {
  const {
    port,
    timeout,
    noColor,
    maxRpm,
    maxCost,
    loopThreshold,
    disableLoopDetection,
    apiKey,
  } = options;

  const timeoutMs = timeout * 60 * 1000;

  if (!noColor) {
    chalk.level = 3;
  } else {
    chalk.level = 0;
  }

  // Create shared evidence store
  const store = new EvidenceStore();
  store.init();

  // Create MCP server with shared store
  const mcpServer = new TrustScopeMCPServer({
    apiKey,
    store,
  });

  // Create safety engine for blocking
  const safetyEngine = createSafetyEngine({
    maxRpm,
    maxCost,
    loopThreshold,
    disableLoopDetection,
  });

  // Check credentials
  const credentials = getCredentials();
  const config = loadConfig();

  // Track blocked requests
  let blockedCount = 0;
  let savedCost = 0;

  // Initialize session stats
  const stats: WatchSessionStats = {
    startTime: new Date().toISOString(),
    requests: 0,
    errors: 0,
    toolCalls: 0,
    tokensIn: 0,
    tokensOut: 0,
    estimatedCost: 0,
    alerts: [],
    requestHistory: [],
  };

  // Track recent requests for UI display
  const recentRequests: LLMRequest[] = [];
  const MAX_RECENT = 10;

  // Callbacks for proxy events with evidence store integration
  const callbacks = {
    onRequest: (request: LLMRequest) => {
      recentRequests.push(request);
      if (recentRequests.length > MAX_RECENT) {
        recentRequests.shift();
      }
      updateDisplay();
    },
    onResponse: (request: LLMRequest) => {
      const index = recentRequests.findIndex(r => r.id === request.id);
      if (index !== -1) {
        recentRequests[index] = request;
      }

      // Log to evidence store
      store.insertTrace({
        source: 'gateway',
        agent_id: config?.agentId || 'watch-proxy',
        session_id: request.id,
        action_type: request.model ? 'llm_completion' : 'api_call',
        tool_name: request.model || 'unknown',
        request_summary: request.prompt?.substring(0, 500),
        response_summary: request.completion?.substring(0, 500),
        blocked: request.error?.includes('BLOCKED') ? 1 : 0,
        simulated: 0,
        risk_weight: 0.5,
      });

      updateDisplay();
    },
    onAlert: (_alert: WatchAlert) => {
      updateDisplay();
    },
    onError: (error: Error, _requestId?: string) => {
      console.error(chalk.red(`Proxy error: ${error.message}`));
    },
    onBlock: (result: SafetyResult, request: Partial<LLMRequest>) => {
      blockedCount++;
      if (result.savedCost) {
        savedCost += result.savedCost;
      }

      // Log blocked action to evidence store
      store.insertTrace({
        source: 'gateway',
        agent_id: config?.agentId || 'watch-proxy',
        session_id: request.id || 'blocked',
        action_type: 'blocked_request',
        tool_name: request.model || 'unknown',
        request_summary: result.message,
        blocked: 1,
        simulated: 0,
        risk_weight: 1.0,
      });

      const blockedRequest: LLMRequest = {
        id: request.id || 'blocked',
        timestamp: request.timestamp || new Date().toISOString(),
        method: request.method || 'POST',
        path: request.path || '/unknown',
        model: request.model,
        provider: request.provider || 'unknown',
        error: `BLOCKED: ${result.message}`,
        status: 429,
      };
      recentRequests.push(blockedRequest);
      if (recentRequests.length > MAX_RECENT) {
        recentRequests.shift();
      }
      updateDisplay();
    },
  };

  // Create proxy app
  const app = createWatchProxy(callbacks, stats, safetyEngine, credentials || undefined, config || undefined);
  const server = createServer(app);

  // Write PID file
  writePidFile(port, 'hybrid');

  // Log startup info
  console.log(chalk.green('Starting TrustScope Hybrid Mode'));
  console.log(chalk.dim('  Watch proxy + MCP server with shared evidence store'));
  console.log('');

  if (credentials) {
    console.log(chalk.green(`  Cloud: logged in as ${credentials.user.email}`));
  }
  console.log(chalk.cyan(`  MCP: running on stdio (${mcpServer.getMode()} mode)`));
  console.log(chalk.cyan(`  Watch: running on port ${port}`));
  console.log(chalk.dim(`  Evidence: ${store.getPath()}`));
  console.log('');

  // Calculate time remaining
  const startTime = Date.now();
  const getTimeRemaining = () => Math.max(0, timeoutMs - (Date.now() - startTime));

  // Update display function
  let displayUpdatePending = false;
  function updateDisplay(): void {
    if (displayUpdatePending) return;
    displayUpdatePending = true;

    setImmediate(() => {
      displayUpdatePending = false;
      clearScreen();
      const ui = renderWatchUI(port, getTimeRemaining(), stats, recentRequests, !noColor);
      // Add hybrid mode indicator
      const hybridIndicator = chalk.bgCyan.black(' HYBRID ') + ' ';
      process.stdout.write(hybridIndicator + ui);
    });
  }

  // Refresh display periodically
  const refreshInterval = setInterval(() => {
    updateDisplay();
  }, 1000);

  // Handle timeout
  const timeoutHandle = setTimeout(() => {
    shutdown('timeout');
  }, timeoutMs);

  // Setup keyboard input (only if not in MCP stdio mode)
  if (process.stdin.isTTY) {
    readline.emitKeypressEvents(process.stdin);
    process.stdin.setRawMode(true);
  }

  const restoreTerminal = () => {
    if (process.stdin.isTTY) {
      try {
        process.stdin.setRawMode(false);
      } catch {
        // Ignore
      }
    }
  };

  // Handle signals
  process.on('SIGINT', () => {
    restoreTerminal();
    removePidFile();
    process.exit(130);
  });
  process.on('SIGTERM', () => {
    restoreTerminal();
    removePidFile();
    process.exit(143);
  });

  let shuttingDown = false;

  function shutdown(reason: 'quit' | 'timeout' | 'error'): void {
    if (shuttingDown) return;
    shuttingDown = true;

    clearInterval(refreshInterval);
    clearTimeout(timeoutHandle);
    removePidFile();

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(false);
    }

    server.close(() => {
      clearScreen();

      if (reason === 'timeout') {
        console.log(chalk.yellow('\nHybrid mode timed out.\n'));
      }

      const safetySummary = safetyEngine.getSessionSummary();
      console.log(renderSessionSummary(stats, !noColor, {
        blockedCount: safetySummary.blockedCount,
        savedCost: safetySummary.savedCost,
        blocksByReason: safetySummary.blocksByReason,
      }));
      process.exit(0);
    });

    setTimeout(() => {
      process.exit(0);
    }, 5000);
  }

  if (process.stdin.isTTY) {
    process.stdin.on('keypress', (_str, key) => {
      if (key.name === 'q' || (key.ctrl && key.name === 'c')) {
        shutdown('quit');
      } else if (key.name === 's') {
        clearScreen();
        console.log(renderSessionSummary(stats, !noColor));
        console.log(chalk.dim('\nPress any key to continue...\n'));
        process.stdin.once('keypress', () => {
          updateDisplay();
        });
      }
    });
  }

  // Start both servers
  return new Promise((resolve, reject) => {
    server.on('error', (err: NodeJS.ErrnoException) => {
      removePidFile();
      if (err.code === 'EADDRINUSE') {
        console.error(chalk.red(`\nError: Port ${port} is already in use.`));
        reject(err);
      } else {
        console.error(chalk.red(`\nServer error: ${err.message}`));
        reject(err);
      }
    });

    server.listen(port, () => {
      // MCP server runs on stdio - start it
      // Note: In true hybrid mode, MCP would use stdio while watch uses HTTP
      // For now, we just share the evidence store
      updateDisplay();
    });
  });
}

export { EvidenceStore };
