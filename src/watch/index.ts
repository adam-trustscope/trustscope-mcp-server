import { createServer } from 'node:http';
import readline from 'node:readline';
import chalk from 'chalk';
import type { WatchOptions, WatchSessionStats, LLMRequest, WatchAlert } from '../types/cli.js';
import { createWatchProxy } from './proxy.js';
import { clearScreen, renderWatchUI, renderSessionSummary } from './ui.js';
import { createSafetyEngine, type SafetyResult } from './safety.js';
import { getCredentials } from '../auth/index.js';
import { loadConfig } from '../cli/init.js';
import { EvidenceStore } from '../evidence/store.js';

export async function startWatchMode(options: WatchOptions): Promise<void> {
  const { port, timeout, noColor, maxRpm, maxCost, loopThreshold, disableLoopDetection } = options;
  const timeoutMs = timeout * 60 * 1000;

  if (!noColor) {
    chalk.level = 3;
  } else {
    chalk.level = 0;
  }

  // Create safety engine for blocking
  const safetyEngine = createSafetyEngine({
    maxRpm,
    maxCost,
    loopThreshold,
    disableLoopDetection,
  });

  // Check if logged in - if so, traces will flow to cloud automatically
  const credentials = getCredentials();

  // Load config file if present (for agent_id override, etc.)
  const config = loadConfig();

  // Sprint 3: Create evidence store for local trace recording
  const evidenceStore = new EvidenceStore();
  evidenceStore.init();
  console.log(chalk.dim(`Evidence store initialized at ${evidenceStore.getPath()}`));

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

  // Callbacks for proxy events
  const callbacks = {
    onRequest: (request: LLMRequest) => {
      recentRequests.push(request);
      if (recentRequests.length > MAX_RECENT) {
        recentRequests.shift();
      }
      updateDisplay();
    },
    onResponse: (request: LLMRequest) => {
      // Update the request in recent list
      const index = recentRequests.findIndex(r => r.id === request.id);
      if (index !== -1) {
        recentRequests[index] = request;
      }
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
      // Add blocked request to display (marked as blocked)
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

  // Create proxy app with safety engine and evidence store
  // If logged in, traces automatically flow to cloud
  // Sprint 3: Pass evidence store for local trace recording + full detection
  const app = createWatchProxy(
    callbacks,
    stats,
    safetyEngine,
    credentials || undefined,
    config || undefined,
    evidenceStore,
    true // enableFullDetection
  );
  const server = createServer(app);

  // Show cloud status
  if (credentials) {
    console.log(chalk.green(`✓ Logged in as ${credentials.user.email} - traces will sync to cloud`));
    console.log('');
  }

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
      process.stdout.write(ui);
    });
  }

  // Refresh display periodically (for timer)
  const refreshInterval = setInterval(() => {
    updateDisplay();
  }, 1000);

  // Handle timeout
  const timeoutHandle = setTimeout(() => {
    shutdown('timeout');
  }, timeoutMs);

  // Setup keyboard input
  readline.emitKeypressEvents(process.stdin);
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(true);
  }

  // Restore terminal on crash/exit to prevent broken terminal state
  const restoreTerminal = () => {
    if (process.stdin.isTTY) {
      try {
        process.stdin.setRawMode(false);
      } catch {
        // Ignore errors during cleanup
      }
    }
  };

  // Handle signals and crashes
  process.on('SIGINT', () => {
    restoreTerminal();
    process.exit(130);
  });
  process.on('SIGTERM', () => {
    restoreTerminal();
    process.exit(143);
  });
  process.on('uncaughtException', (err) => {
    restoreTerminal();
    console.error('Uncaught exception:', err);
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    restoreTerminal();
    console.error('Unhandled rejection:', reason);
    process.exit(1);
  });

  let shuttingDown = false;

  function shutdown(reason: 'quit' | 'timeout' | 'error'): void {
    if (shuttingDown) return;
    shuttingDown = true;

    clearInterval(refreshInterval);
    clearTimeout(timeoutHandle);

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(false);
    }

    server.close(() => {
      clearScreen();

      if (reason === 'timeout') {
        console.log(chalk.yellow('\n⏰ Watch mode timed out.\n'));
      }

      const safetySummary = safetyEngine.getSessionSummary();
      console.log(renderSessionSummary(stats, !noColor, {
        blockedCount: safetySummary.blockedCount,
        savedCost: safetySummary.savedCost,
        blocksByReason: safetySummary.blocksByReason,
      }));
      process.exit(0);
    });

    // Force exit after 5 seconds if server doesn't close
    setTimeout(() => {
      process.exit(0);
    }, 5000);
  }

  process.stdin.on('keypress', (_str, key) => {
    if (key.name === 'q' || (key.ctrl && key.name === 'c')) {
      shutdown('quit');
    } else if (key.name === 's') {
      // Show summary without quitting
      clearScreen();
      console.log(renderSessionSummary(stats, !noColor));
      console.log(chalk.dim('\nPress any key to continue watching...\n'));
      process.stdin.once('keypress', () => {
        updateDisplay();
      });
    }
  });

  // Start server
  return new Promise((resolve, reject) => {
    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        console.error(chalk.red(`\nError: Port ${port} is already in use.`));
        console.error(chalk.dim('Try a different port with: trustscope watch --port <port>\n'));
        reject(err);
      } else {
        console.error(chalk.red(`\nServer error: ${err.message}`));
        reject(err);
      }
    });

    server.listen(port, () => {
      updateDisplay();
    });
  });
}
