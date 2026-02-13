/**
 * Enforcement Coverage Detection
 *
 * Detects if watch proxy is running and determines overall enforcement coverage.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import http from 'node:http';

/**
 * Enforcement coverage level
 */
export type EnforcementCoverage = 'full' | 'partial' | 'none';

/**
 * Enforcement status
 */
export interface EnforcementStatus {
  mcp_active: boolean;
  proxy_active: boolean;
  coverage: EnforcementCoverage;
  proxy_port?: number;
  proxy_pid?: number;
  proxy_mode?: 'watch' | 'mcp' | 'hybrid';
}

/**
 * PID file content
 */
interface PidFileContent {
  pid: number;
  port: number;
  started: string;
  mode: 'watch' | 'mcp' | 'hybrid';
}

const PID_FILE_PATH = join(homedir(), '.trustscope', 'watch.pid');

/**
 * Read PID file if it exists
 */
function readPidFile(): PidFileContent | null {
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
 * Check if a process is running by PID
 */
function isProcessRunning(pid: number): boolean {
  try {
    process.kill(pid, 0); // Signal 0 = check if process exists
    return true;
  } catch {
    return false;
  }
}

/**
 * Probe a port for the watch proxy health endpoint
 */
async function probePort(port: number, timeout: number = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/health',
        method: 'GET',
        timeout,
      },
      (res) => {
        resolve(res.statusCode === 200);
      },
    );

    req.on('error', () => {
      resolve(false);
    });

    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });

    req.end();
  });
}

/**
 * Detect enforcement coverage
 *
 * @param mcpActive - Whether MCP server is active (caller knows this)
 * @returns EnforcementStatus
 */
export async function detectEnforcement(mcpActive: boolean = true): Promise<EnforcementStatus> {
  // Check PID file first
  const pidData = readPidFile();

  if (!pidData) {
    return {
      mcp_active: mcpActive,
      proxy_active: false,
      coverage: mcpActive ? 'partial' : 'none',
    };
  }

  // Check if process is still running
  const processRunning = isProcessRunning(pidData.pid);

  if (!processRunning) {
    return {
      mcp_active: mcpActive,
      proxy_active: false,
      coverage: mcpActive ? 'partial' : 'none',
    };
  }

  // Probe the port to confirm it's responding
  const portActive = await probePort(pidData.port);

  if (!portActive) {
    // Process running but not responding - might be starting up or shutting down
    return {
      mcp_active: mcpActive,
      proxy_active: false,
      coverage: mcpActive ? 'partial' : 'none',
      proxy_pid: pidData.pid,
    };
  }

  // Proxy is active
  const proxyActive = true;

  // Determine coverage
  let coverage: EnforcementCoverage;
  if (mcpActive && proxyActive) {
    coverage = 'full';
  } else if (mcpActive || proxyActive) {
    coverage = 'partial';
  } else {
    coverage = 'none';
  }

  return {
    mcp_active: mcpActive,
    proxy_active: proxyActive,
    coverage,
    proxy_port: pidData.port,
    proxy_pid: pidData.pid,
    proxy_mode: pidData.mode,
  };
}

/**
 * Synchronous check for enforcement coverage (without port probe)
 * Use this when you can't await
 */
export function detectEnforcementSync(mcpActive: boolean = true): EnforcementStatus {
  const pidData = readPidFile();

  if (!pidData) {
    return {
      mcp_active: mcpActive,
      proxy_active: false,
      coverage: mcpActive ? 'partial' : 'none',
    };
  }

  const processRunning = isProcessRunning(pidData.pid);

  if (!processRunning) {
    return {
      mcp_active: mcpActive,
      proxy_active: false,
      coverage: mcpActive ? 'partial' : 'none',
    };
  }

  // Assume proxy is active if process is running (can't probe sync)
  const proxyActive = true;

  let coverage: EnforcementCoverage;
  if (mcpActive && proxyActive) {
    coverage = 'full';
  } else if (mcpActive || proxyActive) {
    coverage = 'partial';
  } else {
    coverage = 'none';
  }

  return {
    mcp_active: mcpActive,
    proxy_active: proxyActive,
    coverage,
    proxy_port: pidData.port,
    proxy_pid: pidData.pid,
    proxy_mode: pidData.mode,
  };
}

/**
 * Get human-readable enforcement description
 */
export function getEnforcementDescription(status: EnforcementStatus): string {
  if (status.coverage === 'full') {
    return 'Full coverage: MCP server and watch proxy both active';
  } else if (status.coverage === 'partial') {
    if (status.mcp_active && !status.proxy_active) {
      return 'Partial coverage: MCP server active, watch proxy not running';
    } else if (!status.mcp_active && status.proxy_active) {
      return 'Partial coverage: Watch proxy active, MCP server not running';
    }
    return 'Partial coverage';
  } else {
    return 'No coverage: Neither MCP server nor watch proxy active';
  }
}
