/**
 * MCP wrapper commands for TrustScope CLI.
 *
 * Commands:
 * - trustscope mcp wrap [--config <path>] [--project <id>]
 * - trustscope mcp list
 * - trustscope mcp unwrap [--all]
 */

import { existsSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import chalk from 'chalk';
import { getCredentials } from '../auth/index.js';

// MCP config file locations
const MCP_CONFIG_PATHS = [
  // Claude Desktop
  { name: 'Claude Desktop', path: join(homedir(), '.config', 'claude', 'claude_desktop_config.json') },
  { name: 'Claude Desktop (macOS)', path: join(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json') },
  // Cursor
  { name: 'Cursor', path: join(homedir(), '.cursor', 'mcp.json') },
  // VS Code
  { name: 'VS Code', path: join(homedir(), '.vscode', 'mcp.json') },
  // Project-level
  { name: 'Project (.mcp.json)', path: '.mcp.json' },
];

interface MCPServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  [key: string]: unknown;
}

interface MCPConfig {
  mcpServers?: Record<string, MCPServerConfig>;
  [key: string]: unknown;
}

interface WrappedServer {
  name: string;
  configPath: string;
  originalCommand?: string;
  status: 'wrapped' | 'unwrapped' | 'already_wrapped';
}

/**
 * Find all MCP config files on the system.
 */
function findMcpConfigs(customPath?: string): Array<{ name: string; path: string; exists: boolean }> {
  const configs: Array<{ name: string; path: string; exists: boolean }> = [];

  if (customPath) {
    configs.push({ name: 'Custom', path: customPath, exists: existsSync(customPath) });
    return configs;
  }

  for (const config of MCP_CONFIG_PATHS) {
    configs.push({
      name: config.name,
      path: config.path,
      exists: existsSync(config.path),
    });
  }

  return configs;
}

/**
 * Parse an MCP config file.
 */
function parseConfig(configPath: string): MCPConfig | null {
  try {
    const content = readFileSync(configPath, 'utf-8');
    return JSON.parse(content);
  } catch (error) {
    return null;
  }
}

/**
 * Create a backup of a config file.
 */
function backupConfig(configPath: string): string {
  const backupPath = `${configPath}.backup-${Date.now()}`;
  copyFileSync(configPath, backupPath);
  return backupPath;
}

/**
 * Check if a server is already wrapped.
 */
function isServerWrapped(server: MCPServerConfig): boolean {
  // Check if command points to trustscope mcp-proxy
  if (server.command === 'npx' && server.args?.includes('@trustscope/mcp-proxy')) {
    return true;
  }
  // Check for TRUSTSCOPE_ENABLED env var
  if (server.env?.TRUSTSCOPE_ENABLED === 'true') {
    return true;
  }
  return false;
}

/**
 * Wrap an MCP server config with TrustScope proxy.
 */
function wrapServer(name: string, server: MCPServerConfig, apiKey: string, projectId?: string): MCPServerConfig {
  if (isServerWrapped(server)) {
    return server; // Already wrapped
  }

  // Build wrapped config - use environment variable approach for simplicity
  const wrapped: MCPServerConfig = {
    ...server,
    env: {
      ...server.env,
      TRUSTSCOPE_ENABLED: 'true',
      TRUSTSCOPE_API_KEY: apiKey,
      ...(projectId ? { TRUSTSCOPE_PROJECT_ID: projectId } : {}),
    },
  };

  return wrapped;
}

/**
 * Unwrap an MCP server config (remove TrustScope proxy).
 */
function unwrapServer(name: string, server: MCPServerConfig): MCPServerConfig {
  if (!isServerWrapped(server)) {
    return server; // Not wrapped
  }

  // Remove TrustScope environment variables
  const { TRUSTSCOPE_ENABLED, TRUSTSCOPE_API_KEY, TRUSTSCOPE_PROJECT_ID, ...restEnv } = server.env || {};

  const unwrapped: MCPServerConfig = {
    ...server,
    env: Object.keys(restEnv).length > 0 ? restEnv : undefined,
  };

  // Clean up empty env object
  if (unwrapped.env && Object.keys(unwrapped.env).length === 0) {
    delete unwrapped.env;
  }

  return unwrapped;
}

/**
 * trustscope mcp wrap command
 */
export async function mcpWrap(options: {
  config?: string;
  project?: string;
  verbose?: boolean;
}): Promise<void> {
  console.log(chalk.cyan('\nTrustScope MCP Wrapper\n'));

  // Check authentication
  const creds = getCredentials();
  if (!creds) {
    console.log(chalk.yellow('⚠️  Not logged in. Please run: trustscope login\n'));
    return;
  }

  // Get API key
  const apiKey = process.env.TRUSTSCOPE_API_KEY;
  if (!apiKey) {
    console.log(chalk.yellow('⚠️  No TRUSTSCOPE_API_KEY environment variable found.'));
    console.log(chalk.dim('Create a project at https://app.trustscope.ai/onboarding to get your API key.\n'));
    return;
  }

  // Find config files
  const configs = findMcpConfigs(options.config);
  const existingConfigs = configs.filter(c => c.exists);

  if (existingConfigs.length === 0) {
    console.log(chalk.yellow('No MCP configuration files found.\n'));
    console.log(chalk.dim('Expected locations:'));
    configs.forEach(c => console.log(chalk.dim(`  - ${c.path}`)));
    console.log('');
    return;
  }

  console.log(chalk.bold('Found MCP configurations:\n'));

  let totalWrapped = 0;
  let totalSkipped = 0;

  for (const configInfo of existingConfigs) {
    console.log(chalk.cyan(`${configInfo.name}: ${configInfo.path}`));

    // Parse config
    const config = parseConfig(configInfo.path);
    if (!config || !config.mcpServers) {
      console.log(chalk.dim('  No servers found\n'));
      continue;
    }

    // Backup before modifying
    const backupPath = backupConfig(configInfo.path);
    console.log(chalk.dim(`  Backup: ${backupPath}`));

    // Process each server
    const servers = Object.entries(config.mcpServers);
    for (const [name, server] of servers) {
      if (isServerWrapped(server)) {
        console.log(chalk.dim(`  ⏭️  ${name} (already wrapped)`));
        totalSkipped++;
        continue;
      }

      config.mcpServers[name] = wrapServer(name, server, apiKey, options.project);
      console.log(chalk.green(`  ✅ ${name}`));
      totalWrapped++;
    }

    // Save updated config
    writeFileSync(configInfo.path, JSON.stringify(config, null, 2));
    console.log('');
  }

  // Summary
  console.log(chalk.bold('Summary:\n'));
  console.log(`  Wrapped: ${chalk.green(totalWrapped.toString())}`);
  if (totalSkipped > 0) {
    console.log(`  Skipped: ${chalk.dim(totalSkipped.toString())} (already wrapped)`);
  }
  console.log('');

  if (totalWrapped > 0) {
    console.log(chalk.yellow('⚠️  Please restart your MCP client for changes to take effect.\n'));
    console.log(chalk.dim('To undo: trustscope mcp unwrap\n'));
  }
}

/**
 * trustscope mcp list command
 */
export async function mcpList(options: {
  verbose?: boolean;
}): Promise<void> {
  console.log(chalk.cyan('\nMCP Server Status\n'));

  // Find config files
  const configs = findMcpConfigs();
  const existingConfigs = configs.filter(c => c.exists);

  if (existingConfigs.length === 0) {
    console.log(chalk.yellow('No MCP configuration files found.\n'));
    return;
  }

  for (const configInfo of existingConfigs) {
    console.log(chalk.bold(`${configInfo.name}:`));
    console.log(chalk.dim(`  ${configInfo.path}\n`));

    // Parse config
    const config = parseConfig(configInfo.path);
    if (!config || !config.mcpServers) {
      console.log(chalk.dim('  No servers configured\n'));
      continue;
    }

    // List servers
    const servers = Object.entries(config.mcpServers);
    for (const [name, server] of servers) {
      const wrapped = isServerWrapped(server);
      const statusIcon = wrapped ? '🛡️' : '⚪';
      const statusText = wrapped ? chalk.green('wrapped') : chalk.dim('not wrapped');

      console.log(`  ${statusIcon} ${name} - ${statusText}`);

      if (options.verbose) {
        if (server.command) {
          console.log(chalk.dim(`     command: ${server.command} ${(server.args || []).join(' ')}`));
        }
        if (server.url) {
          console.log(chalk.dim(`     url: ${server.url}`));
        }
      }
    }
    console.log('');
  }
}

/**
 * trustscope mcp unwrap command
 */
export async function mcpUnwrap(options: {
  all?: boolean;
  config?: string;
  verbose?: boolean;
}): Promise<void> {
  console.log(chalk.cyan('\nUnwrapping MCP Servers\n'));

  // Find config files
  const configs = findMcpConfigs(options.config);
  const existingConfigs = configs.filter(c => c.exists);

  if (existingConfigs.length === 0) {
    console.log(chalk.yellow('No MCP configuration files found.\n'));
    return;
  }

  let totalUnwrapped = 0;
  let totalSkipped = 0;

  for (const configInfo of existingConfigs) {
    console.log(chalk.cyan(`${configInfo.name}: ${configInfo.path}`));

    // Parse config
    const config = parseConfig(configInfo.path);
    if (!config || !config.mcpServers) {
      console.log(chalk.dim('  No servers found\n'));
      continue;
    }

    // Backup before modifying
    const backupPath = backupConfig(configInfo.path);
    console.log(chalk.dim(`  Backup: ${backupPath}`));

    // Process each server
    const servers = Object.entries(config.mcpServers);
    for (const [name, server] of servers) {
      if (!isServerWrapped(server)) {
        console.log(chalk.dim(`  ⏭️  ${name} (not wrapped)`));
        totalSkipped++;
        continue;
      }

      config.mcpServers[name] = unwrapServer(name, server);
      console.log(chalk.green(`  ✅ ${name} (unwrapped)`));
      totalUnwrapped++;
    }

    // Save updated config
    writeFileSync(configInfo.path, JSON.stringify(config, null, 2));
    console.log('');
  }

  // Summary
  console.log(chalk.bold('Summary:\n'));
  console.log(`  Unwrapped: ${chalk.green(totalUnwrapped.toString())}`);
  if (totalSkipped > 0) {
    console.log(`  Skipped: ${chalk.dim(totalSkipped.toString())} (not wrapped)`);
  }
  console.log('');

  if (totalUnwrapped > 0) {
    console.log(chalk.yellow('⚠️  Please restart your MCP client for changes to take effect.\n'));
  }
}
