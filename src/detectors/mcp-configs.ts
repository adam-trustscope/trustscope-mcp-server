import { join } from 'node:path';
import type { MCPConfig, MCPServer } from '../types/cli.js';
import { containsSecret, expandHomePath, fileExists, log, readJsonFile } from '../utils.js';

interface ClaudeDesktopConfig {
  mcpServers?: Record<string, {
    command?: string;
    args?: string[];
    env?: Record<string, string>;
  }>;
}

interface CursorConfig {
  mcpServers?: Record<string, {
    command?: string;
    args?: string[];
    env?: Record<string, string>;
    url?: string;
  }>;
}

interface ContinueConfig {
  models?: unknown[];
  mcpServers?: Array<{
    name: string;
    command?: string;
    args?: string[];
    env?: Record<string, string>;
  }>;
}

interface CodeiumConfig {
  mcpServers?: Record<string, {
    command?: string;
    args?: string[];
    env?: Record<string, string>;
  }>;
}

interface LocalMcpConfig {
  mcpServers?: Record<string, {
    command?: string;
    args?: string[];
    env?: Record<string, string>;
    transport?: string;
    url?: string;
  }>;
}

const MCP_CONFIG_LOCATIONS = [
  { path: '~/.config/claude/claude_desktop_config.json', type: 'claude-desktop' },
  { path: '~/.cursor/mcp.json', type: 'cursor' },
  { path: '~/.continue/config.json', type: 'continue' },
  { path: '~/.codeium/config.json', type: 'codeium' },
] as const;

function checkEnvForSecrets(env?: Record<string, string>): boolean {
  if (!env) return false;
  return Object.values(env).some((value) => containsSecret(value));
}

function sanitizeEnv(env?: Record<string, string>): Record<string, string> | undefined {
  if (!env) return undefined;
  const sanitized: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    sanitized[key] = containsSecret(value) ? '[REDACTED]' : value;
  }
  return sanitized;
}

function parseClaudeDesktopConfig(config: ClaudeDesktopConfig, source: string): MCPConfig | null {
  if (!config.mcpServers || Object.keys(config.mcpServers).length === 0) {
    return null;
  }

  const servers: MCPServer[] = Object.entries(config.mcpServers).map(([name, server]) => ({
    name,
    command: server.command,
    args: server.args,
    env: sanitizeEnv(server.env),
    hasSecrets: checkEnvForSecrets(server.env),
  }));

  return { source, servers };
}

function parseCursorConfig(config: CursorConfig, source: string): MCPConfig | null {
  if (!config.mcpServers || Object.keys(config.mcpServers).length === 0) {
    return null;
  }

  const servers: MCPServer[] = Object.entries(config.mcpServers).map(([name, server]) => ({
    name,
    command: server.command,
    args: server.args,
    env: sanitizeEnv(server.env),
    transport: server.url ? 'http' : 'stdio',
    hasSecrets: checkEnvForSecrets(server.env),
  }));

  return { source, servers };
}

function parseContinueConfig(config: ContinueConfig, source: string): MCPConfig | null {
  if (!config.mcpServers || config.mcpServers.length === 0) {
    return null;
  }

  const servers: MCPServer[] = config.mcpServers.map((server) => ({
    name: server.name,
    command: server.command,
    args: server.args,
    env: sanitizeEnv(server.env),
    hasSecrets: checkEnvForSecrets(server.env),
  }));

  return { source, servers };
}

function parseCodeiumConfig(config: CodeiumConfig, source: string): MCPConfig | null {
  if (!config.mcpServers || Object.keys(config.mcpServers).length === 0) {
    return null;
  }

  const servers: MCPServer[] = Object.entries(config.mcpServers).map(([name, server]) => ({
    name,
    command: server.command,
    args: server.args,
    env: sanitizeEnv(server.env),
    hasSecrets: checkEnvForSecrets(server.env),
  }));

  return { source, servers };
}

function parseLocalMcpConfig(config: LocalMcpConfig, source: string): MCPConfig | null {
  if (!config.mcpServers || Object.keys(config.mcpServers).length === 0) {
    return null;
  }

  const servers: MCPServer[] = Object.entries(config.mcpServers).map(([name, server]) => ({
    name,
    command: server.command,
    args: server.args,
    env: sanitizeEnv(server.env),
    transport: server.transport || (server.url ? 'http' : 'stdio'),
    hasSecrets: checkEnvForSecrets(server.env),
  }));

  return { source, servers };
}

export async function detectMcpConfigs(
  scanDir: string,
  verbose: boolean = false,
  includeGlobalConfigs: boolean = true
): Promise<MCPConfig[]> {
  const configs: MCPConfig[] = [];

  // Check global config locations (only for local scans, not GitHub repo scans)
  if (includeGlobalConfigs) {
    for (const { path, type } of MCP_CONFIG_LOCATIONS) {
      const expandedPath = expandHomePath(path);
      log(`Checking ${type} config at ${expandedPath}`, verbose);

      if (!fileExists(path)) {
        continue;
      }

      let mcpConfig: MCPConfig | null = null;

      switch (type) {
        case 'claude-desktop': {
          const config = readJsonFile<ClaudeDesktopConfig>(path);
          if (config) {
            mcpConfig = parseClaudeDesktopConfig(config, expandedPath);
          }
          break;
        }
        case 'cursor': {
          const config = readJsonFile<CursorConfig>(path);
          if (config) {
            mcpConfig = parseCursorConfig(config, expandedPath);
          }
          break;
        }
        case 'continue': {
          const config = readJsonFile<ContinueConfig>(path);
          if (config) {
            mcpConfig = parseContinueConfig(config, expandedPath);
          }
          break;
        }
        case 'codeium': {
          const config = readJsonFile<CodeiumConfig>(path);
          if (config) {
            mcpConfig = parseCodeiumConfig(config, expandedPath);
          }
          break;
        }
      }

      if (mcpConfig) {
        log(`Found ${mcpConfig.servers.length} MCP server(s) in ${type} config`, verbose);
        configs.push(mcpConfig);
      }
    }
  }

  // Check local directory for .mcp.json and mcp.json
  const localConfigPaths = [
    join(scanDir, '.mcp.json'),
    join(scanDir, 'mcp.json'),
  ];

  for (const localPath of localConfigPaths) {
    log(`Checking local MCP config at ${localPath}`, verbose);

    if (!fileExists(localPath)) {
      continue;
    }

    const config = readJsonFile<LocalMcpConfig>(localPath);
    if (config) {
      const mcpConfig = parseLocalMcpConfig(config, localPath);
      if (mcpConfig) {
        log(`Found ${mcpConfig.servers.length} MCP server(s) in local config`, verbose);
        configs.push(mcpConfig);
      }
    }
  }

  return configs;
}
