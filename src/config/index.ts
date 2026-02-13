/**
 * Config Resolution Module
 *
 * Handles configuration loading with priority:
 * 1. CLI flags (highest)
 * 2. Environment variables
 * 3. .trustscope/config.yaml (project)
 * 4. ~/.trustscope/config.yaml (global)
 * 5. Built-in defaults (lowest)
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import { parse as parseYaml } from 'yaml';
import { DEFAULT_CONFIG, DEFAULT_DETECTION_CONFIG, DEFAULT_POLICY_CONFIG } from './defaults.js';
import type { TrustScopeConfig, DetectionConfig, PolicyConfig } from './types.js';

export type { TrustScopeConfig, DetectionConfig, PolicyConfig } from './types.js';

/**
 * Get the mode based on API key presence
 */
export function getMode(config?: TrustScopeConfig): 'local' | 'connected' {
  const apiKey = config?.apiKey || process.env.TRUSTSCOPE_API_KEY;
  return apiKey ? 'connected' : 'local';
}

/**
 * Load configuration from YAML file
 */
function loadYamlFile(filePath: string): Partial<TrustScopeConfig> | null {
  try {
    if (!existsSync(filePath)) {
      return null;
    }
    const content = readFileSync(filePath, 'utf-8');
    return parseYaml(content) || {};
  } catch {
    return null;
  }
}

/**
 * Load configuration from environment variables
 */
function loadEnvConfig(): Partial<TrustScopeConfig> {
  const env: Partial<TrustScopeConfig> = {};

  if (process.env.TRUSTSCOPE_API_KEY) {
    env.apiKey = process.env.TRUSTSCOPE_API_KEY;
  }

  if (process.env.TRUSTSCOPE_BASE_URL) {
    env.baseUrl = process.env.TRUSTSCOPE_BASE_URL;
  }

  if (process.env.TRUSTSCOPE_PROJECT_ID) {
    env.projectId = process.env.TRUSTSCOPE_PROJECT_ID;
  }

  if (process.env.TRUSTSCOPE_AGENT_ID) {
    env.agentId = process.env.TRUSTSCOPE_AGENT_ID;
  }

  if (process.env.TRUSTSCOPE_DB_PATH) {
    env.dbPath = process.env.TRUSTSCOPE_DB_PATH;
  }

  if (process.env.TRUSTSCOPE_PORT) {
    const port = parseInt(process.env.TRUSTSCOPE_PORT, 10);
    if (!isNaN(port)) {
      env.watch = { ...env.watch, port };
    }
  }

  return env;
}

/**
 * Deep merge two objects
 */
function deepMerge<T extends Record<string, unknown>>(target: T, source: Partial<T>): T {
  const result = { ...target };

  for (const key in source) {
    const sourceValue = source[key];
    const targetValue = result[key];

    if (sourceValue === undefined || sourceValue === null) {
      continue;
    }

    if (
      typeof sourceValue === 'object' &&
      !Array.isArray(sourceValue) &&
      typeof targetValue === 'object' &&
      !Array.isArray(targetValue)
    ) {
      result[key] = deepMerge(
        targetValue as Record<string, unknown>,
        sourceValue as Record<string, unknown>
      ) as T[Extract<keyof T, string>];
    } else {
      result[key] = sourceValue as T[Extract<keyof T, string>];
    }
  }

  return result;
}

/**
 * Find project config file
 */
function findProjectConfig(): string | null {
  const cwd = process.cwd();

  // Check .trustscope/config.yaml
  const configPath = join(cwd, '.trustscope', 'config.yaml');
  if (existsSync(configPath)) {
    return configPath;
  }

  // Check .trustscope.yaml (legacy)
  const legacyPath = join(cwd, '.trustscope.yaml');
  if (existsSync(legacyPath)) {
    return legacyPath;
  }

  return null;
}

/**
 * Find global config file
 */
function findGlobalConfig(): string | null {
  const home = homedir();
  const configPath = join(home, '.trustscope', 'config.yaml');

  if (existsSync(configPath)) {
    return configPath;
  }

  return null;
}

/**
 * Load full configuration with priority resolution
 */
export function loadConfig(cliOptions?: Partial<TrustScopeConfig>): TrustScopeConfig {
  // Start with defaults
  let config: TrustScopeConfig = { ...DEFAULT_CONFIG };

  // Load global config
  const globalConfigPath = findGlobalConfig();
  if (globalConfigPath) {
    const globalConfig = loadYamlFile(globalConfigPath);
    if (globalConfig) {
      config = deepMerge(config, globalConfig);
    }
  }

  // Load project config
  const projectConfigPath = findProjectConfig();
  if (projectConfigPath) {
    const projectConfig = loadYamlFile(projectConfigPath);
    if (projectConfig) {
      config = deepMerge(config, projectConfig);
    }
  }

  // Load environment variables
  const envConfig = loadEnvConfig();
  config = deepMerge(config, envConfig);

  // Apply CLI options (highest priority)
  if (cliOptions) {
    config = deepMerge(config, cliOptions);
  }

  return config;
}

/**
 * Load detection configuration
 */
export function loadDetectionConfig(config?: TrustScopeConfig): DetectionConfig {
  const fullConfig = config || loadConfig();
  return deepMerge(DEFAULT_DETECTION_CONFIG, fullConfig.detection || {});
}

/**
 * Load policy configuration
 */
export function loadPolicyConfig(config?: TrustScopeConfig): PolicyConfig {
  const fullConfig = config || loadConfig();
  return deepMerge(DEFAULT_POLICY_CONFIG, fullConfig.policies || {});
}

/**
 * Get the evidence database path
 */
export function getDbPath(config?: TrustScopeConfig): string {
  const fullConfig = config || loadConfig();
  return fullConfig.dbPath || resolve(process.cwd(), '.trustscope', 'evidence.db');
}

/**
 * Check if running in local mode
 */
export function isLocalMode(config?: TrustScopeConfig): boolean {
  return getMode(config) === 'local';
}

/**
 * Check if running in connected mode
 */
export function isConnectedMode(config?: TrustScopeConfig): boolean {
  return getMode(config) === 'connected';
}
