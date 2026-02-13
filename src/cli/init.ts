import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import chalk from 'chalk';
import YAML from 'yaml';
import type { TrustScopeConfig } from '../types/cli.js';

export interface InitOptions {
  dir?: string;
  ci?: boolean;
  force?: boolean;
}

const WORKFLOW_TEMPLATE = `name: TrustScope

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Run TrustScope Scan
        run: npx @trustscope/cli scan --format sarif --output results.sarif
        continue-on-error: true

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
`;

const CONFIG_TEMPLATE = `# TrustScope Configuration
# Documentation: https://docs.trustscope.ai/config

version: 1

# Optional: Link to cloud account (added after running 'trustscope connect')
# project_id: proj_xxxxx

# Optional: Custom agent ID for watch mode (defaults to auto-generated from machine)
# agent_id: my-local-agent

# Governance policies (enforced by SDK/Gateway)
policies:
  # Maximum tokens per single request
  max_tokens_per_request: 4000

  # Rate limiting
  max_requests_per_minute: 60

  # Tools that should be blocked
  blocked_tools:
    # - execute_code
    # - delete_file
    # - send_email

  # PII detection mode: warn | block | off
  pii_detection: warn

# Alerting configuration
alerts:
  # Daily cost threshold (USD) before alerting
  cost_threshold_daily: 100

  # Detect potential infinite loops
  loop_detection: true
`;

export async function initConfig(options: InitOptions = {}): Promise<void> {
  const dir = options.dir || process.cwd();

  // If --ci flag, create workflow file
  if (options.ci) {
    await initCIWorkflow(dir, options.force);
    return;
  }

  // Otherwise create config file
  const configPath = join(dir, '.trustscope.yaml');

  if (existsSync(configPath) && !options.force) {
    console.log(chalk.yellow(`\n⚠️  ${configPath} already exists.\n`));

    // Dynamic import for inquirer
    const inquirer = await import('inquirer');

    const { overwrite } = await inquirer.default.prompt([
      {
        type: 'confirm',
        name: 'overwrite',
        message: 'Do you want to overwrite it?',
        default: false,
      },
    ]);

    if (!overwrite) {
      console.log(chalk.dim('Cancelled.\n'));
      return;
    }
  }

  try {
    writeFileSync(configPath, CONFIG_TEMPLATE);
    console.log(chalk.green(`\n✅ Created ${configPath}\n`));

    console.log('Next steps:');
    console.log(chalk.dim('  1. Edit the config file to customize policies'));
    console.log(chalk.dim('  2. Run "trustscope connect" to link to your account'));
    console.log(chalk.dim('  3. Commit the config file to your repository\n'));
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.error(chalk.red(`\n❌ Failed to create config: ${message}\n`));
    process.exit(1);
  }
}

export async function initCIWorkflow(dir: string = process.cwd(), force: boolean = false): Promise<void> {
  const workflowPath = join(dir, '.github', 'workflows', 'trustscope.yml');

  if (existsSync(workflowPath) && !force) {
    console.log(chalk.yellow(`\n⚠️  ${workflowPath} already exists.`));
    console.log(chalk.dim('Use --force to overwrite.\n'));
    return;
  }

  try {
    // Ensure directory exists
    const workflowDir = dirname(workflowPath);
    if (!existsSync(workflowDir)) {
      mkdirSync(workflowDir, { recursive: true });
    }

    writeFileSync(workflowPath, WORKFLOW_TEMPLATE);
    console.log(chalk.green(`\n✅ Created ${workflowPath}\n`));

    console.log('TrustScope will now scan every PR for:');
    console.log(chalk.dim('  • Ungoverned AI agents'));
    console.log(chalk.dim('  • Security risks (hardcoded keys, dangerous configs)'));
    console.log(chalk.dim('  • Compliance gaps'));
    console.log('');
    console.log('Findings will appear in the GitHub Security tab.');
    console.log('');
    console.log('Next steps:');
    console.log(chalk.dim('  1. Commit the workflow file'));
    console.log(chalk.dim('  2. Push to GitHub'));
    console.log(chalk.dim('  3. Open a PR to see TrustScope in action\n'));
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.error(chalk.red(`\n❌ Failed to create workflow: ${message}\n`));
    process.exit(1);
  }
}

// Maximum config file size (1MB)
const MAX_CONFIG_FILE_SIZE = 1024 * 1024;

/**
 * Validate config structure and values.
 * Returns null if invalid, otherwise returns the validated config.
 */
function validateConfig(config: unknown): TrustScopeConfig | null {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return null;
  }

  const obj = config as Record<string, unknown>;

  // Version must be a positive integer
  const version = typeof obj.version === 'number' && obj.version > 0 ? Math.floor(obj.version) : 1;

  // Validate string fields
  const projectId = typeof obj.project_id === 'string' && obj.project_id.length <= 100 ? obj.project_id : undefined;
  const agentId = typeof obj.agent_id === 'string' && obj.agent_id.length <= 100 ? obj.agent_id : undefined;

  // Validate policies
  let policies: TrustScopeConfig['policies'];
  if (obj.policies && typeof obj.policies === 'object' && !Array.isArray(obj.policies)) {
    const p = obj.policies as Record<string, unknown>;
    policies = {
      maxTokensPerRequest: typeof p.max_tokens_per_request === 'number' ? Math.max(0, Math.floor(p.max_tokens_per_request)) : undefined,
      maxRequestsPerMinute: typeof p.max_requests_per_minute === 'number' ? Math.max(0, Math.floor(p.max_requests_per_minute)) : undefined,
      blockedTools: Array.isArray(p.blocked_tools) ? p.blocked_tools.filter((t): t is string => typeof t === 'string' && t.length <= 100).slice(0, 100) : undefined,
      piiDetection: ['warn', 'block', 'off'].includes(p.pii_detection as string) ? p.pii_detection as 'warn' | 'block' | 'off' : undefined,
    };
  }

  // Validate alerts
  let alerts: TrustScopeConfig['alerts'];
  if (obj.alerts && typeof obj.alerts === 'object' && !Array.isArray(obj.alerts)) {
    const a = obj.alerts as Record<string, unknown>;
    alerts = {
      costThresholdDaily: typeof a.cost_threshold_daily === 'number' ? Math.max(0, a.cost_threshold_daily) : undefined,
      loopDetection: typeof a.loop_detection === 'boolean' ? a.loop_detection : undefined,
    };
  }

  return { version, projectId, agentId, policies, alerts };
}

export function loadConfig(dir: string = process.cwd()): TrustScopeConfig | null {
  const yamlPath = join(dir, '.trustscope.yaml');
  const ymlPath = join(dir, '.trustscope.yml');
  const jsonPath = join(dir, 'trustscope.json');

  let configPath: string | null = null;

  if (existsSync(yamlPath)) {
    configPath = yamlPath;
  } else if (existsSync(ymlPath)) {
    configPath = ymlPath;
  } else if (existsSync(jsonPath)) {
    configPath = jsonPath;
  }

  if (!configPath) {
    return null;
  }

  try {
    const content = readFileSync(configPath, 'utf-8');

    // Size check to prevent DoS
    if (content.length > MAX_CONFIG_FILE_SIZE) {
      console.warn(chalk.yellow(`Warning: Config file too large (max ${MAX_CONFIG_FILE_SIZE} bytes)`));
      return null;
    }

    let parsed: unknown;

    if (configPath.endsWith('.json')) {
      parsed = JSON.parse(content);
    } else {
      // Parse YAML with security options:
      // - maxAliasCount: 0 prevents alias-based attacks
      // - Strict mode for better error handling
      parsed = YAML.parse(content, {
        maxAliasCount: 0,  // Disable aliases (prevents billion laughs attack)
        strict: true,       // Strict mode
        uniqueKeys: true,   // Disallow duplicate keys
      });
    }

    // Validate the parsed config
    const validated = validateConfig(parsed);
    if (!validated) {
      console.warn(chalk.yellow(`Warning: Invalid config structure in ${configPath}`));
      return null;
    }

    return validated;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.warn(chalk.yellow(`Warning: Could not parse ${configPath}: ${message}`));
    return null;
  }
}
