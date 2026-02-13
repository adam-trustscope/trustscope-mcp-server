import { resolve } from 'node:path';
import chalk from 'chalk';
import open from 'open';
import {
  detectMcpConfigs,
  detectCodePatterns,
  detectPackageDeps,
} from '../detectors/index.js';
import { getCredentials, login } from '../auth/index.js';
import type { CodePatternFinding, DependencyFinding, MCPConfig } from '../types/cli.js';

const API_BASE_URL = process.env.TRUSTSCOPE_API_URL || 'https://api.trustscope.ai';
const DASHBOARD_URL = process.env.TRUSTSCOPE_DASHBOARD_URL || 'https://app.trustscope.ai';

// Map detected patterns to framework IDs
const FRAMEWORK_MAPPING: Record<string, string> = {
  langchain: 'langchain',
  crewai: 'crewai',
  autogen: 'autogen',
  semantic_kernel: 'semantic-kernel',
  llamaindex: 'llamaindex',
  openai_sdk: 'openai-agents-sdk',
  agents_sdk: 'openai-agents-sdk',
  vercel_ai: 'other',
  haystack: 'other',
};

// Map dependencies to provider IDs
const PROVIDER_MAPPING: Record<string, string> = {
  openai: 'openai',
  anthropic: 'anthropic',
  'anthropic-ai': 'anthropic',
  '@anthropic-ai/sdk': 'anthropic',
  'google-generativeai': 'google',
  '@google/generative-ai': 'google',
  '@ai-sdk/google': 'google',
  mistralai: 'mistral',
  '@mistralai/mistralai': 'mistral',
  '@ai-sdk/mistral': 'mistral',
  cohere: 'cohere',
  'cohere-ai': 'cohere',
  '@ai-sdk/cohere': 'cohere',
  groq: 'groq',
  'groq-sdk': 'groq',
  '@azure/openai': 'azure-openai',
  together: 'other',
  replicate: 'other',
};

// Map dependencies to framework IDs
const DEPENDENCY_FRAMEWORK_MAPPING: Record<string, string> = {
  langchain: 'langchain',
  'langchain-core': 'langchain',
  '@langchain/core': 'langchain',
  '@langchain/openai': 'langchain',
  '@langchain/anthropic': 'langchain',
  crewai: 'crewai',
  autogen: 'autogen',
  pyautogen: 'autogen',
  'semantic-kernel': 'semantic-kernel',
  'llama-index': 'llamaindex',
  'llama-index-core': 'llamaindex',
  llamaindex: 'llamaindex',
  agents: 'openai-agents-sdk',
};

export interface OnboardingScanResult {
  scan_id: string;
  timestamp: string;
  directory: string;
  detected: {
    framework: string | null;
    providers: string[];
    mcp_usage: boolean;
    mcp_servers: string[];
    language: 'python' | 'javascript' | 'both' | 'unknown';
    package_manager: 'pip' | 'npm' | 'both' | null;
  };
  files_scanned: number;
  recommendations: {
    primary_entry_point: 'sdk' | 'gateway' | 'mcp';
    additional_entry_points: string[];
    sdk_integration: string | null;
  };
}

function generateScanId(): string {
  return `scan_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function detectLanguage(dependencies: DependencyFinding[]): 'python' | 'javascript' | 'both' | 'unknown' {
  const hasPip = dependencies.some(d => d.source === 'pip');
  const hasNpm = dependencies.some(d => d.source === 'npm');

  if (hasPip && hasNpm) return 'both';
  if (hasPip) return 'python';
  if (hasNpm) return 'javascript';
  return 'unknown';
}

function detectPackageManager(dependencies: DependencyFinding[]): 'pip' | 'npm' | 'both' | null {
  const hasPip = dependencies.some(d => d.source === 'pip');
  const hasNpm = dependencies.some(d => d.source === 'npm');

  if (hasPip && hasNpm) return 'both';
  if (hasPip) return 'pip';
  if (hasNpm) return 'npm';
  return null;
}

function detectFramework(
  codePatterns: CodePatternFinding[],
  dependencies: DependencyFinding[]
): string | null {
  // First, check code patterns (more reliable for actual usage)
  const frameworkCounts: Record<string, number> = {};

  for (const pattern of codePatterns) {
    const frameworkId = FRAMEWORK_MAPPING[pattern.framework];
    if (frameworkId) {
      frameworkCounts[frameworkId] = (frameworkCounts[frameworkId] || 0) + 1;
    }
  }

  // If we found frameworks in code, use the most common one
  if (Object.keys(frameworkCounts).length > 0) {
    const sorted = Object.entries(frameworkCounts).sort((a, b) => b[1] - a[1]);
    return sorted[0][0];
  }

  // Fall back to dependencies
  for (const dep of dependencies) {
    const frameworkId = DEPENDENCY_FRAMEWORK_MAPPING[dep.name.toLowerCase()];
    if (frameworkId) {
      return frameworkId;
    }
  }

  return null;
}

function detectProviders(dependencies: DependencyFinding[]): string[] {
  const providers = new Set<string>();

  for (const dep of dependencies) {
    const providerId = PROVIDER_MAPPING[dep.name.toLowerCase()];
    if (providerId && providerId !== 'other') {
      providers.add(providerId);
    }
  }

  // Default to openai if no providers detected but we have AI dependencies
  if (providers.size === 0 && dependencies.length > 0) {
    providers.add('openai');
  }

  return Array.from(providers);
}

function getRecommendations(
  framework: string | null,
  hasMcp: boolean,
  providers: string[]
): OnboardingScanResult['recommendations'] {
  // Framework-based recommendations
  const sdkFrameworks = ['langchain', 'crewai', 'autogen', 'semantic-kernel', 'llamaindex'];
  const gatewayFrameworks = ['direct-api', 'other', null];

  let primaryEntryPoint: 'sdk' | 'gateway' | 'mcp' = 'gateway';
  let sdkIntegration: string | null = null;
  const additionalEntryPoints: string[] = [];

  if (framework && sdkFrameworks.includes(framework)) {
    primaryEntryPoint = 'sdk';
    sdkIntegration = `${framework}_callback`;
  } else if (framework === 'openai-agents-sdk') {
    primaryEntryPoint = 'sdk';
    sdkIntegration = 'openai_agents_wrapper';
  }

  if (hasMcp) {
    additionalEntryPoints.push('mcp');
    if (primaryEntryPoint !== 'sdk') {
      primaryEntryPoint = 'mcp';
    }
  }

  // Always suggest gateway as a backup option
  if (primaryEntryPoint !== 'gateway') {
    additionalEntryPoints.push('gateway');
  }

  return {
    primary_entry_point: primaryEntryPoint,
    additional_entry_points: additionalEntryPoints,
    sdk_integration: sdkIntegration,
  };
}

export async function runOnboardingScan(options: {
  dir: string;
  send: boolean;
  projectId?: string;
  verbose: boolean;
}): Promise<OnboardingScanResult> {
  const scanDir = resolve(options.dir);

  if (!options.send) {
    console.log(chalk.cyan(`\nScanning ${scanDir}...\n`));
  }

  // Run detectors in parallel
  const [mcpConfigs, codePatterns, dependencies] = await Promise.all([
    detectMcpConfigs(scanDir, options.verbose),
    detectCodePatterns(scanDir, options.verbose),
    detectPackageDeps(scanDir, options.verbose),
  ]);

  // Process results
  const framework = detectFramework(codePatterns, dependencies);
  const providers = detectProviders(dependencies);
  const hasMcp = mcpConfigs.length > 0 || mcpConfigs.some(c => c.servers.length > 0);
  const mcpServers = mcpConfigs.flatMap(c => c.servers.map(s => s.name));
  const language = detectLanguage(dependencies);
  const packageManager = detectPackageManager(dependencies);
  const recommendations = getRecommendations(framework, hasMcp, providers);

  const result: OnboardingScanResult = {
    scan_id: generateScanId(),
    timestamp: new Date().toISOString(),
    directory: scanDir,
    detected: {
      framework,
      providers,
      mcp_usage: hasMcp,
      mcp_servers: mcpServers,
      language,
      package_manager: packageManager,
    },
    files_scanned: codePatterns.length + dependencies.length,
    recommendations,
  };

  if (options.send) {
    await sendToCloud(result, options.projectId);
  } else {
    printLocalResult(result);
  }

  return result;
}

function printLocalResult(result: OnboardingScanResult): void {
  console.log(chalk.green('✓ Scan complete\n'));

  console.log(chalk.bold('Detected:'));
  console.log(`  Framework:    ${result.detected.framework || chalk.dim('none detected')}`);
  console.log(`  Providers:    ${result.detected.providers.join(', ') || chalk.dim('none detected')}`);
  console.log(`  Language:     ${result.detected.language}`);
  console.log(`  MCP Usage:    ${result.detected.mcp_usage ? 'yes' : 'no'}`);
  if (result.detected.mcp_servers.length > 0) {
    console.log(`  MCP Servers:  ${result.detected.mcp_servers.join(', ')}`);
  }

  console.log(chalk.bold('\nRecommendations:'));
  console.log(`  Primary Entry Point: ${result.recommendations.primary_entry_point}`);
  if (result.recommendations.additional_entry_points.length > 0) {
    console.log(`  Also Consider:       ${result.recommendations.additional_entry_points.join(', ')}`);
  }
  if (result.recommendations.sdk_integration) {
    console.log(`  SDK Integration:     ${result.recommendations.sdk_integration}`);
  }

  console.log(chalk.dim('\nTo send to TrustScope and open wizard:'));
  console.log(chalk.cyan('  trustscope scan --send\n'));

  // Also output JSON for programmatic use
  console.log(chalk.dim('JSON output:'));
  console.log(JSON.stringify(result, null, 2));
}

async function sendToCloud(result: OnboardingScanResult, projectId?: string): Promise<void> {
  // Check authentication
  let creds = getCredentials();

  if (!creds) {
    console.log(chalk.yellow('\n⚠️  Not logged in. Starting authentication...\n'));
    await login();
    creds = getCredentials();

    if (!creds) {
      console.log(chalk.red('Authentication failed. Please try again.\n'));
      return;
    }
  }

  console.log(chalk.cyan('\nSending scan results to TrustScope...\n'));

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/onboarding/cli-scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${creds.accessToken}`,
      },
      body: JSON.stringify({
        scan_id: result.scan_id,
        detected: result.detected,
        recommendations: result.recommendations,
        project_id: projectId,
      }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
      console.log(chalk.red(`Failed to send scan: ${error.detail || error.error}\n`));
      return;
    }

    const data = await response.json() as { scan_id: string };
    const wizardUrl = `${DASHBOARD_URL}/onboarding?scan=${data.scan_id}`;

    console.log(chalk.green('✓ Scan results sent successfully!\n'));
    console.log(chalk.bold('Open the wizard to continue:'));
    console.log(chalk.cyan(`  ${wizardUrl}\n`));

    // Attempt to open browser
    try {
      await open(wizardUrl);
      console.log(chalk.dim('(Opening browser...)\n'));
    } catch {
      console.log(chalk.dim('(Copy the URL above to continue in your browser)\n'));
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.log(chalk.red(`Failed to send scan: ${message}\n`));

    // Print local result as fallback
    console.log(chalk.dim('Showing local results instead:\n'));
    printLocalResult(result);
  }
}
