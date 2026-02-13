import chalk from 'chalk';
import boxen from 'boxen';
import { getCredentials } from '../auth/index.js';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { TrustScopeConfig } from '../types/cli.js';

const API_BASE_URL = process.env.TRUSTSCOPE_API_URL || 'https://api.trustscope.ai';

interface DoctorResult {
  authentication: 'pass' | 'fail' | 'warn';
  apiKey: 'pass' | 'fail' | 'warn';
  projectExists: 'pass' | 'fail' | 'warn';
  traceTest: 'pass' | 'fail' | 'warn';
  config: 'pass' | 'fail' | 'warn';
  messages: string[];
}

export async function runDoctor(): Promise<void> {
  console.log(boxen(chalk.cyan('TrustScope Doctor'), {
    padding: 1,
    borderStyle: 'round',
    borderColor: 'cyan',
  }));
  console.log(chalk.dim('\nChecking your TrustScope setup...\n'));

  const result: DoctorResult = {
    authentication: 'fail',
    apiKey: 'fail',
    projectExists: 'fail',
    traceTest: 'fail',
    config: 'warn',
    messages: [],
  };

  // 1. Check authentication
  const creds = getCredentials();
  if (creds && creds.user?.email) {
    console.log(chalk.green('✓') + ' Authentication');
    console.log(chalk.dim(`  Logged in as ${creds.user.email}`));
    result.authentication = 'pass';
  } else if (creds) {
    // Credentials exist but in old format
    console.log(chalk.yellow('⚠') + ' Authentication');
    console.log(chalk.dim('  Credentials found but may need refresh. Run: trustscope login'));
    result.authentication = 'warn';
    result.messages.push('Re-authenticate with "trustscope login" for full access');
  } else {
    console.log(chalk.red('✗') + ' Authentication');
    console.log(chalk.dim('  Not logged in. Run: trustscope login'));
    result.messages.push('Run "trustscope login" to authenticate');
    return printSummary(result);
  }

  // 2. Check for local config
  const configPath = join(process.cwd(), '.trustscope.json');
  let config: TrustScopeConfig | null = null;

  if (existsSync(configPath)) {
    try {
      const content = readFileSync(configPath, 'utf-8');
      config = JSON.parse(content) as TrustScopeConfig;
      console.log(chalk.green('✓') + ' Local config (.trustscope.json)');
      if (config.projectId) {
        console.log(chalk.dim(`  Project: ${config.projectId}`));
      }
      result.config = 'pass';
    } catch {
      console.log(chalk.yellow('⚠') + ' Local config (.trustscope.json)');
      console.log(chalk.dim('  Config file exists but could not be parsed'));
      result.config = 'warn';
    }
  } else {
    console.log(chalk.yellow('⚠') + ' Local config (.trustscope.json)');
    console.log(chalk.dim('  No local config found (optional)'));
    result.config = 'warn';
  }

  // 3. Check API key from environment
  const apiKey = process.env.TRUSTSCOPE_API_KEY;
  const projectId = config?.projectId || process.env.TRUSTSCOPE_PROJECT_ID;

  if (apiKey) {
    console.log(chalk.green('✓') + ' API Key');
    console.log(chalk.dim(`  Found in TRUSTSCOPE_API_KEY (${apiKey.slice(0, 12)}...)`));
    result.apiKey = 'pass';
  } else {
    console.log(chalk.yellow('⚠') + ' API Key');
    console.log(chalk.dim('  No TRUSTSCOPE_API_KEY environment variable set'));
    result.apiKey = 'warn';
    result.messages.push('Set TRUSTSCOPE_API_KEY environment variable for trace ingestion');
  }

  // 4. Check if project exists (requires API key)
  if (projectId && apiKey) {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/onboarding/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${creds.accessToken}`,
        },
        body: JSON.stringify({ project_id: projectId }),
      });

      if (response.ok) {
        const data = await response.json() as { valid: boolean; project_name: string; trace_count: number };
        console.log(chalk.green('✓') + ' Project verification');
        console.log(chalk.dim(`  Project "${data.project_name}" exists and is accessible`));
        console.log(chalk.dim(`  Traces received: ${data.trace_count}`));
        result.projectExists = 'pass';
      } else {
        console.log(chalk.red('✗') + ' Project verification');
        console.log(chalk.dim(`  Project ${projectId} not found or not accessible`));
        result.projectExists = 'fail';
        result.messages.push('Project not found. Check your project ID.');
      }
    } catch (error) {
      console.log(chalk.yellow('⚠') + ' Project verification');
      console.log(chalk.dim('  Could not connect to TrustScope API'));
      result.projectExists = 'warn';
    }
  } else if (!projectId) {
    console.log(chalk.yellow('⚠') + ' Project verification');
    console.log(chalk.dim('  No project ID configured. Set TRUSTSCOPE_PROJECT_ID or add to .trustscope.json'));
    result.projectExists = 'warn';
    result.messages.push('Configure a project ID to enable tracing');
  }

  // 5. Test trace submission
  if (apiKey && projectId) {
    console.log(chalk.dim('\nTesting trace submission...'));
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/onboarding/test-trace`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${creds.accessToken}`,
        },
        body: JSON.stringify({ project_id: projectId }),
      });

      if (response.ok) {
        console.log(chalk.green('✓') + ' Test trace sent');
        console.log(chalk.dim('  Trace was successfully ingested'));
        result.traceTest = 'pass';
      } else {
        const data = await response.json() as { error?: string; detail?: string };
        console.log(chalk.red('✗') + ' Test trace failed');
        console.log(chalk.dim(`  ${data.error || data.detail || 'Unknown error'}`));
        result.traceTest = 'fail';
      }
    } catch (error) {
      console.log(chalk.yellow('⚠') + ' Test trace');
      console.log(chalk.dim('  Could not send test trace'));
      result.traceTest = 'warn';
    }
  } else {
    console.log(chalk.yellow('⚠') + ' Test trace');
    console.log(chalk.dim('  Skipped (requires API key and project ID)'));
    result.traceTest = 'warn';
  }

  printSummary(result);
}

function printSummary(result: DoctorResult): void {
  console.log('');

  // Count results excluding the messages array
  const checks = [result.authentication, result.apiKey, result.projectExists, result.traceTest, result.config];
  const passCount = checks.filter(v => v === 'pass').length;
  const failCount = checks.filter(v => v === 'fail').length;
  const warnCount = checks.filter(v => v === 'warn').length;

  if (failCount === 0 && warnCount === 0) {
    console.log(chalk.green.bold('✅ All checks passed!\n'));
    console.log('Your TrustScope setup is ready to use.');
    console.log(`View dashboard: ${chalk.cyan('https://app.trustscope.ai/dashboard')}\n`);
  } else if (failCount === 0) {
    console.log(chalk.yellow.bold('⚠️  Setup mostly complete\n'));
    console.log(`${passCount} checks passed, ${warnCount} warnings`);
  } else {
    console.log(chalk.red.bold('❌ Setup incomplete\n'));
    console.log(`${passCount} checks passed, ${failCount} failed, ${warnCount} warnings`);
  }

  if (result.messages.length > 0) {
    console.log(chalk.dim('\nRecommendations:'));
    result.messages.forEach(msg => {
      console.log(chalk.dim(`  • ${msg}`));
    });
    console.log('');
  }
}
