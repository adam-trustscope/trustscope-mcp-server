import { platform, release } from 'node:os';
import { randomBytes } from 'node:crypto';
import chalk from 'chalk';
import type { FullScanResult, GitHubScanResult, UploadResponse } from '../types/cli.js';
import { getCredentials, requireAuth } from '../auth/index.js';
import { CLI_VERSION } from '../version.js';

const API_BASE_URL = process.env.TRUSTSCOPE_API_URL || 'https://api.trustscope.ai';

interface UploadPayload {
  scanType: 'local' | 'github';
  scanResult: unknown;
  securityFindings: unknown[];
  governanceFindings: unknown[];
  metadata: {
    cliVersion: string;
    os: string;
    nodeVersion: string;
    scanPath?: string;
    org?: string;
  };
}

export async function uploadScanResult(
  result: FullScanResult | GitHubScanResult,
  scanType: 'local' | 'github'
): Promise<UploadResponse> {
  const credentials = requireAuth();

  console.log(chalk.dim('\nUploading results to TrustScope Cloud...'));

  const payload: UploadPayload = {
    scanType,
    scanResult: scanType === 'local'
      ? (result as FullScanResult).scan
      : result,
    securityFindings: scanType === 'local'
      ? (result as FullScanResult).analysis.securityFindings
      : (result as GitHubScanResult).aggregatedFindings.security,
    governanceFindings: scanType === 'local'
      ? (result as FullScanResult).analysis.governanceFindings
      : (result as GitHubScanResult).aggregatedFindings.governance,
    metadata: {
      cliVersion: CLI_VERSION,
      os: `${platform()} ${release()}`,
      nodeVersion: process.version,
      scanPath: scanType === 'local' ? (result as FullScanResult).scan.scanPath : undefined,
      org: scanType === 'github' ? (result as GitHubScanResult).org : undefined,
    },
  };

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/cli/scan-results`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${credentials.accessToken}`,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({})) as { error?: string };
      throw new Error(errorData.error || `Upload failed with status ${response.status}`);
    }

    const uploadResponse = await response.json() as UploadResponse;

    console.log(chalk.green('\n✅ Upload successful!\n'));
    console.log(`View your report: ${chalk.cyan.bold(uploadResponse.reportUrl)}\n`);

    return uploadResponse;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Upload failed';

    // For demo purposes, create mock response if API is not available
    if (message.includes('fetch') || message.includes('ECONNREFUSED')) {
      console.log(chalk.yellow('\n⚠️  TrustScope API not available (demo mode)\n'));

      const mockResponse: UploadResponse = {
        reportId: 'demo_' + randomBytes(5).toString('hex'),
        reportUrl: 'https://app.trustscope.ai/reports/demo',
        summary: {
          criticalCount: scanType === 'local'
            ? (result as FullScanResult).analysis.summary.securityCounts.critical
            : (result as GitHubScanResult).summary.securityCounts.critical,
          highCount: scanType === 'local'
            ? (result as FullScanResult).analysis.summary.securityCounts.high
            : (result as GitHubScanResult).summary.securityCounts.high,
        },
      };

      console.log(chalk.dim('In production, results would be uploaded to TrustScope cloud.\n'));
      console.log(`Demo report URL: ${chalk.cyan.bold(mockResponse.reportUrl)}\n`);

      return mockResponse;
    }

    console.error(chalk.red(`\n❌ Upload failed: ${message}\n`));
    throw error;
  }
}

export async function promptForAuth(): Promise<boolean> {
  // Check if already authenticated
  const creds = getCredentials();
  if (creds) {
    return true;
  }

  // Import inquirer dynamically
  const inquirer = await import('inquirer');

  console.log(chalk.yellow('\n⚠️  Upload requires authentication.\n'));

  const { choice } = await inquirer.default.prompt([
    {
      type: 'list',
      name: 'choice',
      message: 'What would you like to do?',
      choices: [
        { name: 'Login to existing account', value: 'login' },
        { name: 'Sign up for free account', value: 'signup' },
        { name: 'Cancel', value: 'cancel' },
      ],
    },
  ]);

  if (choice === 'cancel') {
    return false;
  }

  if (choice === 'signup') {
    const open = await import('open');
    console.log(chalk.dim('\nOpening signup page...\n'));
    await open.default('https://app.trustscope.ai/signup?ref=cli-upload');
    console.log(chalk.dim('After signing up, run: trustscope login\n'));
    return false;
  }

  // Login
  const { login } = await import('../auth/index.js');
  await login();
  return getCredentials() !== null;
}
