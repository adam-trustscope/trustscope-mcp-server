/**
 * TrustScope Cloud Connect Command
 *
 * Connect to TrustScope cloud and optionally import existing traces.
 */

import chalk from 'chalk';
import readline from 'node:readline';
import { getCredentials, login, isLoggedIn, getCurrentUser } from '../auth/index.js';
import { importTracesToCloud, countLocalTraces } from '../cloud/import.js';

export interface CloudConnectOptions {
  import?: boolean;
  verbose?: boolean;
}

/**
 * Prompt user for yes/no
 */
async function promptYesNo(question: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(`${question} [y/N] `, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

/**
 * Run cloud connect flow
 */
export async function runCloudConnect(options?: CloudConnectOptions): Promise<void> {
  console.log('');
  console.log(chalk.bold('  TrustScope Cloud Connect'));
  console.log(chalk.dim('  ────────────────────────'));
  console.log('');

  // Check if already connected
  if (isLoggedIn()) {
    const user = getCurrentUser();
    console.log(chalk.green(`  ✓ Already connected to TrustScope Cloud`));
    console.log(`    Email: ${chalk.bold(user?.email || 'unknown')}`);
    console.log(`    Organization: ${chalk.bold(user?.org || 'unknown')}`);
    console.log('');

    // Check for local traces to import
    const localTraceCount = countLocalTraces();
    if (localTraceCount > 0 && options?.import !== false) {
      console.log(chalk.dim(`  Found ${localTraceCount.toLocaleString()} local traces.`));
      console.log('');

      const shouldImport = options?.import || await promptYesNo('  Import local traces to cloud?');

      if (shouldImport) {
        console.log('');
        console.log(chalk.dim('  Importing traces (PII will be redacted)...'));

        try {
          const result = await importTracesToCloud({ verbose: options?.verbose });

          console.log('');
          console.log(chalk.green(`  ✓ Import complete`));
          console.log(`    Imported: ${result.imported.toLocaleString()}`);
          if (result.skipped > 0) {
            console.log(chalk.dim(`    Skipped (already exists): ${result.skipped.toLocaleString()}`));
          }
          if (result.failed > 0) {
            console.log(chalk.yellow(`    Failed: ${result.failed.toLocaleString()}`));
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Unknown error';
          console.log(chalk.red(`  ✗ Import failed: ${message}`));
        }
      }
    } else if (localTraceCount === 0) {
      console.log(chalk.dim('  No local traces to import.'));
    }

    console.log('');
    return;
  }

  // Not connected - initiate login flow
  console.log(chalk.dim('  Connecting to TrustScope Cloud...'));
  console.log('');

  try {
    await login();

    // After successful login, check for local traces
    const localTraceCount = countLocalTraces();
    if (localTraceCount > 0) {
      console.log(chalk.dim(`  Found ${localTraceCount.toLocaleString()} local traces.`));
      console.log('');

      const shouldImport = options?.import || await promptYesNo('  Import local traces to cloud?');

      if (shouldImport) {
        console.log('');
        console.log(chalk.dim('  Importing traces (PII will be redacted)...'));

        try {
          const result = await importTracesToCloud({ verbose: options?.verbose });

          console.log('');
          console.log(chalk.green(`  ✓ Import complete`));
          console.log(`    Imported: ${result.imported.toLocaleString()}`);
          if (result.skipped > 0) {
            console.log(chalk.dim(`    Skipped (already exists): ${result.skipped.toLocaleString()}`));
          }
          if (result.failed > 0) {
            console.log(chalk.yellow(`    Failed: ${result.failed.toLocaleString()}`));
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Unknown error';
          console.log(chalk.red(`  ✗ Import failed: ${message}`));
        }
      }
    }

    console.log('');
    console.log(chalk.green('  ✓ Connected to TrustScope Cloud'));
    console.log(chalk.dim('  Traces will now sync automatically.'));
    console.log('');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.log(chalk.red(`  ✗ Connection failed: ${message}`));
    console.log('');
    process.exit(1);
  }
}

/**
 * Show cloud connection status
 */
export async function runCloudStatus(): Promise<void> {
  console.log('');
  console.log(chalk.bold('  TrustScope Cloud Status'));
  console.log(chalk.dim('  ───────────────────────'));
  console.log('');

  if (isLoggedIn()) {
    const user = getCurrentUser();
    const creds = getCredentials();

    console.log(`  ${chalk.green('●')} Connected`);
    console.log('');
    console.log(`  Email:        ${chalk.bold(user?.email || 'unknown')}`);
    console.log(`  Organization: ${chalk.bold(user?.org || 'unknown')}`);

    if (creds?.expiresAt) {
      const expiresAt = new Date(creds.expiresAt);
      const now = new Date();
      const daysRemaining = Math.ceil((expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      console.log(`  Session:      ${daysRemaining > 0 ? `${daysRemaining} days remaining` : 'Expired'}`);
    }
  } else {
    console.log(`  ${chalk.red('●')} Not connected`);
    console.log('');
    console.log(chalk.dim('  Run "trustscope cloud connect" to connect.'));
  }

  // Show local trace count
  const localTraceCount = countLocalTraces();
  console.log('');
  console.log(`  Local traces: ${localTraceCount.toLocaleString()}`);

  console.log('');
}
