import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, unlinkSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import open from 'open';
import chalk from 'chalk';
import type { Credentials, DeviceCodeResponse } from '../types/cli.js';

const TRUSTSCOPE_DIR = join(homedir(), '.trustscope');
const CREDENTIALS_FILE = join(TRUSTSCOPE_DIR, 'credentials.json');
const API_BASE_URL = process.env.TRUSTSCOPE_API_URL || 'https://api.trustscope.ai';

function ensureDir(): void {
  if (!existsSync(TRUSTSCOPE_DIR)) {
    mkdirSync(TRUSTSCOPE_DIR, { recursive: true });
  }
}

export function getCredentials(): Credentials | null {
  if (!existsSync(CREDENTIALS_FILE)) {
    return null;
  }

  try {
    const content = readFileSync(CREDENTIALS_FILE, 'utf-8');
    const creds = JSON.parse(content) as Credentials;

    // Validate the expiration date
    const expiresAt = new Date(creds.expiresAt);
    if (isNaN(expiresAt.getTime())) {
      // Invalid date format - treat as expired
      return null;
    }

    // Check if expired
    if (expiresAt <= new Date()) {
      // TODO: Implement token refresh
      return null;
    }

    return creds;
  } catch {
    return null;
  }
}

export function saveCredentials(credentials: Credentials): void {
  ensureDir();
  writeFileSync(CREDENTIALS_FILE, JSON.stringify(credentials, null, 2));

  // Set file permissions to 0600 (owner read/write only)
  try {
    chmodSync(CREDENTIALS_FILE, 0o600);
  } catch {
    // May fail on Windows
  }
}

export function clearCredentials(): void {
  if (existsSync(CREDENTIALS_FILE)) {
    unlinkSync(CREDENTIALS_FILE);
  }
}

export function isLoggedIn(): boolean {
  const creds = getCredentials();
  return creds !== null;
}

export function getCurrentUser(): { email: string; org: string } | null {
  const creds = getCredentials();
  if (!creds || !creds.user) return null;
  return { email: creds.user.email || 'unknown', org: creds.user.org || 'unknown' };
}

async function requestDeviceCode(): Promise<DeviceCodeResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/cli/device-code`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: 'trustscope-cli',
        scope: 'traces:write traces:read attestations:write',
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Failed to get device code: ${response.status} ${errorBody}`);
    }

    return response.json() as Promise<DeviceCodeResponse>;
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error('Request timed out while getting device code');
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function pollForToken(
  deviceCode: string,
  interval: number,
  expiresIn: number
): Promise<Credentials> {
  const startTime = Date.now();
  const maxTime = expiresIn * 1000;

  while (Date.now() - startTime < maxTime) {
    await new Promise(resolve => setTimeout(resolve, interval * 1000));

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/cli/device-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_code: deviceCode }),
        signal: controller.signal,
      });

      if (response.ok) {
        return response.json() as Promise<Credentials>;
      }

      const data = await response.json() as { error?: string };

      if (data.error === 'authorization_pending') {
        continue;
      }

      if (data.error === 'expired_token') {
        throw new Error('Authentication expired. Please try again.');
      }

      if (data.error === 'access_denied') {
        throw new Error('Authentication denied.');
      }
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        // Timeout occurred, continue polling
        continue;
      }
      if (error instanceof Error && error.message.includes('Authentication')) {
        throw error;
      }
      // Network error, continue polling
    } finally {
      clearTimeout(timeoutId);
    }
  }

  throw new Error('Authentication timed out. Please try again.');
}

export async function login(): Promise<void> {
  // Check if already logged in
  const existing = getCredentials();
  if (existing) {
    console.log(chalk.yellow(`\nAlready logged in as ${existing.user.email}`));
    console.log(chalk.dim('Use "trustscope logout" to sign out first.\n'));
    return;
  }

  console.log(chalk.cyan('\n🔐 Authenticating with TrustScope...\n'));

  try {
    // Request device code
    const deviceCode = await requestDeviceCode();

    // Build signup URL with device code - new users go straight to signup
    // After signup completes, frontend redirects to /device with the code
    const baseUrl = API_BASE_URL.replace('api.', 'app.');
    const verificationUrl = `${baseUrl}/signup?redirect_url=/device&code=${deviceCode.user_code}`;

    console.log(chalk.bold('Opening browser to create your account...'));
    console.log(chalk.dim(`Or visit: ${verificationUrl}`));
    console.log(chalk.dim(`Code: ${chalk.bold(deviceCode.user_code)}\n`));

    // Open browser
    try {
      await open(verificationUrl);
    } catch {
      // Browser failed to open, user can use manual URL
    }

    console.log(chalk.dim('Waiting for authentication...'));

    // Poll for token
    const credentials = await pollForToken(
      deviceCode.device_code,
      deviceCode.interval,
      deviceCode.expires_in
    );

    // Save credentials
    saveCredentials(credentials);

    console.log(chalk.green('\n✅ Success!\n'));
    console.log(`Logged in as: ${chalk.bold(credentials.user.email)}`);
    console.log(`Organization: ${chalk.bold(credentials.user.org)}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Authentication failed';

    // For demo purposes, create mock credentials if API is not available
    if (message.includes('fetch') || message.includes('ECONNREFUSED')) {
      console.log(chalk.yellow('\n⚠️  TrustScope API not available (demo mode)\n'));
      console.log(chalk.dim('In production, this would authenticate with the TrustScope cloud.\n'));

      // Create demo credentials for testing
      const demoCredentials: Credentials = {
        accessToken: 'ts_demo_token_' + randomBytes(16).toString('hex'),
        refreshToken: 'ts_demo_refresh_' + randomBytes(16).toString('hex'),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        user: {
          id: 'demo_user_id',
          email: 'demo@trustscope.ai',
          org: 'TrustScope Demo',
          orgId: 'demo_org_id',
        },
      };

      saveCredentials(demoCredentials);

      console.log(chalk.green('✅ Demo credentials created\n'));
      console.log(`Logged in as: ${chalk.bold(demoCredentials.user.email)}`);
      console.log(`Organization: ${chalk.bold(demoCredentials.user.org)}\n`);
      return;
    }

    console.error(chalk.red(`\n❌ ${message}\n`));
    process.exit(1);
  }
}

export async function logout(): Promise<void> {
  const creds = getCredentials();

  if (!creds) {
    console.log(chalk.yellow('\nNot logged in.\n'));
    return;
  }

  clearCredentials();
  console.log(chalk.green('\n✅ Logged out successfully.\n'));
}

export function requireAuth(): Credentials {
  const creds = getCredentials();

  if (!creds) {
    console.log(chalk.yellow('\n⚠️  Authentication required.\n'));
    console.log('Please run: ' + chalk.cyan('trustscope login\n'));
    process.exit(1);
  }

  return creds;
}
