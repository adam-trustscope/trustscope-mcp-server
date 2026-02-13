import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, normalize } from 'node:path';

// Maximum file size to read (10MB) - prevents DoS
const MAX_FILE_SIZE = 10 * 1024 * 1024;

// Maximum path length (most filesystems support 4096)
const MAX_PATH_LENGTH = 4096;

/**
 * Expand ~ to home directory with validation.
 */
export function expandHomePath(filePath: string): string {
  if (!filePath || typeof filePath !== 'string') {
    throw new Error('Invalid file path');
  }

  if (filePath.length > MAX_PATH_LENGTH) {
    throw new Error('File path too long');
  }

  if (filePath.startsWith('~/')) {
    return join(homedir(), filePath.slice(2));
  }
  return filePath;
}

/**
 * Validate that a path is safe and doesn't traverse outside allowed directories.
 */
export function isPathSafe(inputPath: string, allowedBase?: string): boolean {
  if (!inputPath || typeof inputPath !== 'string') {
    return false;
  }

  if (inputPath.length > MAX_PATH_LENGTH) {
    return false;
  }

  // Normalize to resolve ../ and ./ components
  const normalized = normalize(inputPath);

  // Check for null bytes (path injection attack)
  if (normalized.includes('\0')) {
    return false;
  }

  // If an allowed base is specified, ensure the path stays within it
  if (allowedBase) {
    const resolvedBase = resolve(allowedBase);
    const resolvedPath = resolve(allowedBase, normalized);

    // Ensure the resolved path starts with the base path
    if (!resolvedPath.startsWith(resolvedBase + '/') && resolvedPath !== resolvedBase) {
      return false;
    }
  }

  return true;
}

/**
 * Safely resolve a path within a base directory.
 * Throws if the path escapes the base directory.
 */
export function safeResolvePath(basePath: string, ...paths: string[]): string {
  const resolvedBase = resolve(basePath);
  const resolvedFull = resolve(basePath, ...paths);

  // Prevent path traversal
  if (!resolvedFull.startsWith(resolvedBase + '/') && resolvedFull !== resolvedBase) {
    throw new Error('Path traversal detected');
  }

  return resolvedFull;
}

/**
 * Read a JSON file with size limits and validation.
 */
export function readJsonFile<T>(filePath: string): T | null {
  try {
    const fullPath = expandHomePath(filePath);

    if (!existsSync(fullPath)) {
      return null;
    }

    const content = readFileSync(fullPath, 'utf-8');

    // Size check
    if (content.length > MAX_FILE_SIZE) {
      console.warn(`File too large: ${filePath}`);
      return null;
    }

    return JSON.parse(content) as T;
  } catch {
    return null;
  }
}

/**
 * Read a text file with size limits.
 */
export function readTextFile(filePath: string): string | null {
  try {
    const fullPath = expandHomePath(filePath);

    if (!existsSync(fullPath)) {
      return null;
    }

    const content = readFileSync(fullPath, 'utf-8');

    // Size check
    if (content.length > MAX_FILE_SIZE) {
      console.warn(`File too large: ${filePath}`);
      return null;
    }

    return content;
  } catch {
    return null;
  }
}

export function fileExists(filePath: string): boolean {
  try {
    return existsSync(expandHomePath(filePath));
  } catch {
    return false;
  }
}

export function resolvePath(basePath: string, ...paths: string[]): string {
  return resolve(basePath, ...paths);
}

export function getRelativePath(basePath: string, fullPath: string): string {
  const resolvedBase = resolve(basePath);
  const resolvedFull = resolve(fullPath);
  if (resolvedFull.startsWith(resolvedBase + '/')) {
    return resolvedFull.slice(resolvedBase.length + 1);
  }
  if (resolvedFull === resolvedBase) {
    return '.';
  }
  return fullPath;
}

/**
 * Known secret prefixes for various services.
 * More accurate than generic patterns.
 */
const SECRET_PREFIXES = [
  // OpenAI
  { prefix: 'sk-', minLength: 40, name: 'OpenAI API key' },
  { prefix: 'sk-proj-', minLength: 40, name: 'OpenAI Project key' },

  // Anthropic
  { prefix: 'sk-ant-', minLength: 40, name: 'Anthropic API key' },

  // GitHub
  { prefix: 'ghp_', minLength: 36, name: 'GitHub PAT' },
  { prefix: 'gho_', minLength: 36, name: 'GitHub OAuth' },
  { prefix: 'ghs_', minLength: 36, name: 'GitHub App' },
  { prefix: 'ghr_', minLength: 36, name: 'GitHub Refresh' },

  // AWS
  { prefix: 'AKIA', minLength: 20, name: 'AWS Access Key' },
  { prefix: 'ABIA', minLength: 20, name: 'AWS STS' },
  { prefix: 'ACCA', minLength: 20, name: 'AWS CloudFront' },

  // Stripe
  { prefix: 'sk_live_', minLength: 30, name: 'Stripe Live Key' },
  { prefix: 'sk_test_', minLength: 30, name: 'Stripe Test Key' },
  { prefix: 'rk_live_', minLength: 30, name: 'Stripe Restricted Key' },

  // Slack
  { prefix: 'xoxb-', minLength: 50, name: 'Slack Bot Token' },
  { prefix: 'xoxp-', minLength: 50, name: 'Slack User Token' },
  { prefix: 'xoxa-', minLength: 50, name: 'Slack App Token' },

  // Google
  { prefix: 'AIza', minLength: 35, name: 'Google API Key' },

  // Twilio
  { prefix: 'SK', minLength: 32, name: 'Twilio API Key' },

  // SendGrid
  { prefix: 'SG.', minLength: 50, name: 'SendGrid API Key' },

  // Datadog
  { prefix: 'dd', minLength: 32, name: 'Datadog API Key' },

  // npm
  { prefix: 'npm_', minLength: 36, name: 'npm Token' },

  // PyPI
  { prefix: 'pypi-', minLength: 50, name: 'PyPI Token' },

  // Cohere
  { prefix: 'co-', minLength: 30, name: 'Cohere API Key' },

  // Mistral
  { prefix: 'mist-', minLength: 30, name: 'Mistral API Key' },

  // Together AI
  { prefix: 'tg-', minLength: 30, name: 'Together AI Key' },

  // Groq
  { prefix: 'gsk_', minLength: 30, name: 'Groq API Key' },

  // Replicate
  { prefix: 'r8_', minLength: 30, name: 'Replicate API Key' },
];

/**
 * Keywords that suggest a value is a secret.
 */
const SECRET_KEYWORDS = [
  'password', 'passwd', 'pwd',
  'secret', 'token', 'key', 'api_key', 'apikey',
  'auth', 'credential', 'cred',
  'private', 'priv_key', 'privatekey',
  'bearer', 'jwt', 'session',
  'access_token', 'refresh_token',
];

/**
 * Check if a value appears to be a secret/credential.
 * More accurate than simple regex matching.
 */
export function containsSecret(value: string): boolean {
  if (!value || typeof value !== 'string') {
    return false;
  }

  const trimmed = value.trim();

  // Check against known secret prefixes
  for (const { prefix, minLength } of SECRET_PREFIXES) {
    if (trimmed.startsWith(prefix) && trimmed.length >= minLength) {
      return true;
    }
  }

  // Check for high-entropy strings (likely generated secrets)
  // Only flag if it looks like a generated secret (alphanumeric, 32+ chars)
  if (trimmed.length >= 32 && /^[a-zA-Z0-9+/=_-]+$/.test(trimmed)) {
    // Calculate a simple entropy measure
    const uniqueChars = new Set(trimmed).size;
    const entropy = uniqueChars / trimmed.length;

    // High entropy (many unique characters relative to length) suggests randomness
    if (entropy > 0.4 && uniqueChars >= 10) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a key name suggests it contains a secret.
 */
export function isSecretKeyName(keyName: string): boolean {
  if (!keyName || typeof keyName !== 'string') {
    return false;
  }

  const normalized = keyName.toLowerCase();
  return SECRET_KEYWORDS.some(keyword => normalized.includes(keyword));
}

/**
 * Identify what type of secret a value appears to be.
 */
export function identifySecretType(value: string): string | null {
  if (!value || typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();

  for (const { prefix, minLength, name } of SECRET_PREFIXES) {
    if (trimmed.startsWith(prefix) && trimmed.length >= minLength) {
      return name;
    }
  }

  return null;
}

/**
 * Mask a secret value for safe display.
 */
export function maskSecret(value: string): string {
  if (!value || typeof value !== 'string') {
    return '********';
  }

  if (value.length <= 8) {
    return '********';
  }

  // Show first 4 and last 4 characters
  return value.slice(0, 4) + '****' + value.slice(-4);
}

/**
 * Check if a hostname is an internal/private IP address.
 * Handles various SSRF bypass techniques:
 * - Decimal IPs (2130706433 = 127.0.0.1)
 * - Octal IPs (0177.0.0.01 = 127.0.0.1)
 * - IPv6 variants ([::1], [0:0:0:0:0:0:0:1])
 * - Mixed IPv6 (::ffff:127.0.0.1)
 */
function isPrivateOrLocalAddress(hostname: string): boolean {
  const lower = hostname.toLowerCase();

  // Block obvious localhost variants
  const blockedHostnames = [
    'localhost',
    'localhost.localdomain',
    'local',
    '127.0.0.1',
    '0.0.0.0',
    '0',
    '::1',
    '[::1]',
    '[0:0:0:0:0:0:0:1]',
    '[0000:0000:0000:0000:0000:0000:0000:0001]',
  ];
  if (blockedHostnames.includes(lower)) {
    return true;
  }

  // Block IPv6 addresses (all bracketed addresses are suspicious in URLs)
  if (lower.startsWith('[') || lower.includes('::')) {
    return true;
  }

  // Block decimal IP addresses (single large number)
  // e.g., 2130706433 = 127.0.0.1
  if (/^\d+$/.test(hostname)) {
    const decimal = parseInt(hostname, 10);
    // Any valid decimal IP is suspicious in a URL
    if (decimal >= 0 && decimal <= 0xFFFFFFFF) {
      return true;
    }
  }

  // Block octal IP addresses (leading zeros)
  // e.g., 0177.0.0.01 = 127.0.0.1
  if (/^0\d/.test(hostname) || /\.\d*0\d/.test(hostname)) {
    // Contains octal-style notation
    const parts = hostname.split('.');
    if (parts.length === 4 && parts.every(p => /^\d+$/.test(p))) {
      return true; // Suspicious IP-like format with leading zeros
    }
  }

  // Block hex IP addresses
  // e.g., 0x7f.0x0.0x0.0x1 = 127.0.0.1
  if (/0x[0-9a-f]/i.test(hostname)) {
    return true;
  }

  // Standard IPv4 internal range checks
  const ipv4Match = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [, a, b, c] = ipv4Match.map(Number);

    // 127.0.0.0/8 - Loopback
    if (a === 127) return true;

    // 10.0.0.0/8 - Private
    if (a === 10) return true;

    // 172.16.0.0/12 - Private
    if (a === 172 && b >= 16 && b <= 31) return true;

    // 192.168.0.0/16 - Private
    if (a === 192 && b === 168) return true;

    // 169.254.0.0/16 - Link-local
    if (a === 169 && b === 254) return true;

    // 0.0.0.0/8 - Current network
    if (a === 0) return true;

    // 224.0.0.0/4 - Multicast
    if (a >= 224 && a <= 239) return true;

    // 240.0.0.0/4 - Reserved
    if (a >= 240) return true;
  }

  // Block cloud metadata endpoints
  const metadataHosts = [
    '169.254.169.254', // AWS, GCP, Azure metadata
    'metadata.google.internal',
    'metadata.goog',
    'instance-data',
  ];
  if (metadataHosts.some(h => lower === h || lower.endsWith('.' + h))) {
    return true;
  }

  return false;
}

/**
 * Validate a URL is safe (HTTPS, valid hostname).
 * Guards against SSRF attacks with comprehensive IP/hostname checks.
 */
export function isValidHttpsUrl(urlString: string): boolean {
  try {
    const url = new URL(urlString);

    // Must be HTTPS
    if (url.protocol !== 'https:') {
      return false;
    }

    // No credentials in URL
    if (url.username || url.password) {
      return false;
    }

    // No port (except implicit 443)
    if (url.port && url.port !== '443') {
      return false;
    }

    // Check for private/internal addresses
    if (isPrivateOrLocalAddress(url.hostname)) {
      return false;
    }

    // Hostname must have at least one dot (no single-label hostnames)
    // This prevents "localhost" variants and internal network names
    if (!url.hostname.includes('.')) {
      return false;
    }

    // Block common TLDs used for internal services
    const blockedTlds = ['.local', '.internal', '.corp', '.home', '.lan', '.intranet'];
    const lowerHostname = url.hostname.toLowerCase();
    if (blockedTlds.some(tld => lowerHostname.endsWith(tld))) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Validate a URL allowing localhost for development.
 */
export function isValidUrl(urlString: string, allowLocalhost: boolean = false): boolean {
  try {
    const url = new URL(urlString);

    // Must be HTTP or HTTPS
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      return false;
    }

    // No credentials in URL
    if (url.username || url.password) {
      return false;
    }

    // When allowing localhost, still block dangerous patterns
    if (allowLocalhost) {
      const hostname = url.hostname.toLowerCase();

      // Allow localhost and 127.0.0.1 explicitly
      const allowedLocal = ['localhost', '127.0.0.1', '0.0.0.0'];
      if (allowedLocal.includes(hostname)) {
        return true;
      }

      // For non-localhost, use the strict HTTPS validation
      if (url.protocol === 'https:') {
        return isValidHttpsUrl(urlString);
      }

      // For HTTP, check for private IPs (block internal network access)
      if (isPrivateOrLocalAddress(hostname)) {
        return false;
      }

      return true;
    }

    return isValidHttpsUrl(urlString);
  } catch {
    return false;
  }
}

/**
 * Log a message conditionally based on verbose flag.
 */
export function log(message: string, verbose: boolean = false): void {
  if (verbose) {
    console.log(`[trustscope] ${message}`);
  }
}

/**
 * Sanitize an error message for display (remove sensitive info).
 */
export function sanitizeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    let message = error.message;

    // Remove potential secrets from error messages
    for (const { prefix } of SECRET_PREFIXES) {
      const regex = new RegExp(`${prefix}[a-zA-Z0-9_-]+`, 'gi');
      message = message.replace(regex, `${prefix}****`);
    }

    // Remove file paths that might leak info
    message = message.replace(/\/Users\/[^/\s]+/g, '/Users/***');
    message = message.replace(/\/home\/[^/\s]+/g, '/home/***');

    return message;
  }

  return 'An unknown error occurred';
}
