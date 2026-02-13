/**
 * Input validation for CLI arguments.
 * Ensures all user inputs are safe and within expected bounds.
 */

import { existsSync } from 'node:fs';
import { resolve, isAbsolute } from 'node:path';

// Validation limits
const MAX_PATH_LENGTH = 4096;
const MAX_ORG_NAME_LENGTH = 256;
const MAX_REPO_NAME_LENGTH = 256;
const MAX_PORT = 65535;
const MIN_PORT = 1;
const MAX_TIMEOUT_MINUTES = 1440; // 24 hours
const MAX_RPM = 10000;
const MAX_COST = 100000;

export interface ValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validate a directory path for scanning.
 */
export function validateDirectory(dir: string): ValidationResult {
  if (!dir || typeof dir !== 'string') {
    return { valid: false, error: 'Directory path is required' };
  }

  if (dir.length > MAX_PATH_LENGTH) {
    return { valid: false, error: 'Directory path is too long' };
  }

  // Check for null bytes BEFORE resolve (security: prevent path injection)
  if (dir.includes('\0')) {
    return { valid: false, error: 'Directory path contains invalid characters' };
  }

  // Resolve to absolute path
  const resolved = isAbsolute(dir) ? dir : resolve(process.cwd(), dir);

  // Also check resolved path for null bytes (belt and suspenders)
  if (resolved.includes('\0')) {
    return { valid: false, error: 'Directory path contains invalid characters' };
  }

  // Ensure resolved path stays within cwd for relative paths
  // This prevents path traversal attacks like "../../../etc"
  if (!isAbsolute(dir)) {
    const cwd = resolve(process.cwd());
    if (!resolved.startsWith(cwd + '/') && resolved !== cwd) {
      return { valid: false, error: 'Directory path escapes current directory' };
    }
  }

  // Check if directory exists
  if (!existsSync(resolved)) {
    return { valid: false, error: 'Directory does not exist' };
  }

  return { valid: true };
}

/**
 * Validate a GitHub organization name.
 */
export function validateGitHubOrg(org: string): ValidationResult {
  if (!org || typeof org !== 'string') {
    return { valid: false, error: 'Organization name is required' };
  }

  if (org.length > MAX_ORG_NAME_LENGTH) {
    return { valid: false, error: 'Organization name is too long' };
  }

  // GitHub org names: alphanumeric and hyphens, cannot start/end with hyphen
  const validOrgPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/;
  if (!validOrgPattern.test(org)) {
    return { valid: false, error: 'Invalid organization name format' };
  }

  return { valid: true };
}

/**
 * Validate a GitHub repository in owner/repo format.
 */
export function validateGitHubRepo(repo: string): ValidationResult {
  if (!repo || typeof repo !== 'string') {
    return { valid: false, error: 'Repository name is required' };
  }

  if (repo.length > MAX_REPO_NAME_LENGTH) {
    return { valid: false, error: 'Repository name is too long' };
  }

  const parts = repo.split('/');
  if (parts.length !== 2) {
    return { valid: false, error: 'Repository must be in owner/repo format' };
  }

  const [owner, name] = parts;

  // Validate owner
  const ownerValidation = validateGitHubOrg(owner);
  if (!ownerValidation.valid) {
    return { valid: false, error: `Invalid owner: ${ownerValidation.error}` };
  }

  // Validate repo name: alphanumeric, hyphens, underscores, dots
  const validRepoPattern = /^[a-zA-Z0-9._-]+$/;
  if (!validRepoPattern.test(name)) {
    return { valid: false, error: 'Invalid repository name format' };
  }

  // Cannot be . or ..
  if (name === '.' || name === '..') {
    return { valid: false, error: 'Invalid repository name' };
  }

  return { valid: true };
}

/**
 * Validate a port number.
 */
export function validatePort(port: string | number): ValidationResult {
  const portNum = typeof port === 'string' ? parseInt(port, 10) : port;

  if (isNaN(portNum)) {
    return { valid: false, error: 'Port must be a number' };
  }

  if (portNum < MIN_PORT || portNum > MAX_PORT) {
    return { valid: false, error: `Port must be between ${MIN_PORT} and ${MAX_PORT}` };
  }

  return { valid: true };
}

/**
 * Validate timeout in minutes.
 */
export function validateTimeout(timeout: string | number): ValidationResult {
  const timeoutNum = typeof timeout === 'string' ? parseInt(timeout, 10) : timeout;

  if (isNaN(timeoutNum)) {
    return { valid: false, error: 'Timeout must be a number' };
  }

  if (timeoutNum <= 0) {
    return { valid: false, error: 'Timeout must be positive' };
  }

  if (timeoutNum > MAX_TIMEOUT_MINUTES) {
    return { valid: false, error: `Timeout cannot exceed ${MAX_TIMEOUT_MINUTES} minutes` };
  }

  return { valid: true };
}

/**
 * Validate max requests per minute.
 */
export function validateMaxRpm(rpm: string | number): ValidationResult {
  const rpmNum = typeof rpm === 'string' ? parseInt(rpm, 10) : rpm;

  if (isNaN(rpmNum)) {
    return { valid: false, error: 'Max RPM must be a number' };
  }

  if (rpmNum <= 0) {
    return { valid: false, error: 'Max RPM must be positive' };
  }

  if (rpmNum > MAX_RPM) {
    return { valid: false, error: `Max RPM cannot exceed ${MAX_RPM}` };
  }

  return { valid: true };
}

/**
 * Validate max cost in dollars.
 */
export function validateMaxCost(cost: string | number): ValidationResult {
  const costNum = typeof cost === 'string' ? parseFloat(cost) : cost;

  if (isNaN(costNum)) {
    return { valid: false, error: 'Max cost must be a number' };
  }

  if (costNum <= 0) {
    return { valid: false, error: 'Max cost must be positive' };
  }

  if (costNum > MAX_COST) {
    return { valid: false, error: `Max cost cannot exceed $${MAX_COST}` };
  }

  return { valid: true };
}

/**
 * Validate an output file path.
 */
export function validateOutputPath(outputPath: string): ValidationResult {
  if (!outputPath || typeof outputPath !== 'string') {
    return { valid: false, error: 'Output path is required' };
  }

  if (outputPath.length > MAX_PATH_LENGTH) {
    return { valid: false, error: 'Output path is too long' };
  }

  // Check for null bytes
  if (outputPath.includes('\0')) {
    return { valid: false, error: 'Output path contains invalid characters' };
  }

  // Resolve to absolute path
  const resolved = isAbsolute(outputPath) ? outputPath : resolve(process.cwd(), outputPath);

  // Check the output path doesn't escape current directory
  // (optional, could be too restrictive for some use cases)
  // For now, we just ensure it's a valid path format

  // Check for obviously dangerous paths
  const dangerousPaths = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin'];
  const lowerResolved = resolved.toLowerCase();
  for (const dangerous of dangerousPaths) {
    if (lowerResolved.startsWith(dangerous)) {
      return { valid: false, error: 'Cannot write to system directories' };
    }
  }

  return { valid: true };
}

/**
 * Validate output format.
 */
export function validateFormat(format: string): ValidationResult {
  const validFormats = ['terminal', 'json', 'sarif'];

  if (!format || typeof format !== 'string') {
    return { valid: false, error: 'Format is required' };
  }

  if (!validFormats.includes(format.toLowerCase())) {
    return { valid: false, error: `Invalid format. Must be one of: ${validFormats.join(', ')}` };
  }

  return { valid: true };
}

/**
 * Validate loop threshold.
 */
export function validateLoopThreshold(threshold: string | number): ValidationResult {
  const thresholdNum = typeof threshold === 'string' ? parseInt(threshold, 10) : threshold;

  if (isNaN(thresholdNum)) {
    return { valid: false, error: 'Loop threshold must be a number' };
  }

  if (thresholdNum < 2) {
    return { valid: false, error: 'Loop threshold must be at least 2' };
  }

  if (thresholdNum > 100) {
    return { valid: false, error: 'Loop threshold cannot exceed 100' };
  }

  return { valid: true };
}

/**
 * Validate max repos for GitHub org scan.
 */
export function validateMaxRepos(maxRepos: string | number): ValidationResult {
  const maxReposNum = typeof maxRepos === 'string' ? parseInt(maxRepos, 10) : maxRepos;

  if (isNaN(maxReposNum)) {
    return { valid: false, error: 'Max repos must be a number' };
  }

  if (maxReposNum <= 0) {
    return { valid: false, error: 'Max repos must be positive' };
  }

  if (maxReposNum > 10000) {
    return { valid: false, error: 'Max repos cannot exceed 10000' };
  }

  return { valid: true };
}

/**
 * Validate project ID format.
 */
export function validateProjectId(projectId: string): ValidationResult {
  if (!projectId || typeof projectId !== 'string') {
    return { valid: false, error: 'Project ID is required' };
  }

  if (projectId.length > 100) {
    return { valid: false, error: 'Project ID is too long' };
  }

  // Project IDs should be alphanumeric with underscores and hyphens
  const validPattern = /^[a-zA-Z0-9_-]+$/;
  if (!validPattern.test(projectId)) {
    return { valid: false, error: 'Invalid project ID format' };
  }

  return { valid: true };
}

/**
 * Helper to validate and exit on error.
 */
export function validateOrExit(result: ValidationResult, exitCode: number = 1): void {
  if (!result.valid) {
    console.error(`Error: ${result.error}`);
    process.exit(exitCode);
  }
}

/**
 * Validate all scan command options.
 */
export function validateScanOptions(options: {
  dir?: string;
  github?: string;
  repo?: string;
  output?: string;
  format?: string;
  maxRepos?: string | number;
}): ValidationResult {
  // Validate directory if specified
  if (options.dir) {
    const dirResult = validateDirectory(options.dir);
    if (!dirResult.valid) return dirResult;
  }

  // Validate GitHub org if specified
  if (options.github) {
    const orgResult = validateGitHubOrg(options.github);
    if (!orgResult.valid) return orgResult;
  }

  // Validate repo if specified
  if (options.repo) {
    const repoResult = validateGitHubRepo(options.repo);
    if (!repoResult.valid) return repoResult;
  }

  // Cannot specify both github and repo
  if (options.github && options.repo) {
    return { valid: false, error: 'Cannot specify both --github and --repo' };
  }

  // Validate output path if specified
  if (options.output) {
    const outputResult = validateOutputPath(options.output);
    if (!outputResult.valid) return outputResult;
  }

  // Validate format if specified
  if (options.format) {
    const formatResult = validateFormat(options.format);
    if (!formatResult.valid) return formatResult;
  }

  // Validate max repos if specified
  if (options.maxRepos !== undefined) {
    const maxReposResult = validateMaxRepos(options.maxRepos);
    if (!maxReposResult.valid) return maxReposResult;
  }

  return { valid: true };
}

/**
 * Validate all watch command options.
 */
export function validateWatchOptions(options: {
  port?: string | number;
  timeout?: string | number;
  maxRpm?: string | number;
  maxCost?: string | number;
  loopThreshold?: string | number;
}): ValidationResult {
  if (options.port !== undefined) {
    const portResult = validatePort(options.port);
    if (!portResult.valid) return portResult;
  }

  if (options.timeout !== undefined) {
    const timeoutResult = validateTimeout(options.timeout);
    if (!timeoutResult.valid) return timeoutResult;
  }

  if (options.maxRpm !== undefined) {
    const rpmResult = validateMaxRpm(options.maxRpm);
    if (!rpmResult.valid) return rpmResult;
  }

  if (options.maxCost !== undefined) {
    const costResult = validateMaxCost(options.maxCost);
    if (!costResult.valid) return costResult;
  }

  if (options.loopThreshold !== undefined) {
    const thresholdResult = validateLoopThreshold(options.loopThreshold);
    if (!thresholdResult.valid) return thresholdResult;
  }

  return { valid: true };
}
