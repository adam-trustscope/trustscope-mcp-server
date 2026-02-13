import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { ScanResult, SecurityFinding } from '../types/cli.js';
import { fileExists, containsSecret, identifySecretType, safeResolvePath } from '../utils.js';

/**
 * Patterns for detecting hardcoded API keys in source code.
 * Each pattern includes the regex and a description of what it matches.
 */
const API_KEY_PATTERNS = [
  // OpenAI
  { pattern: /sk-[a-zA-Z0-9]{20,}/, description: 'OpenAI API key' },
  { pattern: /sk-proj-[a-zA-Z0-9_-]{40,}/, description: 'OpenAI Project key' },

  // Anthropic
  { pattern: /sk-ant-[a-zA-Z0-9_-]{40,}/, description: 'Anthropic API key' },

  // Google
  { pattern: /AIza[a-zA-Z0-9_-]{35}/, description: 'Google API key' },

  // AWS
  { pattern: /AKIA[A-Z0-9]{16}/, description: 'AWS Access Key ID' },
  { pattern: /aws_secret_access_key\s*[=:]\s*['"][a-zA-Z0-9/+=]{40}['"]/, description: 'AWS Secret Access Key' },

  // GitHub
  { pattern: /ghp_[a-zA-Z0-9]{36}/, description: 'GitHub Personal Access Token' },
  { pattern: /gho_[a-zA-Z0-9]{36}/, description: 'GitHub OAuth Token' },
  { pattern: /github_pat_[a-zA-Z0-9_]{22,}/, description: 'GitHub Fine-grained PAT' },

  // Stripe
  { pattern: /sk_live_[a-zA-Z0-9]{24,}/, description: 'Stripe Live Secret Key' },
  { pattern: /rk_live_[a-zA-Z0-9]{24,}/, description: 'Stripe Restricted Key' },

  // Slack
  { pattern: /xox[baprs]-[a-zA-Z0-9-]+/, description: 'Slack Token' },

  // Twilio
  { pattern: /SK[a-f0-9]{32}/, description: 'Twilio API Key' },

  // SendGrid
  { pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/, description: 'SendGrid API Key' },

  // npm
  { pattern: /npm_[a-zA-Z0-9]{36}/, description: 'npm Token' },

  // PyPI
  { pattern: /pypi-[a-zA-Z0-9_-]{50,}/, description: 'PyPI Token' },

  // Cohere
  { pattern: /co-[a-zA-Z0-9]{40,}/, description: 'Cohere API key' },

  // Mistral
  { pattern: /mist-[a-zA-Z0-9]{32,}/, description: 'Mistral API key' },

  // Groq
  { pattern: /gsk_[a-zA-Z0-9]{52,}/, description: 'Groq API key' },

  // Replicate
  { pattern: /r8_[a-zA-Z0-9]{36,}/, description: 'Replicate API key' },

  // Together AI
  { pattern: /tg-[a-zA-Z0-9]{40,}/, description: 'Together AI key' },

  // Hugging Face
  { pattern: /hf_[a-zA-Z0-9]{34,}/, description: 'Hugging Face Token' },
];

const RATE_LIMIT_PATTERNS = [/rate[_-]?limit/i, /retry/i, /backoff/i, /RateLimiter/i, /throttle/i];
const VALIDATION_PATTERNS = [/validate/i, /schema/i, /pydantic/i, /zod/i, /joi/i, /yup/i];
const DATABASE_PATTERNS = [/postgres/i, /mysql/i, /sqlite/i, /prisma/i, /sqlalchemy/i, /\bSELECT\b/i, /\bINSERT\b/i, /\bUPDATE\b/i, /\bDELETE\b/i, /mongodb/i, /mongoose/i];
const CREDENTIAL_KEYWORDS = ['PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'CREDENTIAL', 'AUTH'];

// Patterns that indicate potentially unsafe code execution
const UNSAFE_EXECUTION_PATTERNS = [
  { pattern: /exec\s*\(/, description: 'Dynamic code execution (exec)' },
  { pattern: /eval\s*\(/, description: 'Dynamic code evaluation (eval)' },
  { pattern: /subprocess\.call|subprocess\.run|subprocess\.Popen/, description: 'Shell subprocess execution' },
  { pattern: /child_process\.exec|child_process\.spawn/, description: 'Node.js child process execution' },
  { pattern: /os\.system\s*\(/, description: 'OS system command execution' },
];

async function readFileContent(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, 'utf-8');
  } catch {
    return null;
  }
}

/**
 * Safely resolve a file path within the scan directory.
 * Returns null if the path would escape the scan directory (path traversal attempt).
 */
function safeResolveFile(scanDir: string, relativePath: string): string | null {
  try {
    return safeResolvePath(scanDir, relativePath);
  } catch {
    // Path traversal attempt detected - silently skip
    return null;
  }
}

async function checkHardcodedApiKeys(scanResult: ScanResult, scanDir: string): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const checkedFiles = new Set<string>();

  // Check for API keys in .env files (should be in environment, not committed)
  for (const envVar of scanResult.envVars) {
    if (envVar.source === 'dotenv' && envVar.file) {
      // Check if .env is in gitignore
      const gitignorePath = join(scanDir, '.gitignore');
      let isIgnored = false;

      if (fileExists(gitignorePath)) {
        const gitignore = await readFileContent(gitignorePath);
        if (gitignore) {
          const envFileName = envVar.file.split('/').pop() || '';
          isIgnored = gitignore.includes(envFileName) || gitignore.includes('.env');
        }
      }

      if (!isIgnored) {
        findings.push({
          id: 'HARDCODED_API_KEY',
          severity: 'critical',
          category: 'credentials',
          title: 'API key in potentially committed file',
          description: `${envVar.name} found in ${envVar.file} which may be committed to version control`,
          location: envVar.file,
          recommendation: 'Move API keys to environment variables and ensure .env files are in .gitignore',
        });
      }
    }
  }

  // Check for hardcoded API key patterns in code files
  for (const codePattern of scanResult.codePatterns) {
    const filePath = safeResolveFile(scanDir, codePattern.file);

    // Skip if path traversal attempt or already checked
    if (!filePath || checkedFiles.has(filePath)) continue;
    checkedFiles.add(filePath);

    const content = await readFileContent(filePath);
    if (!content) continue;

    // Check against all known API key patterns
    for (const { pattern, description } of API_KEY_PATTERNS) {
      if (pattern.test(content)) {
        findings.push({
          id: 'HARDCODED_API_KEY',
          severity: 'critical',
          category: 'credentials',
          title: 'Hardcoded API key in source code',
          description: `${description} pattern found directly in source code`,
          location: codePattern.file,
          recommendation: 'Remove hardcoded API keys and use environment variables instead',
        });
        // Only report one finding per file to avoid spam
        break;
      }
    }
  }

  return findings;
}

function checkBroadMcpFilesystem(scanResult: ScanResult): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const broadPaths = ['~', '/Users', '/home', '/', '/root', '/var', '/etc'];

  for (const config of scanResult.mcpConfigs) {
    for (const server of config.servers) {
      // Check if it's a filesystem server
      const isFilesystemServer =
        server.name.toLowerCase().includes('filesystem') ||
        server.command?.includes('filesystem') ||
        server.args?.some(arg => arg.includes('filesystem'));

      if (isFilesystemServer && server.args) {
        for (const arg of server.args) {
          for (const broadPath of broadPaths) {
            if (arg === broadPath || arg.startsWith(broadPath + '/') || arg === broadPath.slice(1)) {
              findings.push({
                id: 'BROAD_MCP_FILESYSTEM',
                severity: 'high',
                category: 'access-control',
                title: 'MCP server has broad filesystem access',
                description: `MCP server "${server.name}" has access to "${arg}" which grants broad filesystem permissions`,
                location: config.source,
                recommendation: 'Restrict MCP filesystem access to specific project directories only',
              });
              break;
            }
          }
        }
      }
    }
  }

  return findings;
}

function checkMcpCredentialsExposed(scanResult: ScanResult): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const config of scanResult.mcpConfigs) {
    for (const server of config.servers) {
      if (server.env) {
        for (const [key, value] of Object.entries(server.env)) {
          const hasCredentialKeyword = CREDENTIAL_KEYWORDS.some(
            keyword => key.toUpperCase().includes(keyword)
          );

          // Also check if value looks like a credential (long alphanumeric string)
          const looksLikeCredential = value !== '[REDACTED]' && /^[a-zA-Z0-9_-]{20,}$/.test(value);

          if (hasCredentialKeyword || looksLikeCredential) {
            findings.push({
              id: 'MCP_CREDENTIALS_EXPOSED',
              severity: 'critical',
              category: 'credentials',
              title: 'MCP server configuration exposes credentials',
              description: `MCP server "${server.name}" has credential "${key}" in its configuration`,
              location: config.source,
              recommendation: 'Use environment variable references instead of hardcoding credentials in MCP config',
            });
          }
        }
      }
    }
  }

  return findings;
}

async function checkNoRateLimiting(scanResult: ScanResult, scanDir: string): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  // Check if there's AI SDK usage
  const hasAiSdk = scanResult.codePatterns.some(p =>
    ['openai_sdk', 'anthropic_sdk', 'langchain', 'llamaindex'].includes(p.framework)
  ) || scanResult.dependencies.some(d =>
    ['openai', 'anthropic', '@anthropic-ai/sdk', 'langchain'].includes(d.name.toLowerCase())
  );

  if (!hasAiSdk) return findings;

  // Check for rate limiting patterns in code files
  let hasRateLimiting = false;

  for (const pattern of scanResult.codePatterns) {
    const filePath = safeResolveFile(scanDir, pattern.file);
    if (!filePath) continue; // Skip path traversal attempts
    const content = await readFileContent(filePath);
    if (content) {
      for (const rateLimitPattern of RATE_LIMIT_PATTERNS) {
        if (rateLimitPattern.test(content)) {
          hasRateLimiting = true;
          break;
        }
      }
    }
    if (hasRateLimiting) break;
  }

  // Also check dependencies for rate limiting libraries
  const rateLimitDeps = ['p-retry', 'bottleneck', 'limiter', 'rate-limiter-flexible', 'tenacity', 'backoff'];
  hasRateLimiting = hasRateLimiting || scanResult.dependencies.some(d =>
    rateLimitDeps.includes(d.name.toLowerCase())
  );

  if (!hasRateLimiting) {
    findings.push({
      id: 'NO_RATE_LIMITING',
      severity: 'high',
      category: 'cost-control',
      title: 'No rate limiting detected',
      description: 'AI SDK usage found but no rate limiting or retry patterns detected',
      recommendation: 'Implement rate limiting to prevent runaway API costs and handle rate limit errors gracefully',
    });
  }

  return findings;
}

async function checkToolUseNoValidation(scanResult: ScanResult, scanDir: string): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  // Check if there's tool/function calling usage
  const toolUsePatterns = scanResult.codePatterns.filter(p => p.framework === 'tool_use');

  if (toolUsePatterns.length === 0) return findings;

  // Check for validation patterns in tool use files
  let hasValidation = false;

  for (const pattern of toolUsePatterns) {
    const filePath = safeResolveFile(scanDir, pattern.file);
    if (!filePath) continue; // Skip path traversal attempts
    const content = await readFileContent(filePath);
    if (content) {
      for (const validationPattern of VALIDATION_PATTERNS) {
        if (validationPattern.test(content)) {
          hasValidation = true;
          break;
        }
      }
    }
    if (hasValidation) break;
  }

  // Also check dependencies for validation libraries
  const validationDeps = ['zod', 'joi', 'yup', 'pydantic', 'typeguard', 'ajv'];
  hasValidation = hasValidation || scanResult.dependencies.some(d =>
    validationDeps.includes(d.name.toLowerCase())
  );

  if (!hasValidation) {
    findings.push({
      id: 'TOOL_USE_NO_VALIDATION',
      severity: 'medium',
      category: 'input-validation',
      title: 'Tool usage without input validation',
      description: 'Function/tool calling detected without apparent input validation',
      location: toolUsePatterns[0]?.file,
      recommendation: 'Add input validation using Zod, Pydantic, or similar to validate tool arguments',
    });
  }

  return findings;
}

async function checkDatabaseInAgent(scanResult: ScanResult, scanDir: string): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  // Find files with AI patterns
  const aiFiles = new Set(scanResult.codePatterns
    .filter(p => ['openai_sdk', 'anthropic_sdk', 'langchain', 'tool_use'].includes(p.framework))
    .map(p => p.file)
  );

  for (const file of aiFiles) {
    const filePath = safeResolveFile(scanDir, file);
    if (!filePath) continue; // Skip path traversal attempts
    const content = await readFileContent(filePath);
    if (content) {
      for (const dbPattern of DATABASE_PATTERNS) {
        if (dbPattern.test(content)) {
          findings.push({
            id: 'DATABASE_IN_AGENT',
            severity: 'medium',
            category: 'data-access',
            title: 'Agent has direct database access',
            description: `AI agent code in "${file}" has direct database access - potential PII exposure risk`,
            location: file,
            recommendation: 'Add a data access layer with proper filtering to prevent PII exposure in AI contexts',
          });
          break;
        }
      }
    }
  }

  return findings;
}

function checkUnpinnedAiDeps(scanResult: ScanResult): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  const unpinnedDeps = scanResult.dependencies.filter(d => {
    if (!d.version) return true;
    // Check for loose version specifiers
    return (
      d.version === '*' ||
      d.version === 'latest' ||
      d.version.startsWith('^') ||
      d.version.startsWith('~') ||
      d.version.startsWith('>') ||
      d.version.startsWith('<')
    );
  });

  if (unpinnedDeps.length > 0) {
    const depList = unpinnedDeps.map(d => d.name).join(', ');
    findings.push({
      id: 'UNPINNED_AI_DEPS',
      severity: 'low',
      category: 'dependency-management',
      title: 'Unpinned AI dependencies',
      description: `AI packages without strict version pinning: ${depList}`,
      recommendation: 'Pin AI dependency versions (e.g., "openai": "4.28.0") to prevent unexpected behavior changes',
    });
  }

  return findings;
}

/**
 * Check for unsafe code execution patterns in AI agent code.
 * Agents that can execute arbitrary code are a significant security risk.
 */
async function checkUnsafeCodeExecution(scanResult: ScanResult, scanDir: string): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const checkedFiles = new Set<string>();

  // Find files with AI patterns
  const aiFiles = scanResult.codePatterns
    .filter(p => ['openai_sdk', 'anthropic_sdk', 'langchain', 'tool_use', 'code_execution', 'agent_executor'].includes(p.framework))
    .map(p => p.file);

  for (const file of aiFiles) {
    if (checkedFiles.has(file)) continue;
    checkedFiles.add(file);

    const filePath = safeResolveFile(scanDir, file);
    if (!filePath) continue; // Skip path traversal attempts
    const content = await readFileContent(filePath);
    if (!content) continue;

    for (const { pattern, description } of UNSAFE_EXECUTION_PATTERNS) {
      if (pattern.test(content)) {
        findings.push({
          id: 'UNSAFE_CODE_EXECUTION',
          severity: 'high',
          category: 'code-execution',
          title: 'Agent may execute untrusted code',
          description: `${description} found in AI agent code "${file}" - could allow arbitrary code execution`,
          location: file,
          recommendation: 'Sandbox code execution in containers, use restricted execution environments, or implement strict input validation',
        });
        // Only report one finding per file
        break;
      }
    }
  }

  return findings;
}

/**
 * Check for missing error handling in AI SDK calls.
 * Unhandled errors can crash applications and leak information.
 */
async function checkMissingErrorHandling(scanResult: ScanResult, scanDir: string): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const checkedFiles = new Set<string>();

  // Find files with AI SDK patterns
  const aiFiles = scanResult.codePatterns
    .filter(p => ['openai_sdk', 'anthropic_sdk', 'google_ai', 'mistral_ai', 'cohere'].includes(p.framework))
    .map(p => p.file);

  for (const file of aiFiles) {
    if (checkedFiles.has(file)) continue;
    checkedFiles.add(file);

    const filePath = safeResolveFile(scanDir, file);
    if (!filePath) continue; // Skip path traversal attempts
    const content = await readFileContent(filePath);
    if (!content) continue;

    // Check for common AI SDK call patterns without error handling
    const hasAwaitCalls = /await\s+(?:client|openai|anthropic)\.[a-zA-Z]+\.[a-zA-Z]+\(/i.test(content);
    const hasTryCatch = /try\s*\{[\s\S]*?catch\s*\(/i.test(content);
    const hasCatch = /\.catch\s*\(/i.test(content);

    if (hasAwaitCalls && !hasTryCatch && !hasCatch) {
      findings.push({
        id: 'MISSING_ERROR_HANDLING',
        severity: 'medium',
        category: 'error-handling',
        title: 'AI SDK calls may lack error handling',
        description: `AI SDK calls in "${file}" may not have proper try-catch error handling`,
        location: file,
        recommendation: 'Wrap AI SDK calls in try-catch blocks to handle API errors, rate limits, and timeouts gracefully',
      });
    }
  }

  return findings;
}

/**
 * Check for streaming responses without proper cleanup.
 * Unclosed streams can leak resources and cause memory issues.
 */
async function checkStreamingWithoutCleanup(scanResult: ScanResult, scanDir: string): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const checkedFiles = new Set<string>();

  // Find files with streaming patterns
  const streamingFiles = scanResult.codePatterns
    .filter(p => p.framework === 'streaming')
    .map(p => p.file);

  for (const file of streamingFiles) {
    if (checkedFiles.has(file)) continue;
    checkedFiles.add(file);

    const filePath = safeResolveFile(scanDir, file);
    if (!filePath) continue; // Skip path traversal attempts
    const content = await readFileContent(filePath);
    if (!content) continue;

    // Check for stream creation without obvious cleanup patterns
    const hasStreamCreation = /createStream|\.stream\(|StreamingResponse/i.test(content);
    const hasCleanup = /\.close\(\)|\.destroy\(\)|finally\s*\{|\.on\s*\(\s*['"](?:end|close|error)['"]/i.test(content);

    if (hasStreamCreation && !hasCleanup) {
      findings.push({
        id: 'STREAMING_NO_CLEANUP',
        severity: 'low',
        category: 'resource-management',
        title: 'Streaming response may lack cleanup',
        description: `Streaming in "${file}" may not have proper cleanup handlers`,
        location: file,
        recommendation: 'Add error handlers and cleanup logic for streaming responses to prevent resource leaks',
      });
    }
  }

  return findings;
}

export async function analyzeSecurityRisks(scanResult: ScanResult, scanDir: string): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  // Run all security checks (async ones in parallel, sync ones directly)
  const [
    hardcodedApiKeys,
    rateLimiting,
    toolUseValidation,
    databaseInAgent,
    unsafeCodeExecution,
    missingErrorHandling,
    streamingWithoutCleanup,
  ] = await Promise.all([
    checkHardcodedApiKeys(scanResult, scanDir),
    checkNoRateLimiting(scanResult, scanDir),
    checkToolUseNoValidation(scanResult, scanDir),
    checkDatabaseInAgent(scanResult, scanDir),
    checkUnsafeCodeExecution(scanResult, scanDir),
    checkMissingErrorHandling(scanResult, scanDir),
    checkStreamingWithoutCleanup(scanResult, scanDir),
  ]);

  findings.push(...hardcodedApiKeys);
  findings.push(...checkBroadMcpFilesystem(scanResult));
  findings.push(...checkMcpCredentialsExposed(scanResult));
  findings.push(...rateLimiting);
  findings.push(...toolUseValidation);
  findings.push(...databaseInAgent);
  findings.push(...checkUnpinnedAiDeps(scanResult));
  findings.push(...unsafeCodeExecution);
  findings.push(...missingErrorHandling);
  findings.push(...streamingWithoutCleanup);

  // Deduplicate by id + location
  const seen = new Set<string>();
  const deduplicated: SecurityFinding[] = [];

  for (const finding of findings) {
    const key = `${finding.id}-${finding.location || ''}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduplicated.push(finding);
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  deduplicated.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return deduplicated;
}
