import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { ScanResult, GovernanceFinding } from '../types/cli.js';
import { fileExists, safeResolvePath } from '../utils.js';

const LOGGING_PATTERNS = [/logger/i, /logging/i, /winston/i, /pino/i, /bunyan/i, /log4j/i, /console\.log/i, /console\.info/i];
const COST_PATTERNS = [/budget/i, /max_tokens/i, /maxTokens/i, /limit/i, /cost/i, /spending/i, /usage/i];
const AGENT_ID_PATTERNS = [/X-Agent-ID/i, /agent[_-]?id/i, /metadata/i, /trace[_-]?id/i, /request[_-]?id/i, /correlation[_-]?id/i];
const MULTI_AGENT_PATTERNS = [/crew/i, /Agent\s*\(/i, /delegate/i, /handoff/i, /orchestrat/i, /workflow/i, /chain/i];
const POLICY_FILES = ['.trustscope.yaml', '.trustscope.yml', 'trustscope.config.js', 'trustscope.config.ts', 'trustscope.json', '.ai-policy.yaml', 'ai-governance.yaml'];

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

async function checkNoAuditTrail(scanResult: ScanResult, scanDir: string): Promise<GovernanceFinding[]> {
  const findings: GovernanceFinding[] = [];

  // Check if there's AI SDK usage
  const hasAiUsage = scanResult.codePatterns.length > 0 || scanResult.dependencies.length > 0;

  if (!hasAiUsage) return findings;

  // Check for logging patterns near AI code
  let hasLogging = false;

  for (const pattern of scanResult.codePatterns) {
    const filePath = safeResolveFile(scanDir, pattern.file);
    if (!filePath) continue; // Skip path traversal attempts
    const content = await readFileContent(filePath);
    if (content) {
      for (const loggingPattern of LOGGING_PATTERNS) {
        if (loggingPattern.test(content)) {
          hasLogging = true;
          break;
        }
      }
    }
    if (hasLogging) break;
  }

  // Also check for logging dependencies
  const loggingDeps = ['winston', 'pino', 'bunyan', 'log4js', 'morgan', 'structlog', 'loguru'];
  hasLogging = hasLogging || scanResult.dependencies.some(d =>
    loggingDeps.includes(d.name.toLowerCase())
  );

  if (!hasLogging) {
    findings.push({
      id: 'NO_AUDIT_TRAIL',
      severity: 'high',
      category: 'observability',
      title: 'No audit trail detected',
      description: 'AI SDK usage found but no logging patterns detected for audit trails',
      recommendation: 'Add TrustScope SDK for automatic audit trails or implement structured logging for AI operations',
      framework: 'SOC 2',
    });
  }

  return findings;
}

function checkNoPolicyFile(scanDir: string): GovernanceFinding[] {
  const findings: GovernanceFinding[] = [];

  const hasPolicyFile = POLICY_FILES.some(file => fileExists(join(scanDir, file)));

  if (!hasPolicyFile) {
    findings.push({
      id: 'NO_POLICY_FILE',
      severity: 'medium',
      category: 'governance',
      title: 'No policy file found',
      description: 'No TrustScope or AI governance policy file detected in the project',
      recommendation: 'Create a .trustscope.yaml file to define governance rules and agent policies',
    });
  }

  return findings;
}

async function checkNoCostControls(scanResult: ScanResult, scanDir: string): Promise<GovernanceFinding[]> {
  const findings: GovernanceFinding[] = [];

  // Check if there's AI SDK usage
  const hasAiUsage = scanResult.codePatterns.some(p =>
    ['openai_sdk', 'anthropic_sdk', 'langchain', 'llamaindex'].includes(p.framework)
  ) || scanResult.dependencies.some(d =>
    ['openai', 'anthropic', '@anthropic-ai/sdk', 'langchain'].includes(d.name.toLowerCase())
  );

  if (!hasAiUsage) return findings;

  // Check for cost control patterns
  let hasCostControls = false;

  for (const pattern of scanResult.codePatterns) {
    const filePath = safeResolveFile(scanDir, pattern.file);
    if (!filePath) continue; // Skip path traversal attempts
    const content = await readFileContent(filePath);
    if (content) {
      for (const costPattern of COST_PATTERNS) {
        if (costPattern.test(content)) {
          hasCostControls = true;
          break;
        }
      }
    }
    if (hasCostControls) break;
  }

  if (!hasCostControls) {
    findings.push({
      id: 'NO_COST_CONTROLS',
      severity: 'medium',
      category: 'cost-management',
      title: 'No cost controls detected',
      description: 'AI usage without apparent budget or token limits configured',
      recommendation: 'Implement cost controls such as max_tokens limits, budget caps, or usage monitoring',
    });
  }

  return findings;
}

async function checkAgentIdentityMissing(scanResult: ScanResult, scanDir: string): Promise<GovernanceFinding[]> {
  const findings: GovernanceFinding[] = [];

  // Check if there's AI SDK usage
  const hasAiUsage = scanResult.codePatterns.some(p =>
    ['openai_sdk', 'anthropic_sdk', 'langchain', 'tool_use'].includes(p.framework)
  );

  if (!hasAiUsage) return findings;

  // Check for agent identity patterns
  let hasAgentIdentity = false;

  for (const pattern of scanResult.codePatterns) {
    const filePath = safeResolveFile(scanDir, pattern.file);
    if (!filePath) continue; // Skip path traversal attempts
    const content = await readFileContent(filePath);
    if (content) {
      for (const idPattern of AGENT_ID_PATTERNS) {
        if (idPattern.test(content)) {
          hasAgentIdentity = true;
          break;
        }
      }
    }
    if (hasAgentIdentity) break;
  }

  if (!hasAgentIdentity) {
    findings.push({
      id: 'AGENT_IDENTITY_MISSING',
      severity: 'medium',
      category: 'traceability',
      title: 'Agent identity not configured',
      description: 'AI calls without agent identification headers or metadata for attribution',
      recommendation: 'Add agent identity (X-Agent-ID header or metadata) to enable audit attribution',
      framework: 'EU AI Act',
    });
  }

  return findings;
}

async function checkMcpNoAllowlist(scanResult: ScanResult): Promise<GovernanceFinding[]> {
  const findings: GovernanceFinding[] = [];

  if (scanResult.mcpConfigs.length === 0) return findings;

  // Check each MCP config for tool restrictions
  for (const config of scanResult.mcpConfigs) {
    const content = await readFileContent(config.source);
    if (content) {
      // Look for allowlist/blocklist patterns
      const hasRestrictions =
        /allowlist/i.test(content) ||
        /blocklist/i.test(content) ||
        /allow[_-]?tools/i.test(content) ||
        /block[_-]?tools/i.test(content) ||
        /permitted/i.test(content) ||
        /restricted/i.test(content);

      if (!hasRestrictions) {
        findings.push({
          id: 'MCP_NO_ALLOWLIST',
          severity: 'medium',
          category: 'access-control',
          title: 'MCP tools not restricted',
          description: `MCP configuration at ${config.source} has no tool allowlist/blocklist`,
          recommendation: 'Configure MCP tool allowlists to restrict which tools agents can use',
        });
      }
    }
  }

  return findings;
}

async function checkMultiAgentNoTracking(scanResult: ScanResult, scanDir: string): Promise<GovernanceFinding[]> {
  const findings: GovernanceFinding[] = [];

  // Check for multi-agent patterns
  let hasMultiAgent = false;
  const multiAgentFrameworks = ['crewai', 'autogen'];

  // Check code patterns
  for (const pattern of scanResult.codePatterns) {
    if (multiAgentFrameworks.includes(pattern.framework)) {
      hasMultiAgent = true;
      break;
    }

    const filePath = safeResolveFile(scanDir, pattern.file);
    if (!filePath) continue; // Skip path traversal attempts
    const content = await readFileContent(filePath);
    if (content) {
      for (const multiPattern of MULTI_AGENT_PATTERNS) {
        if (multiPattern.test(content)) {
          hasMultiAgent = true;
          break;
        }
      }
    }
    if (hasMultiAgent) break;
  }

  // Also check dependencies
  hasMultiAgent = hasMultiAgent || scanResult.dependencies.some(d =>
    multiAgentFrameworks.includes(d.name.toLowerCase())
  );

  if (hasMultiAgent) {
    // Check for tracking/session patterns
    let hasTracking = false;
    const trackingPatterns = [/session[_-]?id/i, /trace[_-]?id/i, /span[_-]?id/i, /correlation/i, /opentelemetry/i, /tracing/i];

    for (const pattern of scanResult.codePatterns) {
      const filePath = safeResolveFile(scanDir, pattern.file);
      if (!filePath) continue; // Skip path traversal attempts
      const content = await readFileContent(filePath);
      if (content) {
        for (const trackPattern of trackingPatterns) {
          if (trackPattern.test(content)) {
            hasTracking = true;
            break;
          }
        }
      }
      if (hasTracking) break;
    }

    // Check for tracing dependencies
    const tracingDeps = ['opentelemetry', '@opentelemetry/sdk-node', 'jaeger-client', 'zipkin'];
    hasTracking = hasTracking || scanResult.dependencies.some(d =>
      tracingDeps.some(td => d.name.toLowerCase().includes(td))
    );

    if (!hasTracking) {
      findings.push({
        id: 'MULTI_AGENT_NO_TRACKING',
        severity: 'high',
        category: 'observability',
        title: 'Multi-agent workflow without session tracking',
        description: 'Multiple agent frameworks or delegation patterns detected without distributed tracing',
        recommendation: 'Implement A2A (agent-to-agent) session tracking for multi-agent workflow observability',
        framework: 'SOC 2',
      });
    }
  }

  return findings;
}

export async function analyzeGovernanceGaps(scanResult: ScanResult, scanDir: string): Promise<GovernanceFinding[]> {
  const findings: GovernanceFinding[] = [];

  // Run all governance checks (async ones in parallel, sync ones directly)
  const [
    auditTrail,
    costControls,
    agentIdentity,
    mcpAllowlist,
    multiAgentTracking,
  ] = await Promise.all([
    checkNoAuditTrail(scanResult, scanDir),
    checkNoCostControls(scanResult, scanDir),
    checkAgentIdentityMissing(scanResult, scanDir),
    checkMcpNoAllowlist(scanResult),
    checkMultiAgentNoTracking(scanResult, scanDir),
  ]);

  findings.push(...auditTrail);
  findings.push(...checkNoPolicyFile(scanDir));
  findings.push(...costControls);
  findings.push(...agentIdentity);
  findings.push(...mcpAllowlist);
  findings.push(...multiAgentTracking);

  // Deduplicate by id
  const seen = new Set<string>();
  const deduplicated: GovernanceFinding[] = [];

  for (const finding of findings) {
    if (!seen.has(finding.id)) {
      seen.add(finding.id);
      deduplicated.push(finding);
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  deduplicated.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return deduplicated;
}
