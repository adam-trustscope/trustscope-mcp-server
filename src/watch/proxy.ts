import express, { Request, Response, NextFunction } from 'express';
import { createProxyMiddleware, responseInterceptor } from 'http-proxy-middleware';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import type {
  LLMRequest,
  ToolCallInfo,
  WatchAlert,
  WatchSessionStats,
  Credentials,
  CLITrace,
  EnforceRequest,
  EnforceResponse,
  TrustScopeConfigFile,
} from '../types/cli.js';
import type { SafetyEngine, SafetyResult } from './safety.js';
import { isValidUrl } from '../utils.js';
import type { EvidenceStore } from '../evidence/store.js';
import { runAllDetections } from '../detection/index.js';
import type { DetectionContext, DetectionResultSet as DetectionResultSetInternal, SessionState } from '../detection/types.js';
import type { DetectionResultSet as EvidenceDetectionResultSet, DetectionResult as EvidenceDetectionResult, DetectionSeverity } from '../types/evidence.js';

/**
 * Map internal severity to evidence severity
 */
function mapSeverity(severity: string): DetectionSeverity {
  switch (severity) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'warning': return 'medium';
    case 'info':
    default: return 'info';
  }
}

/**
 * Convert internal detection results to evidence store format
 */
function convertDetectionResults(internal: DetectionResultSetInternal): EvidenceDetectionResultSet {
  const triggeredCount = internal.results.filter(r => r.triggered).length;
  const blockedCount = internal.results.filter(r => r.blocked).length;

  return {
    results: internal.results.map(r => ({
      engine: r.engine,
      triggered: r.triggered,
      blocked: r.blocked,
      severity: mapSeverity(r.severity),
      confidence: r.confidence ?? (r.triggered ? 0.8 : 0),
      mode: r.blocked ? 'block' : 'alert',
      detail: r.message || JSON.stringify(r.details),
    } as EvidenceDetectionResult)),
    summary: {
      total_engines: internal.results.length,
      triggered_count: triggeredCount,
      blocked_count: blockedCount,
      highest_severity: mapSeverity(internal.highestSeverity),
    },
  };
}

// Validate and use API URL
const DEFAULT_API_URL = 'https://api.trustscope.ai';
const API_BASE_URL = (() => {
  const envUrl = process.env.TRUSTSCOPE_API_URL;
  if (envUrl) {
    // Allow localhost for development
    if (isValidUrl(envUrl, true)) {
      return envUrl;
    }
    console.warn('Invalid TRUSTSCOPE_API_URL, using default');
  }
  return DEFAULT_API_URL;
})();

// Pricing per 1K tokens (approximate, Jan 2026)
const MODEL_PRICING: Record<string, { input: number; output: number }> = {
  // OpenAI
  'gpt-4': { input: 0.03, output: 0.06 },
  'gpt-4-turbo': { input: 0.01, output: 0.03 },
  'gpt-4o': { input: 0.005, output: 0.015 },
  'gpt-4o-mini': { input: 0.00015, output: 0.0006 },
  'gpt-3.5-turbo': { input: 0.0005, output: 0.0015 },
  'o1': { input: 0.015, output: 0.06 },
  'o1-mini': { input: 0.003, output: 0.012 },
  // Anthropic
  'claude-3-opus': { input: 0.015, output: 0.075 },
  'claude-3-5-sonnet': { input: 0.003, output: 0.015 },
  'claude-3-sonnet': { input: 0.003, output: 0.015 },
  'claude-3-5-haiku': { input: 0.0008, output: 0.004 },
  'claude-3-haiku': { input: 0.00025, output: 0.00125 },
  // Google
  'gemini-1.5-pro': { input: 0.00125, output: 0.005 },
  'gemini-1.5-flash': { input: 0.000075, output: 0.0003 },
  'gemini-2.0-flash': { input: 0.0001, output: 0.0004 },
  // Mistral
  'mistral-large': { input: 0.004, output: 0.012 },
  'mistral-small': { input: 0.001, output: 0.003 },
  'codestral': { input: 0.001, output: 0.003 },
  // Cohere
  'command-r-plus': { input: 0.003, output: 0.015 },
  'command-r': { input: 0.0005, output: 0.0015 },
  // Groq (fast inference)
  'llama-3.1-70b': { input: 0.00059, output: 0.00079 },
  'llama-3.1-8b': { input: 0.00005, output: 0.00008 },
  'mixtral-8x7b': { input: 0.00024, output: 0.00024 },
  default: { input: 0.01, output: 0.03 },
};

type Provider = 'openai' | 'anthropic' | 'google' | 'mistral' | 'cohere' | 'groq' | 'unknown';

/**
 * PII detection patterns - designed to avoid ReDoS vulnerabilities.
 * These use atomic groups and avoid nested quantifiers.
 *
 * Note: These are basic patterns for alerting purposes.
 * For production PII detection, consider using a dedicated library.
 */
const PII_PATTERNS = {
  // Email: Simple pattern without nested quantifiers
  // Matches most common email formats without ReDoS risk
  email: /\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,10}\b/g,

  // Phone: US phone numbers in common formats
  // Simplified to avoid backtracking
  phone: /\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b/g,

  // SSN: US Social Security Numbers
  // Fixed format, no risk of ReDoS
  ssn: /\b\d{3}-\d{2}-\d{4}\b/g,

  // Credit Card: Major card formats (Visa, MC, Amex, Discover)
  // Fixed length patterns to avoid ReDoS
  creditCard: /\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b/g,

  // Credit Card with separators (more common in text)
  creditCardFormatted: /\b(?:\d{4}[- ]){3}\d{4}\b/g,
};

// Maximum text length to scan for PII (prevent DoS on huge payloads)
const MAX_PII_SCAN_LENGTH = 100000;

const MAX_REQUEST_HISTORY = 100;

export interface ProxyCallbacks {
  onRequest: (request: LLMRequest) => void;
  onResponse: (request: LLMRequest) => void;
  onAlert: (alert: WatchAlert) => void;
  onError: (error: Error, requestId?: string) => void;
  onBlock?: (result: SafetyResult, request: Partial<LLMRequest>) => void;
}

export interface ProxyOptions {
  safetyEngine?: SafetyEngine;
  credentials?: Credentials;
  config?: TrustScopeConfigFile;
  evidenceStore?: EvidenceStore;
  enableFullDetection?: boolean;
}

/**
 * Generate a stable agent ID from machine characteristics.
 * Can be overridden via config file.
 *
 * Uses cryptographic hashing for privacy - the actual machine details
 * are not exposed, only a deterministic hash.
 */
function generateAgentId(machineId: string, configAgentId?: string): string {
  if (configAgentId) {
    // Validate custom agent ID
    if (typeof configAgentId === 'string' && configAgentId.length > 0 && configAgentId.length <= 100) {
      // Sanitize: only allow alphanumeric, dash, underscore
      const sanitized = configAgentId.replace(/[^a-zA-Z0-9_-]/g, '_');
      return sanitized;
    }
  }

  // Hash machine ID + random salt for privacy
  // Include random bytes to prevent rainbow table attacks
  const salt = randomBytes(8).toString('hex');
  const hash = createHash('sha256')
    .update(`${machineId}:cli-watch:${salt}`)
    .digest('hex');

  return `cli_${hash.slice(0, 16)}`;
}

/**
 * Generate a cryptographically secure session ID.
 * Uses UUID v4 for uniqueness guarantees.
 */
function generateSessionId(): string {
  // Use crypto.randomUUID() for proper randomness
  // Much better than Date.now() + small random bytes
  return `sess_${randomUUID().replace(/-/g, '')}`;
}

/**
 * Generate a cryptographically secure machine ID.
 * This is hashed to avoid exposing actual machine info.
 */
function generateMachineId(): string {
  // Combine multiple entropy sources
  const sources = [
    hostname(),
    process.pid.toString(),
    process.ppid?.toString() || '',
    process.platform,
    process.arch,
    randomBytes(16).toString('hex'),
  ];

  return createHash('sha256')
    .update(sources.join(':'))
    .digest('hex')
    .slice(0, 32);
}

export function createWatchProxy(
  callbacks: ProxyCallbacks,
  stats: WatchSessionStats,
  safetyEngine?: SafetyEngine,
  credentials?: Credentials,
  config?: TrustScopeConfigFile,
  evidenceStore?: EvidenceStore,
  enableFullDetection: boolean = true
) {
  const app = express();
  const machineId = generateMachineId();
  const agentId = generateAgentId(machineId, config?.agentId);
  const sessionId = generateSessionId();

  // Session state for statistical detection engines
  const detectionSessionState: SessionState = {
    requestHashes: [],
    recentActions: [],
    totalCost: 0,
    actionCount: 0,
    errorCount: 0,
    startTime: Date.now(),
    tokenCounts: [],
    contextSizes: [],
  };

  // Parse JSON bodies with size limit to prevent memory exhaustion
  app.use(express.json({ limit: '10mb' }));
  app.use(express.text({ type: 'text/plain', limit: '10mb' }));

  // Error handler for payload too large (413)
  app.use((err: Error & { status?: number; type?: string }, _req: Request, res: Response, next: NextFunction): void => {
    if (err.type === 'entity.too.large' || err.status === 413) {
      callbacks.onError(new Error('Request payload too large'), undefined);
      res.status(413).json({
        error: {
          message: 'Request payload too large. Maximum allowed size is 10MB.',
          type: 'payload_too_large',
          code: 'entity_too_large',
        },
      });
      return;
    }
    next(err);
  });

  // Request tracking
  const pendingRequests = new Map<string, {
    request: LLMRequest;
    startTime: number;
    alerts: string[];
    promptText: string;
  }>();
  const recentPrompts: { prompt: string; timestamp: number }[] = [];

  /**
   * Call cloud enforce endpoint for real-time policy evaluation.
   * Returns { allowed, reason } - only called when logged in.
   */
  async function cloudEnforce(
    prompt: string,
    model: string | undefined,
    provider: Provider
  ): Promise<{ allowed: boolean; reason?: string }> {
    if (!credentials) {
      return { allowed: true };
    }

    const enforceReq: EnforceRequest = {
      agent_id: agentId,
      action_type: 'llm_completion',
      parameters: {
        prompt: prompt.slice(0, 10000), // Truncate for reasonable payload
        model,
        provider,
      },
      session_id: sessionId,
    };

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/enforce/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${credentials.accessToken}`,
        },
        body: JSON.stringify(enforceReq),
      });

      if (!response.ok) {
        // Don't block on API errors - fail open
        return { allowed: true };
      }

      const result = await response.json() as EnforceResponse;

      if (!result.allowed) {
        const reason = result.blocking_detection ||
          result.violations?.[0]?.message ||
          'Policy violation';
        return { allowed: false, reason };
      }

      return { allowed: true };
    } catch {
      // Network error - fail open
      return { allowed: true };
    }
  }

  /**
   * Send trace to cloud for observability.
   * Non-blocking, fire-and-forget.
   */
  async function sendTraceToCloud(request: LLMRequest, alerts: string[] = []): Promise<void> {
    if (!credentials) return;

    const trace: CLITrace = {
      agent_id: agentId,
      session_id: sessionId,
      source: 'cli_watch',
      machine_id: machineId,
      provider: request.provider,
      model: request.model,
      prompt_tokens: request.tokensIn,
      completion_tokens: request.tokensOut,
      latency_ms: request.latencyMs,
      action_type: request.toolCalls?.[0]?.name || 'llm_completion',
      tool_calls: request.toolCalls?.map(tc => ({
        name: tc.name,
        pii_detected: tc.piiDetected,
      })),
      status: request.status,
      error: request.error,
      blocked: !!request.error?.includes('BLOCKED'),
      block_reason: request.error?.includes('BLOCKED') ? request.error : undefined,
      local_alerts: alerts.length > 0 ? alerts : undefined,
      timestamp: request.timestamp,
    };

    try {
      await fetch(`${API_BASE_URL}/api/v1/traces/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${credentials.accessToken}`,
        },
        body: JSON.stringify({
          agent_id: trace.agent_id,
          source: 'cli_watch',
          trigger: {
            type: 'user_message',
            input: {},
          },
          action: {
            type: trace.action_type,
            request: {
              model: trace.model,
              provider: trace.provider,
              tool_calls: trace.tool_calls,
            },
          },
          outcome: {
            status: trace.error ? 'failure' : 'success',
            response: {
              latency_ms: trace.latency_ms,
              tokens_in: trace.prompt_tokens,
              tokens_out: trace.completion_tokens,
            },
            duration_ms: trace.latency_ms,
          },
          session_id: trace.session_id,
          model: trace.model,
          prompt_tokens: trace.prompt_tokens,
          completion_tokens: trace.completion_tokens,
          llm_latency_ms: trace.latency_ms,
        }),
      });
    } catch {
      // Silently fail - don't disrupt local monitoring
    }
  }

  function generateRequestId(): string {
    return `req_${Date.now()}_${randomBytes(4).toString('hex')}`;
  }

  /**
   * Detect PII patterns in text with protection against large inputs.
   * Returns array of detected PII types.
   */
  function detectPII(text: string): string[] {
    if (!text || typeof text !== 'string') {
      return [];
    }

    // Limit scan length to prevent DoS
    const scanText = text.length > MAX_PII_SCAN_LENGTH
      ? text.slice(0, MAX_PII_SCAN_LENGTH)
      : text;

    const detected: string[] = [];

    // Reset regex lastIndex (they're global patterns)
    PII_PATTERNS.email.lastIndex = 0;
    PII_PATTERNS.phone.lastIndex = 0;
    PII_PATTERNS.ssn.lastIndex = 0;
    PII_PATTERNS.creditCard.lastIndex = 0;
    PII_PATTERNS.creditCardFormatted.lastIndex = 0;

    if (PII_PATTERNS.email.test(scanText)) detected.push('email');
    if (PII_PATTERNS.phone.test(scanText)) detected.push('phone');
    if (PII_PATTERNS.ssn.test(scanText)) detected.push('SSN');
    if (PII_PATTERNS.creditCard.test(scanText) || PII_PATTERNS.creditCardFormatted.test(scanText)) {
      detected.push('credit card');
    }

    return detected;
  }

  function estimateTokens(text: string): number {
    return Math.ceil(text.length / 4);
  }

  function extractModel(body: Record<string, unknown>): string | undefined {
    return body.model as string | undefined;
  }

  function extractTools(body: Record<string, unknown>): string[] {
    const tools: string[] = [];

    if (Array.isArray(body.tools)) {
      for (const tool of body.tools) {
        if (tool && typeof tool === 'object') {
          if ('function' in tool) {
            const fn = tool.function as { name?: string };
            if (fn.name) tools.push(fn.name);
          } else if ('name' in tool) {
            tools.push(tool.name as string);
          }
        }
      }
    }

    return tools;
  }

  function extractToolCalls(body: Record<string, unknown>): ToolCallInfo[] {
    const toolCalls: ToolCallInfo[] = [];

    // OpenAI format
    if (body.choices && Array.isArray(body.choices)) {
      for (const choice of body.choices) {
        const message = choice.message as Record<string, unknown> | undefined;
        if (message?.tool_calls && Array.isArray(message.tool_calls)) {
          for (const tc of message.tool_calls) {
            const fn = tc.function as { name?: string; arguments?: string } | undefined;
            if (fn?.name) {
              const args = fn.arguments || '';
              const piiDetected = detectPII(args);
              toolCalls.push({
                name: fn.name,
                arguments: args.slice(0, 200),
                piiDetected: piiDetected.length > 0 ? piiDetected : undefined,
              });

              if (piiDetected.length > 0) {
                const alert: WatchAlert = {
                  timestamp: new Date().toISOString(),
                  type: 'pii',
                  message: `PII detected in tool call "${fn.name}": ${piiDetected.join(', ')}`,
                };
                stats.alerts.push(alert);
                callbacks.onAlert(alert);
              }
            }
          }
        }
      }
    }

    // Anthropic format
    if (body.content && Array.isArray(body.content)) {
      for (const block of body.content) {
        if (block && typeof block === 'object' && block.type === 'tool_use') {
          const tb = block as { name?: string; input?: unknown };
          if (tb.name) {
            const args = JSON.stringify(tb.input || {});
            const piiDetected = detectPII(args);
            toolCalls.push({
              name: tb.name,
              arguments: args.slice(0, 200),
              piiDetected: piiDetected.length > 0 ? piiDetected : undefined,
            });

            if (piiDetected.length > 0) {
              const alert: WatchAlert = {
                timestamp: new Date().toISOString(),
                type: 'pii',
                message: `PII detected in tool call "${tb.name}": ${piiDetected.join(', ')}`,
              };
              stats.alerts.push(alert);
              callbacks.onAlert(alert);
            }
          }
        }
      }
    }

    return toolCalls;
  }

  function extractTokenUsage(body: Record<string, unknown>): { tokensIn: number; tokensOut: number } {
    if (body.usage && typeof body.usage === 'object') {
      const usage = body.usage as {
        prompt_tokens?: number;
        completion_tokens?: number;
        input_tokens?: number;
        output_tokens?: number;
      };
      return {
        tokensIn: usage.prompt_tokens || usage.input_tokens || 0,
        tokensOut: usage.completion_tokens || usage.output_tokens || 0,
      };
    }
    return { tokensIn: 0, tokensOut: 0 };
  }

  function calculateCost(model: string | undefined, tokensIn: number, tokensOut: number): number {
    const pricing = MODEL_PRICING[model || 'default'] || MODEL_PRICING.default;
    return (tokensIn / 1000) * pricing.input + (tokensOut / 1000) * pricing.output;
  }

  /**
   * Calculate risk weight for an LLM request based on action type and tool usage.
   * Used for participation scoring in evidence store.
   */
  function calculateRiskWeight(request: LLMRequest): number {
    // Default is moderate risk for LLM completion
    let weight = 0.5;

    // Higher risk for tool calls
    if (request.toolCalls && request.toolCalls.length > 0) {
      const toolName = request.toolCalls[0].name.toLowerCase();

      // Destructive actions
      if (/delete|remove|drop|truncate|destroy|wipe/.test(toolName)) {
        weight = 1.0;
      }
      // Data mutations
      else if (/create|update|insert|write|modify|set/.test(toolName)) {
        weight = 0.7;
      }
      // External calls
      else if (/send|post|put|patch|call|invoke|execute/.test(toolName)) {
        weight = 0.6;
      }
      // Read operations
      else if (/get|read|fetch|list|query|search|find/.test(toolName)) {
        weight = 0.3;
      }
    }

    // Higher risk if PII was detected
    if (request.toolCalls?.some(tc => tc.piiDetected && tc.piiDetected.length > 0)) {
      weight = Math.min(weight + 0.2, 1.0);
    }

    return weight;
  }

  function checkForLoop(prompt: string): boolean {
    const now = Date.now();
    const recentWindow = 60000;

    while (recentPrompts.length > 0 && now - recentPrompts[0].timestamp > recentWindow) {
      recentPrompts.shift();
    }

    const similarCount = recentPrompts.filter(p => p.prompt === prompt).length;
    recentPrompts.push({ prompt, timestamp: now });

    return similarCount >= 2;
  }

  function detectProvider(path: string, headers: Record<string, unknown>): Provider {
    if (path.includes('/v1/messages')) return 'anthropic';
    if (headers['anthropic-version']) return 'anthropic';

    if (path.includes('/v1beta/models') || path.includes('/v1/models')) {
      if (path.includes(':generateContent') || path.includes(':streamGenerateContent')) {
        return 'google';
      }
    }

    if (path.includes('/v1/chat/completions') && headers['authorization']?.toString().includes('mistral')) {
      return 'mistral';
    }

    if (path.includes('/v1/chat') || path.includes('/v1/generate')) {
      if (headers['authorization']?.toString().includes('cohere') || headers['x-cohere-api-key']) {
        return 'cohere';
      }
    }

    if (headers['authorization']?.toString().includes('gsk_')) {
      return 'groq';
    }

    if (path.includes('/v1/chat/completions')) return 'openai';
    if (path.includes('/v1/completions')) return 'openai';
    if (path.includes('/v1/embeddings')) return 'openai';

    return 'unknown';
  }

  function getTargetUrl(provider: Provider): string {
    switch (provider) {
      case 'anthropic':
        return process.env.ANTHROPIC_API_BASE || 'https://api.anthropic.com';
      case 'google':
        return process.env.GOOGLE_AI_API_BASE || 'https://generativelanguage.googleapis.com';
      case 'mistral':
        return process.env.MISTRAL_API_BASE || 'https://api.mistral.ai';
      case 'cohere':
        return process.env.COHERE_API_BASE || 'https://api.cohere.ai';
      case 'groq':
        return process.env.GROQ_API_BASE || 'https://api.groq.com/openai';
      case 'openai':
      default:
        return process.env.OPENAI_API_BASE || 'https://api.openai.com';
    }
  }

  // Middleware to capture and analyze requests
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    const requestId = generateRequestId();
    const provider = detectProvider(req.path, req.headers as Record<string, unknown>);
    const startTime = Date.now();

    let body: Record<string, unknown> = {};
    if (typeof req.body === 'string') {
      try {
        body = JSON.parse(req.body);
      } catch {
        body = {};
      }
    } else if (req.body && typeof req.body === 'object') {
      body = req.body as Record<string, unknown>;
    }

    const model = extractModel(body);
    const tools = extractTools(body);

    let estimatedTokensIn = 0;
    let promptText = '';
    if (body.messages && Array.isArray(body.messages)) {
      for (const msg of body.messages) {
        if (msg && typeof msg === 'object' && 'content' in msg) {
          const content = msg.content;
          if (typeof content === 'string') {
            estimatedTokensIn += estimateTokens(content);
            promptText += content + '\n';
          }
        }
      }
    } else if (body.prompt && typeof body.prompt === 'string') {
      promptText = body.prompt;
      estimatedTokensIn = estimateTokens(promptText);
    }

    // 1. LOCAL SAFETY ENGINE CHECK
    if (safetyEngine) {
      const safetyResult = safetyEngine.checkRequest(
        promptText || JSON.stringify(body),
        model || 'unknown',
        provider
      );

      if (!safetyResult.allowed) {
        const alertType = safetyResult.reason === 'loop_detected' ? 'loop' :
                         safetyResult.reason === 'velocity_exceeded' ? 'rate' : 'cost';
        const alert: WatchAlert = {
          timestamp: new Date().toISOString(),
          type: alertType,
          message: `BLOCKED: ${safetyResult.message}`,
          requestId,
        };
        stats.alerts.push(alert);
        callbacks.onAlert(alert);

        if (callbacks.onBlock) {
          callbacks.onBlock(safetyResult, {
            id: requestId,
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.path,
            model,
            provider,
          });
        }

        return res.status(429).json({
          error: {
            message: `TrustScope blocked: ${safetyResult.message}`,
            type: 'trustscope_safety_block',
            code: safetyResult.reason,
            saved_cost: safetyResult.savedCost,
          },
        });
      }
    }

    // 2. CLOUD ENFORCE CHECK (when logged in)
    if (credentials) {
      const enforceResult = await cloudEnforce(promptText, model, provider);

      if (!enforceResult.allowed) {
        const alert: WatchAlert = {
          timestamp: new Date().toISOString(),
          type: 'error',
          message: `CLOUD BLOCKED: ${enforceResult.reason}`,
          requestId,
        };
        stats.alerts.push(alert);
        callbacks.onAlert(alert);

        if (callbacks.onBlock) {
          callbacks.onBlock(
            { allowed: false, reason: 'cloud_policy', message: enforceResult.reason || 'Cloud policy violation' },
            {
              id: requestId,
              timestamp: new Date().toISOString(),
              method: req.method,
              path: req.path,
              model,
              provider,
            }
          );
        }

        return res.status(429).json({
          error: {
            message: `TrustScope cloud blocked: ${enforceResult.reason}`,
            type: 'trustscope_cloud_block',
            code: 'cloud_policy',
          },
        });
      }
    }

    // Legacy loop check (for alerting when safety engine is off)
    const promptKey = JSON.stringify(body.messages || body.prompt || '');
    if (!safetyEngine && checkForLoop(promptKey)) {
      const alert: WatchAlert = {
        timestamp: new Date().toISOString(),
        type: 'loop',
        message: 'Potential loop detected: Same prompt sent 3+ times in 60 seconds',
        requestId,
      };
      stats.alerts.push(alert);
      callbacks.onAlert(alert);
    }

    // Check for PII in request
    const requestText = JSON.stringify(body);
    const requestPII = detectPII(requestText);
    if (requestPII.length > 0) {
      const alert: WatchAlert = {
        timestamp: new Date().toISOString(),
        type: 'pii',
        message: `PII detected in request: ${requestPII.join(', ')}`,
        requestId,
      };
      stats.alerts.push(alert);
      callbacks.onAlert(alert);
    }

    const llmRequest: LLMRequest = {
      id: requestId,
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      model,
      tokensIn: estimatedTokensIn,
      tools: tools.length > 0 ? tools : undefined,
      provider,
      streaming: body.stream === true,
    };

    pendingRequests.set(requestId, { request: llmRequest, startTime, alerts: [], promptText });
    callbacks.onRequest(llmRequest);
    stats.requests++;

    (req as Record<string, unknown>).trustscopeRequestId = requestId;

    next();
  });

  const createProviderProxy = (provider: 'openai' | 'anthropic') => {
    const target = getTargetUrl(provider);

    return createProxyMiddleware({
      target,
      changeOrigin: true,
      selfHandleResponse: true,
      on: {
        proxyReq: (proxyReq, req) => {
          if (req.body) {
            const bodyData = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
            proxyReq.setHeader('Content-Type', 'application/json');
            proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
            proxyReq.write(bodyData);
          }
        },
        proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
          const requestId = (req as Record<string, unknown>).trustscopeRequestId as string;
          const pending = pendingRequests.get(requestId);

          if (pending) {
            const latencyMs = Date.now() - pending.startTime;
            pending.request.latencyMs = latencyMs;
            pending.request.status = proxyRes.statusCode;

            try {
              const responseText = responseBuffer.toString('utf8');
              const responseBody = JSON.parse(responseText) as Record<string, unknown>;

              const { tokensIn, tokensOut } = extractTokenUsage(responseBody);
              pending.request.tokensIn = tokensIn || pending.request.tokensIn;
              pending.request.tokensOut = tokensOut;

              const toolCalls = extractToolCalls(responseBody);
              if (toolCalls.length > 0) {
                pending.request.toolCalls = toolCalls;
                stats.toolCalls += toolCalls.length;
              }

              stats.tokensIn += pending.request.tokensIn || 0;
              stats.tokensOut += pending.request.tokensOut || 0;
              stats.estimatedCost += calculateCost(
                pending.request.model,
                pending.request.tokensIn || 0,
                pending.request.tokensOut || 0
              );

              if (proxyRes.statusCode && proxyRes.statusCode >= 400) {
                stats.errors++;
                pending.request.error = responseBody.error?.toString() || 'Request failed';
              }
            } catch {
              // Response might not be JSON (e.g., streaming)
            }

            stats.requestHistory.push(pending.request);
            if (stats.requestHistory.length > MAX_REQUEST_HISTORY) {
              stats.requestHistory.shift();
            }

            callbacks.onResponse(pending.request);

            // Send trace to cloud
            sendTraceToCloud(pending.request, pending.alerts);

            // Sprint 3: Run full detection and write to evidence store
            if (evidenceStore) {
              let detectionResults: EvidenceDetectionResultSet | undefined;

              if (enableFullDetection) {
                // Build detection context
                const detectionContext: DetectionContext = {
                  sessionId,
                  agentId,
                  actionType: pending.request.toolCalls?.[0]?.name || 'llm_completion',
                  toolName: pending.request.toolCalls?.[0]?.name,
                  requestContent: pending.promptText,
                  timestamp: pending.request.timestamp,
                  direction: 'output',
                  source: 'gateway',
                  metadata: {
                    model: pending.request.model,
                    provider: pending.request.provider,
                    latencyMs: pending.request.latencyMs,
                  },
                };

                // Update session state for statistical engines
                detectionSessionState.actionCount++;
                detectionSessionState.tokenCounts.push(
                  (pending.request.tokensIn || 0) + (pending.request.tokensOut || 0)
                );
                detectionSessionState.totalCost += calculateCost(
                  pending.request.model,
                  pending.request.tokensIn || 0,
                  pending.request.tokensOut || 0
                );
                if (pending.request.error) {
                  detectionSessionState.errorCount++;
                }
                detectionSessionState.recentActions.push(
                  pending.request.toolCalls?.[0]?.name || 'llm_completion'
                );
                if (detectionSessionState.recentActions.length > 100) {
                  detectionSessionState.recentActions.shift();
                }

                // Default configs: enable all engines
                const detectionConfigs: Record<string, { enabled: boolean }> = {};
                const allEngineNames = [
                  'loop_killer', 'velocity_limit', 'cost_velocity', 'budget_caps',
                  'token_growth', 'context_expansion', 'oscillation', 'error_rate',
                  'session_duration', 'session_action_limit',
                  'pii_scanner', 'secrets_scanner', 'prompt_injection', 'jailbreak',
                  'blocked_phrases', 'data_exfiltration', 'command_firewall', 'action_label_mismatch',
                ];
                for (const name of allEngineNames) {
                  detectionConfigs[name] = { enabled: true };
                }

                // Run all 18 detection engines
                const internalResults = runAllDetections(
                  pending.promptText,
                  detectionContext,
                  detectionConfigs,
                  detectionSessionState
                );
                detectionResults = convertDetectionResults(internalResults);
              }

              // Write trace to evidence store
              evidenceStore.insertTrace({
                source: 'gateway',
                agent_id: agentId,
                session_id: sessionId,
                action_type: pending.request.toolCalls?.[0]?.name || 'llm_completion',
                tool_name: pending.request.toolCalls?.[0]?.name,
                request_summary: pending.promptText.slice(0, 500),
                response_summary: pending.request.error || `${pending.request.tokensOut || 0} tokens`,
                blocked: !!pending.request.error?.includes('BLOCKED'),
                detection_results: detectionResults,
                risk_weight: calculateRiskWeight(pending.request),
              });
            }

            pendingRequests.delete(requestId);
          }

          return responseBuffer;
        }),
        error: (err, req, res) => {
          const requestId = (req as Record<string, unknown>).trustscopeRequestId as string;
          const pending = pendingRequests.get(requestId);

          if (pending) {
            pending.request.error = err.message;
            pending.request.status = 500;
            stats.errors++;
            callbacks.onResponse(pending.request);
            callbacks.onError(err, requestId);

            sendTraceToCloud(pending.request, pending.alerts);

            // Sprint 3: Write error trace to evidence store
            if (evidenceStore) {
              detectionSessionState.errorCount++;
              evidenceStore.insertTrace({
                source: 'gateway',
                agent_id: agentId,
                session_id: sessionId,
                action_type: pending.request.toolCalls?.[0]?.name || 'llm_completion',
                tool_name: pending.request.toolCalls?.[0]?.name,
                request_summary: pending.promptText.slice(0, 500),
                response_summary: `Error: ${err.message}`,
                blocked: false,
                risk_weight: calculateRiskWeight(pending.request),
              });
            }

            pendingRequests.delete(requestId);
          }

          if (res && 'writeHead' in res) {
            (res as Response).status(502).json({ error: 'Proxy error', message: err.message });
          }
        },
      },
    });
  };

  // OpenAI routes
  app.post('/v1/chat/completions', createProviderProxy('openai'));
  app.post('/v1/completions', createProviderProxy('openai'));
  app.post('/v1/embeddings', createProviderProxy('openai'));

  // Anthropic routes
  app.post('/v1/messages', createProviderProxy('anthropic'));

  // Google Gemini routes
  app.post('/v1beta/models/:model\\:generateContent', createProviderProxy('google'));
  app.post('/v1beta/models/:model\\:streamGenerateContent', createProviderProxy('google'));
  app.post('/v1/models/:model\\:generateContent', createProviderProxy('google'));
  app.post('/v1/models/:model\\:streamGenerateContent', createProviderProxy('google'));

  // Cohere routes
  app.post('/v1/chat', createProviderProxy('cohere'));
  app.post('/v1/generate', createProviderProxy('cohere'));
  app.post('/v2/chat', createProviderProxy('cohere'));

  // Health check
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      agent_id: agentId,
      session_id: sessionId,
      cloud_connected: !!credentials,
      uptime: Date.now() - new Date(stats.startTime).getTime(),
    });
  });

  // 404 for other routes
  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found', message: 'TrustScope proxy only handles LLM API routes' });
  });

  return app;
}
