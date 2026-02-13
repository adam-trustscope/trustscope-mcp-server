import { createHash } from 'node:crypto';

export interface SafetyConfig {
  loopDetection: {
    enabled: boolean;
    windowMs: number;        // 30000 (30 seconds)
    threshold: number;       // 3 identical prompts
  };
  velocityLimit: {
    enabled: boolean;
    maxPerMinute: number;    // 60
  };
  costCap: {
    enabled: boolean;
    maxPerSession: number;   // 10.00 ($)
  };
}

interface TrackedRequest {
  timestamp: Date;
  promptHash: string;
  estimatedCost: number;
  provider: string;
  model: string;
}

interface RequestTracker {
  requests: TrackedRequest[];
  totalCost: number;
  sessionStart: Date;
}

export interface SafetyResult {
  allowed: boolean;
  reason?: 'loop_detected' | 'velocity_exceeded' | 'cost_cap_reached' | 'cloud_policy';
  message?: string;
  savedCost?: number;
}

export interface SessionSummary {
  totalRequests: number;
  totalCost: number;
  blockedCount: number;
  savedCost: number;
  duration: number;
  blocksByReason: {
    loop: number;
    velocity: number;
    cost: number;
  };
}

// Cost per 1K tokens (as of Jan 2026)
const MODEL_COSTS: Record<string, { input: number; output: number }> = {
  // OpenAI
  'gpt-4': { input: 0.03, output: 0.06 },
  'gpt-4-turbo': { input: 0.01, output: 0.03 },
  'gpt-4o': { input: 0.005, output: 0.015 },
  'gpt-4o-mini': { input: 0.00015, output: 0.0006 },
  'gpt-3.5-turbo': { input: 0.0005, output: 0.0015 },
  'o1': { input: 0.015, output: 0.06 },
  'o1-mini': { input: 0.003, output: 0.012 },
  'o3-mini': { input: 0.0011, output: 0.0044 },

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
  'gemini-1.0-pro': { input: 0.0005, output: 0.0015 },

  // Mistral
  'mistral-large': { input: 0.004, output: 0.012 },
  'mistral-medium': { input: 0.0027, output: 0.0081 },
  'mistral-small': { input: 0.001, output: 0.003 },
  'codestral': { input: 0.001, output: 0.003 },

  // Cohere
  'command-r-plus': { input: 0.003, output: 0.015 },
  'command-r': { input: 0.0005, output: 0.0015 },

  // Groq
  'llama-3.1-70b': { input: 0.00059, output: 0.00079 },
  'llama-3.1-8b': { input: 0.00005, output: 0.00008 },
  'mixtral-8x7b': { input: 0.00024, output: 0.00024 },

  // Together AI
  'llama-3.1-405b': { input: 0.005, output: 0.015 },

  // AWS Bedrock
  'amazon.titan-text': { input: 0.0008, output: 0.0016 },
};

const DEFAULT_CONFIG: SafetyConfig = {
  loopDetection: {
    enabled: true,
    windowMs: 30000,  // 30 seconds
    threshold: 3,     // 3 identical prompts
  },
  velocityLimit: {
    enabled: true,
    maxPerMinute: 60,
  },
  costCap: {
    enabled: true,
    maxPerSession: 10.00,  // $10
  },
};

export class SafetyEngine {
  private config: SafetyConfig;
  private tracker: RequestTracker;
  private blockedCount: number = 0;
  private savedCost: number = 0;
  private blocksByReason = { loop: 0, velocity: 0, cost: 0 };

  constructor(config: Partial<SafetyConfig> = {}) {
    this.config = {
      loopDetection: { ...DEFAULT_CONFIG.loopDetection, ...config.loopDetection },
      velocityLimit: { ...DEFAULT_CONFIG.velocityLimit, ...config.velocityLimit },
      costCap: { ...DEFAULT_CONFIG.costCap, ...config.costCap },
    };

    this.tracker = {
      requests: [],
      totalCost: 0,
      sessionStart: new Date(),
    };
  }

  checkRequest(prompt: string, model: string, provider: string): SafetyResult {
    const promptHash = this.hashPrompt(prompt);
    const estimatedCost = this.estimateCost(model, prompt);
    const now = new Date();

    this.cleanOldRequests(now);

    // 1. LOOP DETECTION
    if (this.config.loopDetection.enabled) {
      const windowStart = new Date(now.getTime() - this.config.loopDetection.windowMs);
      const samePromptCount = this.tracker.requests
        .filter(r => r.timestamp > windowStart && r.promptHash === promptHash)
        .length;

      if (samePromptCount >= this.config.loopDetection.threshold) {
        this.blockedCount++;
        this.blocksByReason.loop++;
        const potentialSavings = estimatedCost * 10; // Assume 10 more iterations avoided
        this.savedCost += potentialSavings;
        return {
          allowed: false,
          reason: 'loop_detected',
          message: `Loop detected: same prompt ${samePromptCount + 1}x in ${this.config.loopDetection.windowMs / 1000}s`,
          savedCost: potentialSavings,
        };
      }
    }

    // 2. VELOCITY LIMIT
    if (this.config.velocityLimit.enabled) {
      const oneMinuteAgo = new Date(now.getTime() - 60000);
      const recentCount = this.tracker.requests
        .filter(r => r.timestamp > oneMinuteAgo)
        .length;

      if (recentCount >= this.config.velocityLimit.maxPerMinute) {
        this.blockedCount++;
        this.blocksByReason.velocity++;
        return {
          allowed: false,
          reason: 'velocity_exceeded',
          message: `Rate limit: ${recentCount}/${this.config.velocityLimit.maxPerMinute} requests/min`,
        };
      }
    }

    // 3. COST CAP
    if (this.config.costCap.enabled) {
      if (this.tracker.totalCost + estimatedCost > this.config.costCap.maxPerSession) {
        this.blockedCount++;
        this.blocksByReason.cost++;
        return {
          allowed: false,
          reason: 'cost_cap_reached',
          message: `Cost cap: $${this.tracker.totalCost.toFixed(2)} / $${this.config.costCap.maxPerSession.toFixed(2)}`,
        };
      }
    }

    // Track request
    this.tracker.requests.push({
      timestamp: now,
      promptHash,
      estimatedCost,
      provider,
      model,
    });
    this.tracker.totalCost += estimatedCost;

    return { allowed: true };
  }

  private hashPrompt(prompt: string): string {
    const normalized = prompt.toLowerCase().replace(/\s+/g, ' ').trim();
    return createHash('sha256').update(normalized).digest('hex').slice(0, 16);
  }

  estimateCost(model: string, prompt: string, outputTokens: number = 500): number {
    const inputTokens = Math.ceil(prompt.length / 4);
    const normalizedModel = this.normalizeModelName(model);
    const modelCost = MODEL_COSTS[normalizedModel] || MODEL_COSTS['gpt-4o'];

    return (inputTokens / 1000 * modelCost.input) + (outputTokens / 1000 * modelCost.output);
  }

  private normalizeModelName(model: string): string {
    const m = model.toLowerCase();

    // OpenAI
    if (m.includes('gpt-4o-mini')) return 'gpt-4o-mini';
    if (m.includes('gpt-4o')) return 'gpt-4o';
    if (m.includes('gpt-4-turbo')) return 'gpt-4-turbo';
    if (m.includes('gpt-4')) return 'gpt-4';
    if (m.includes('gpt-3.5')) return 'gpt-3.5-turbo';
    if (m.includes('o1-mini')) return 'o1-mini';
    if (m.includes('o1')) return 'o1';
    if (m.includes('o3-mini')) return 'o3-mini';

    // Anthropic
    if (m.includes('claude-3-5-sonnet') || m.includes('claude-3.5-sonnet')) return 'claude-3-5-sonnet';
    if (m.includes('claude-3-opus') || m.includes('claude-opus')) return 'claude-3-opus';
    if (m.includes('claude-3-sonnet')) return 'claude-3-sonnet';
    if (m.includes('claude-3-5-haiku') || m.includes('claude-3.5-haiku')) return 'claude-3-5-haiku';
    if (m.includes('claude-3-haiku')) return 'claude-3-haiku';

    // Google
    if (m.includes('gemini-2')) return 'gemini-2.0-flash';
    if (m.includes('gemini-1.5-pro')) return 'gemini-1.5-pro';
    if (m.includes('gemini-1.5-flash')) return 'gemini-1.5-flash';
    if (m.includes('gemini')) return 'gemini-1.5-flash';

    // Mistral
    if (m.includes('mistral-large')) return 'mistral-large';
    if (m.includes('mistral-small')) return 'mistral-small';
    if (m.includes('codestral')) return 'codestral';

    // Cohere
    if (m.includes('command-r-plus')) return 'command-r-plus';
    if (m.includes('command-r')) return 'command-r';

    // Open source
    if (m.includes('llama-3.1-405b')) return 'llama-3.1-405b';
    if (m.includes('llama-3.1-70b') || m.includes('llama-70b')) return 'llama-3.1-70b';
    if (m.includes('llama')) return 'llama-3.1-8b';
    if (m.includes('mixtral')) return 'mixtral-8x7b';

    return model;
  }

  private cleanOldRequests(now: Date): void {
    // Keep requests from last 5 minutes for analysis
    const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
    this.tracker.requests = this.tracker.requests.filter(r => r.timestamp > fiveMinutesAgo);
  }

  getTotalCost(): number {
    return this.tracker.totalCost;
  }

  getRequestsPerMinute(): number {
    const now = new Date();
    const oneMinuteAgo = new Date(now.getTime() - 60000);
    return this.tracker.requests.filter(r => r.timestamp > oneMinuteAgo).length;
  }

  getCostCap(): number {
    return this.config.costCap.maxPerSession;
  }

  getSessionSummary(): SessionSummary {
    return {
      totalRequests: this.tracker.requests.length,
      totalCost: this.tracker.totalCost,
      blockedCount: this.blockedCount,
      savedCost: this.savedCost,
      duration: Date.now() - this.tracker.sessionStart.getTime(),
      blocksByReason: { ...this.blocksByReason },
    };
  }
}

export function createSafetyEngine(options: {
  maxRpm?: number;
  maxCost?: number;
  loopThreshold?: number;
  disableLoopDetection?: boolean;
}): SafetyEngine {
  return new SafetyEngine({
    loopDetection: {
      enabled: !options.disableLoopDetection,
      windowMs: 30000,
      threshold: options.loopThreshold ?? 3,
    },
    velocityLimit: {
      enabled: true,
      maxPerMinute: options.maxRpm ?? 60,
    },
    costCap: {
      enabled: true,
      maxPerSession: options.maxCost ?? 10,
    },
  });
}
