// CLI Scan Types
export interface ScanResult {
  timestamp: string;
  scanPath: string;
  mcpConfigs: MCPConfig[];
  envVars: EnvVarFinding[];
  codePatterns: CodePatternFinding[];
  dependencies: DependencyFinding[];
}

export interface MCPConfig {
  source: string;
  servers: MCPServer[];
}

export interface MCPServer {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  transport?: string;
  hasSecrets?: boolean;
}

export interface EnvVarFinding {
  name: string;
  source: 'environment' | 'dotenv';
  file?: string;
}

export interface CodePatternFinding {
  file: string;
  line: number;
  pattern: string;
  framework: string;
}

export interface DependencyFinding {
  name: string;
  version?: string;
  source: 'npm' | 'pip';
  file: string;
}

export interface ScanOptions {
  dir: string;
  json: boolean;
  verbose: boolean;
  noColor: boolean;
  github?: string;
  repo?: string;
  maxRepos?: number;
  noCache?: boolean;
  format?: 'terminal' | 'json' | 'sarif';
  output?: string;
}

export interface SecurityFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  title: string;
  description: string;
  location?: string;
  recommendation: string;
}

export interface GovernanceFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  title: string;
  description: string;
  recommendation: string;
  framework?: string;
}

export interface AnalysisResult {
  securityFindings: SecurityFinding[];
  governanceFindings: GovernanceFinding[];
  summary: {
    totalMcpServers: number;
    totalEnvVars: number;
    totalCodePatterns: number;
    totalDependencies: number;
    frameworks: string[];
    securityCounts: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    governanceCounts: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
}

export interface FullScanResult {
  scan: ScanResult;
  analysis: AnalysisResult;
}

// GitHub scanning types
export interface RepoScanResult {
  repo: string;
  url: string;
  defaultBranch: string;
  lastUpdated: string;
  scanResult: ScanResult;
  securityFindings: SecurityFinding[];
  governanceFindings: GovernanceFinding[];
}

export interface FrameworkStats {
  framework: string;
  fileCount: number;
  repoCount: number;
  repos: string[];
}

export interface TeamStats {
  team: string;
  fileCount: number;
  repos: string[];
}

export interface AggregatedSecurityFinding extends SecurityFinding {
  repos: string[];
  repoCount: number;
}

export interface AggregatedGovernanceFinding extends GovernanceFinding {
  repos: string[];
  repoCount: number;
  percentage: number;
}

export interface GitHubScanResult {
  org: string;
  scannedAt: string;
  totalRepos: number;
  reposWithAI: number;
  reposScanned: number;
  reposSkipped: number;
  skippedReasons: { repo: string; reason: string }[];
  repoResults: RepoScanResult[];
  aggregatedFindings: {
    security: AggregatedSecurityFinding[];
    governance: AggregatedGovernanceFinding[];
  };
  summary: {
    totalAgentFiles: number;
    byFramework: FrameworkStats[];
    byTeam: TeamStats[];
    securityCounts: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    governanceCounts: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
}

export interface CacheEntry {
  timestamp: string;
  repoUpdatedAt: string;
  result: RepoScanResult;
}

export interface CacheData {
  version: string;
  entries: Record<string, CacheEntry>;
}

// Watch mode types
export interface WatchOptions {
  port: number;
  timeout: number;
  noColor: boolean;
  maxRpm?: number;
  maxCost?: number;
  loopThreshold?: number;
  disableLoopDetection?: boolean;
}

export interface LLMRequest {
  id: string;
  timestamp: string;
  method: string;
  path: string;
  model?: string;
  tokensIn?: number;
  tokensOut?: number;
  tools?: string[];
  toolCalls?: ToolCallInfo[];
  latencyMs?: number;
  status?: number;
  error?: string;
  streaming?: boolean;
  provider: 'openai' | 'anthropic' | 'google' | 'mistral' | 'cohere' | 'groq' | 'unknown';
}

export interface ToolCallInfo {
  name: string;
  arguments: string;
  piiDetected?: string[];
}

export interface WatchAlert {
  timestamp: string;
  type: 'pii' | 'loop' | 'cost' | 'error' | 'rate';
  message: string;
  requestId?: string;
}

export interface WatchSessionStats {
  startTime: string;
  requests: number;
  errors: number;
  toolCalls: number;
  tokensIn: number;
  tokensOut: number;
  estimatedCost: number;
  alerts: WatchAlert[];
  requestHistory: LLMRequest[];
}

// Authentication types
export interface Credentials {
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  user: {
    id: string;
    email: string;
    org: string;
    orgId: string;
  };
}

export interface DeviceCodeResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresIn: number;
  interval: number;
}

// Cloud types
export interface UploadResponse {
  reportId: string;
  reportUrl: string;
  summary: {
    criticalCount: number;
    highCount: number;
  };
}

// Config file types
export interface TrustScopeConfigFile {
  version: number;
  projectId?: string;
  agentId?: string;
  policies?: {
    maxTokensPerRequest?: number;
    maxRequestsPerMinute?: number;
    blockedTools?: string[];
    piiDetection?: 'warn' | 'block' | 'off';
  };
  alerts?: {
    costThresholdDaily?: number;
    loopDetection?: boolean;
  };
}

// Cloud enforce request/response types
export interface EnforceRequest {
  agent_id: string;
  action_type: string;
  parameters: Record<string, unknown>;
  session_id?: string;
}

export interface EnforceResponse {
  allowed: boolean;
  violations: Array<{
    policy_id?: string;
    policy_name: string;
    message: string;
  }>;
  trace_id?: string;
  blocking_detection?: string;
}

// CLI trace format for backend ingestion
export interface CLITrace {
  agent_id: string;
  session_id: string;
  source: 'cli_watch';
  machine_id: string;
  provider: string;
  model?: string;
  prompt_tokens?: number;
  completion_tokens?: number;
  latency_ms?: number;
  action_type: string;
  tool_calls?: Array<{ name: string; pii_detected?: string[] }>;
  status?: number;
  error?: string;
  blocked?: boolean;
  block_reason?: string;
  local_alerts?: string[];
  timestamp: string;
}
