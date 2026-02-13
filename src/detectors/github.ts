import { Octokit } from 'octokit';
import { simpleGit } from 'simple-git';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import chalk from 'chalk';
import type {
  GitHubScanResult,
  RepoScanResult,
  ScanResult,
  SecurityFinding,
  GovernanceFinding,
  AggregatedSecurityFinding,
  AggregatedGovernanceFinding,
  FrameworkStats,
  TeamStats,
} from '../types/cli.js';
import {
  detectMcpConfigs,
  detectEnvVars,
  detectCodePatterns,
  detectPackageDeps,
} from './index.js';
import { analyzeSecurityRisks } from '../analyzers/security.js';
import { analyzeGovernanceGaps } from '../analyzers/governance.js';
import { getCachedResult, setCachedResult } from '../cache.js';

const AI_FILE_PATTERNS = [
  'agent', 'llm', 'openai', 'anthropic', 'langchain', 'crewai',
  'autogen', 'gpt', 'claude', 'gemini', 'mistral', 'embedding',
];

const AI_DEPS_NPM = [
  'openai', '@anthropic-ai/sdk', 'langchain', '@langchain/core',
  'llamaindex', 'ai', '@ai-sdk/openai', '@ai-sdk/anthropic', '@ai-sdk/google',
  'cohere-ai', '@google/generative-ai', '@google-cloud/aiplatform',
  'replicate', '@mistralai/mistralai', 'groq-sdk', '@huggingface/inference',
];

const AI_DEPS_PIP = [
  'openai', 'anthropic', 'langchain', 'llama-index', 'crewai',
  'autogen', 'haystack-ai', 'semantic-kernel', 'google-generativeai',
  'google-cloud-aiplatform', 'vertexai', 'replicate', 'mistralai',
  'groq', 'cohere', 'together', 'huggingface-hub', 'transformers',
];

const REPO_TIMEOUT_MS = 30000; // 30 seconds per repo

interface RepoInfo {
  name: string;
  full_name: string;
  clone_url: string;
  default_branch: string;
  updated_at: string;
  private: boolean;
  archived: boolean;
}

function getGitHubToken(): string | undefined {
  return process.env.TRUSTSCOPE_GITHUB_TOKEN || process.env.GITHUB_TOKEN;
}

function createOctokit(): Octokit {
  const token = getGitHubToken();
  return new Octokit({ auth: token });
}

async function listOrgRepos(octokit: Octokit, org: string): Promise<RepoInfo[]> {
  const repos: RepoInfo[] = [];
  let page = 1;
  const perPage = 100;
  let mode: 'org' | 'user' | 'authenticated' = 'org';

  // Check if this is the authenticated user's account
  if (getGitHubToken()) {
    try {
      const authUser = await octokit.rest.users.getAuthenticated();
      if (authUser.data.login.toLowerCase() === org.toLowerCase()) {
        mode = 'authenticated';
      }
    } catch {
      // Not authenticated or error, continue with org/user mode
    }
  }

  while (true) {
    try {
      let response;

      if (mode === 'authenticated') {
        // Use authenticated user's repos (includes private)
        response = await octokit.rest.repos.listForAuthenticatedUser({
          type: 'all',
          per_page: perPage,
          page,
        });
        // Filter to only repos owned by this user
        response.data = response.data.filter(
          (r: { owner: { login: string } }) => r.owner.login.toLowerCase() === org.toLowerCase()
        );
      } else if (mode === 'user') {
        // Use user repos endpoint (public only for other users)
        response = await octokit.rest.repos.listForUser({
          username: org,
          type: 'all',
          per_page: perPage,
          page,
        });
      } else {
        // Try org endpoint first
        try {
          response = await octokit.rest.repos.listForOrg({
            org,
            type: 'all',
            per_page: perPage,
            page,
          });
        } catch (error: unknown) {
          if (error && typeof error === 'object' && 'status' in error && error.status === 404) {
            // Not an org, try as user
            mode = 'user';
            response = await octokit.rest.repos.listForUser({
              username: org,
              type: 'all',
              per_page: perPage,
              page,
            });
          } else {
            throw error;
          }
        }
      }

      if (response.data.length === 0) break;

      for (const repo of response.data) {
        repos.push({
          name: repo.name,
          full_name: repo.full_name,
          clone_url: repo.clone_url,
          default_branch: repo.default_branch || 'main',
          updated_at: repo.updated_at || new Date().toISOString(),
          private: repo.private,
          archived: repo.archived || false,
        });
      }

      if (response.data.length < perPage) break;
      page++;
    } catch (error: unknown) {
      if (error && typeof error === 'object' && 'status' in error && error.status === 404) {
        throw new Error(`Organization or user "${org}" not found or not accessible`);
      }
      throw error;
    }
  }

  return repos;
}

async function getRepoInfo(octokit: Octokit, owner: string, repo: string): Promise<RepoInfo> {
  const response = await octokit.rest.repos.get({ owner, repo });
  return {
    name: response.data.name,
    full_name: response.data.full_name,
    clone_url: response.data.clone_url,
    default_branch: response.data.default_branch || 'main',
    updated_at: response.data.updated_at || new Date().toISOString(),
    private: response.data.private,
    archived: response.data.archived || false,
  };
}

async function quickFilterRepo(octokit: Octokit, owner: string, repo: string): Promise<boolean> {
  try {
    // Check package.json
    try {
      const pkgResponse = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: 'package.json',
      });

      if ('content' in pkgResponse.data) {
        const content = Buffer.from(pkgResponse.data.content, 'base64').toString('utf-8');
        const pkg = JSON.parse(content);
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

        for (const dep of AI_DEPS_NPM) {
          if (allDeps[dep]) return true;
        }
      }
    } catch {
      // No package.json or can't read it
    }

    // Check requirements.txt
    try {
      const reqResponse = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: 'requirements.txt',
      });

      if ('content' in reqResponse.data) {
        const content = Buffer.from(reqResponse.data.content, 'base64').toString('utf-8');
        const lowerContent = content.toLowerCase();

        for (const dep of AI_DEPS_PIP) {
          if (lowerContent.includes(dep.toLowerCase())) return true;
        }
      }
    } catch {
      // No requirements.txt or can't read it
    }

    // Search for AI-related files using code search
    try {
      const searchQueries = [
        `repo:${owner}/${repo} filename:*agent*`,
        `repo:${owner}/${repo} filename:*llm*`,
        `repo:${owner}/${repo} filename:*openai*`,
        `repo:${owner}/${repo} path:**/claude_desktop_config.json`,
      ];

      for (const query of searchQueries) {
        try {
          const searchResponse = await octokit.rest.search.code({
            q: query,
            per_page: 1,
          });

          if (searchResponse.data.total_count > 0) return true;
        } catch {
          // Search might fail for various reasons, continue
        }
      }
    } catch {
      // Search API might not be available
    }

    return false;
  } catch {
    // If we can't determine, err on the side of scanning
    return true;
  }
}

async function cloneAndScanRepo(
  repoInfo: RepoInfo,
  verbose: boolean,
  useAuth: boolean
): Promise<{ scan: ScanResult; security: SecurityFinding[]; governance: GovernanceFinding[] }> {
  const tempDir = mkdtempSync(join(tmpdir(), 'trustscope-'));

  try {
    const git = simpleGit();
    const cloneUrl = useAuth && getGitHubToken()
      ? repoInfo.clone_url.replace('https://', `https://${getGitHubToken()}@`)
      : repoInfo.clone_url;

    // Clone with timeout
    const clonePromise = git.clone(cloneUrl, tempDir, [
      '--depth', '1',
      '--branch', repoInfo.default_branch,
      '--single-branch',
    ]);

    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Clone timeout')), REPO_TIMEOUT_MS);
    });

    await Promise.race([clonePromise, timeoutPromise]);

    // Run detectors (skip global MCP configs for GitHub repos - only scan repo's own configs)
    const [mcpConfigs, envVars, codePatterns, dependencies] = await Promise.all([
      detectMcpConfigs(tempDir, verbose, false),  // false = don't include global configs
      detectEnvVars(tempDir, verbose),
      detectCodePatterns(tempDir, verbose),
      detectPackageDeps(tempDir, verbose),
    ]);

    const scan: ScanResult = {
      timestamp: new Date().toISOString(),
      scanPath: repoInfo.full_name,
      mcpConfigs,
      envVars,
      codePatterns,
      dependencies,
    };

    const [security, governance] = await Promise.all([
      analyzeSecurityRisks(scan, tempDir),
      analyzeGovernanceGaps(scan, tempDir),
    ]);

    return { scan, security, governance };
  } finally {
    // Clean up temp directory
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  }
}

function extractTeamFromRepo(repoName: string): string {
  // Extract team from repo path like "platform/customer-agent" -> "platform"
  const parts = repoName.split('/');
  if (parts.length > 1) {
    // Check if first part looks like a team name
    const firstPart = parts[0];
    if (firstPart && !['src', 'lib', 'app', 'packages'].includes(firstPart)) {
      return firstPart;
    }
  }

  // Check repo name prefixes
  const prefixes = ['platform-', 'data-', 'product-', 'infra-', 'ml-', 'ai-'];
  for (const prefix of prefixes) {
    if (repoName.toLowerCase().startsWith(prefix)) {
      return prefix.slice(0, -1);
    }
  }

  return 'other';
}

function aggregateFindings(
  repoResults: RepoScanResult[],
  reposWithAI: number
): {
  security: AggregatedSecurityFinding[];
  governance: AggregatedGovernanceFinding[];
} {
  // Aggregate security findings
  const securityByIdMap = new Map<string, { finding: SecurityFinding; repos: Set<string> }>();

  for (const result of repoResults) {
    for (const finding of result.securityFindings) {
      const existing = securityByIdMap.get(finding.id);
      if (existing) {
        existing.repos.add(result.repo);
      } else {
        securityByIdMap.set(finding.id, {
          finding,
          repos: new Set([result.repo]),
        });
      }
    }
  }

  const security: AggregatedSecurityFinding[] = Array.from(securityByIdMap.values())
    .map(({ finding, repos }) => ({
      ...finding,
      repos: Array.from(repos),
      repoCount: repos.size,
    }))
    .sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

  // Aggregate governance findings
  const govByIdMap = new Map<string, { finding: GovernanceFinding; repos: Set<string> }>();

  for (const result of repoResults) {
    for (const finding of result.governanceFindings) {
      const existing = govByIdMap.get(finding.id);
      if (existing) {
        existing.repos.add(result.repo);
      } else {
        govByIdMap.set(finding.id, {
          finding,
          repos: new Set([result.repo]),
        });
      }
    }
  }

  const governance: AggregatedGovernanceFinding[] = Array.from(govByIdMap.values())
    .map(({ finding, repos }) => ({
      ...finding,
      repos: Array.from(repos),
      repoCount: repos.size,
      percentage: Math.round((repos.size / reposWithAI) * 100),
    }))
    .sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

  return { security, governance };
}

function computeFrameworkStats(repoResults: RepoScanResult[]): FrameworkStats[] {
  const frameworkMap = new Map<string, { files: number; repos: Set<string> }>();

  const frameworkNames: Record<string, string> = {
    langchain: 'LangChain',
    crewai: 'CrewAI',
    autogen: 'AutoGen',
    openai_sdk: 'OpenAI SDK',
    anthropic_sdk: 'Anthropic SDK',
    llamaindex: 'LlamaIndex',
    haystack: 'Haystack',
    semantic_kernel: 'Semantic Kernel',
    vercel_ai: 'Vercel AI',
    mcp_client: 'MCP Configs',
  };

  for (const result of repoResults) {
    for (const pattern of result.scanResult.codePatterns) {
      const frameworkKey = pattern.framework;
      if (frameworkKey === 'tool_use') continue;

      const displayName = frameworkNames[frameworkKey] || frameworkKey;
      const existing = frameworkMap.get(displayName);

      if (existing) {
        existing.files++;
        existing.repos.add(result.repo);
      } else {
        frameworkMap.set(displayName, {
          files: 1,
          repos: new Set([result.repo]),
        });
      }
    }
  }

  return Array.from(frameworkMap.entries())
    .map(([framework, data]) => ({
      framework,
      fileCount: data.files,
      repoCount: data.repos.size,
      repos: Array.from(data.repos),
    }))
    .sort((a, b) => b.fileCount - a.fileCount);
}

function computeTeamStats(repoResults: RepoScanResult[]): TeamStats[] {
  const teamMap = new Map<string, { files: number; repos: Set<string> }>();

  for (const result of repoResults) {
    const team = extractTeamFromRepo(result.repo);
    const fileCount = result.scanResult.codePatterns.length;

    const existing = teamMap.get(team);
    if (existing) {
      existing.files += fileCount;
      existing.repos.add(result.repo);
    } else {
      teamMap.set(team, {
        files: fileCount,
        repos: new Set([result.repo]),
      });
    }
  }

  return Array.from(teamMap.entries())
    .map(([team, data]) => ({
      team: team + '/',
      fileCount: data.files,
      repos: Array.from(data.repos),
    }))
    .sort((a, b) => b.fileCount - a.fileCount);
}

export async function scanGitHubOrg(
  org: string,
  options: {
    verbose: boolean;
    maxRepos?: number;
    noCache?: boolean;
    onProgress?: (current: number, total: number, repoName: string) => void;
  }
): Promise<GitHubScanResult> {
  const octokit = createOctokit();
  const hasAuth = !!getGitHubToken();

  if (options.verbose) {
    console.log(chalk.dim(`GitHub authentication: ${hasAuth ? 'yes' : 'no (rate limited)'}`));
  }

  // List all repos
  if (options.onProgress) {
    options.onProgress(0, 0, 'Fetching repository list...');
  }

  const allRepos = await listOrgRepos(octokit, org);

  // Filter out archived repos
  const activeRepos = allRepos.filter(r => !r.archived);

  // Limit repos if specified
  const reposToScan = options.maxRepos
    ? activeRepos.slice(0, options.maxRepos)
    : activeRepos;

  const repoResults: RepoScanResult[] = [];
  const skippedReasons: { repo: string; reason: string }[] = [];
  let reposWithAI = 0;

  for (let i = 0; i < reposToScan.length; i++) {
    const repo = reposToScan[i];

    if (options.onProgress) {
      options.onProgress(i + 1, reposToScan.length, repo.name);
    }

    // Check cache first
    if (!options.noCache) {
      const cached = getCachedResult(org, repo.full_name, repo.updated_at);
      if (cached) {
        if (options.verbose) {
          console.log(chalk.dim(`  [cached] ${repo.name}`));
        }
        repoResults.push(cached);
        reposWithAI++;
        continue;
      }
    }

    // Handle private repos without auth
    if (repo.private && !hasAuth) {
      skippedReasons.push({ repo: repo.full_name, reason: 'Private repo (no auth)' });
      continue;
    }

    // Quick filter - but if rate limited, fall back to deep scanning
    let shouldDeepScan = true;
    try {
      const hasAI = await quickFilterRepo(octokit, org, repo.name);
      if (!hasAI) {
        if (options.verbose) {
          console.log(chalk.dim(`  [skip] ${repo.name} - no AI patterns`));
        }
        shouldDeepScan = false;
      }
    } catch (error) {
      // If filter fails (rate limit, etc.), do a deep scan to be safe
      if (options.verbose) {
        console.log(chalk.dim(`  [deep scan] ${repo.name} - quick filter unavailable`));
      }
    }

    if (!shouldDeepScan) {
      continue;
    }

    // Deep scan
    try {
      if (options.verbose) {
        console.log(chalk.dim(`  [scan] ${repo.name}`));
      }

      const { scan, security, governance } = await cloneAndScanRepo(repo, options.verbose, hasAuth);

      // Only include if has AI patterns
      if (scan.codePatterns.length > 0 || scan.dependencies.length > 0 || scan.mcpConfigs.length > 0) {
        const result: RepoScanResult = {
          repo: repo.full_name,
          url: `https://github.com/${repo.full_name}`,
          defaultBranch: repo.default_branch,
          lastUpdated: repo.updated_at,
          scanResult: scan,
          securityFindings: security,
          governanceFindings: governance,
        };

        repoResults.push(result);
        reposWithAI++;

        // Cache the result
        if (!options.noCache) {
          setCachedResult(org, repo.full_name, repo.updated_at, result);
        }
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      skippedReasons.push({ repo: repo.full_name, reason: message });

      if (options.verbose) {
        console.log(chalk.red(`  [error] ${repo.name}: ${message}`));
      }
    }
  }

  // Aggregate findings
  const aggregatedFindings = aggregateFindings(repoResults, reposWithAI);

  // Compute stats
  const frameworkStats = computeFrameworkStats(repoResults);
  const teamStats = computeTeamStats(repoResults);

  const totalAgentFiles = repoResults.reduce(
    (sum, r) => sum + r.scanResult.codePatterns.length,
    0
  );

  // Count security severities
  const securityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of aggregatedFindings.security) {
    securityCounts[finding.severity] += finding.repoCount;
  }

  // Count governance severities
  const governanceCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of aggregatedFindings.governance) {
    governanceCounts[finding.severity] += finding.repoCount;
  }

  return {
    org,
    scannedAt: new Date().toISOString(),
    totalRepos: allRepos.length,
    reposWithAI,
    reposScanned: reposToScan.length,
    reposSkipped: skippedReasons.length,
    skippedReasons,
    repoResults,
    aggregatedFindings,
    summary: {
      totalAgentFiles,
      byFramework: frameworkStats,
      byTeam: teamStats,
      securityCounts,
      governanceCounts,
    },
  };
}

export async function scanGitHubRepo(
  ownerRepo: string,
  options: { verbose: boolean; noCache?: boolean }
): Promise<GitHubScanResult> {
  const [owner, repo] = ownerRepo.split('/');
  if (!owner || !repo) {
    throw new Error('Invalid repo format. Use owner/repo format.');
  }

  const octokit = createOctokit();
  const hasAuth = !!getGitHubToken();

  const repoInfo = await getRepoInfo(octokit, owner, repo);

  // Check cache
  if (!options.noCache) {
    const cached = getCachedResult(owner, repoInfo.full_name, repoInfo.updated_at);
    if (cached) {
      return {
        org: owner,
        scannedAt: new Date().toISOString(),
        totalRepos: 1,
        reposWithAI: 1,
        reposScanned: 1,
        reposSkipped: 0,
        skippedReasons: [],
        repoResults: [cached],
        aggregatedFindings: aggregateFindings([cached], 1),
        summary: {
          totalAgentFiles: cached.scanResult.codePatterns.length,
          byFramework: computeFrameworkStats([cached]),
          byTeam: computeTeamStats([cached]),
          securityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
          governanceCounts: { critical: 0, high: 0, medium: 0, low: 0 },
        },
      };
    }
  }

  const { scan, security, governance } = await cloneAndScanRepo(repoInfo, options.verbose, hasAuth);

  const result: RepoScanResult = {
    repo: repoInfo.full_name,
    url: `https://github.com/${repoInfo.full_name}`,
    defaultBranch: repoInfo.default_branch,
    lastUpdated: repoInfo.updated_at,
    scanResult: scan,
    securityFindings: security,
    governanceFindings: governance,
  };

  // Cache result
  if (!options.noCache) {
    setCachedResult(owner, repoInfo.full_name, repoInfo.updated_at, result);
  }

  const aggregatedFindings = aggregateFindings([result], 1);

  const securityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of security) {
    securityCounts[finding.severity]++;
  }

  const governanceCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of governance) {
    governanceCounts[finding.severity]++;
  }

  return {
    org: owner,
    scannedAt: new Date().toISOString(),
    totalRepos: 1,
    reposWithAI: scan.codePatterns.length > 0 || scan.dependencies.length > 0 ? 1 : 0,
    reposScanned: 1,
    reposSkipped: 0,
    skippedReasons: [],
    repoResults: [result],
    aggregatedFindings,
    summary: {
      totalAgentFiles: scan.codePatterns.length,
      byFramework: computeFrameworkStats([result]),
      byTeam: computeTeamStats([result]),
      securityCounts,
      governanceCounts,
    },
  };
}
