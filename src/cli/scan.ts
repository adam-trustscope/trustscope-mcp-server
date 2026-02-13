import { resolve } from 'node:path';
import type { ScanOptions, ScanResult, FullScanResult, AnalysisResult } from '../types/cli.js';
import {
  detectMcpConfigs,
  detectEnvVars,
  detectCodePatterns,
  detectPackageDeps,
} from '../detectors/index.js';
import { analyzeSecurityRisks } from '../analyzers/security.js';
import { analyzeGovernanceGaps } from '../analyzers/governance.js';
import { renderTerminalReport, renderJsonReport } from '../report/index.js';
import { renderSarifReport, hasBlockingFindings } from '../reporters/sarif.js';
import { log } from '../utils.js';
import { EvidenceStore } from '../evidence/store.js';

export async function runScan(options: ScanOptions): Promise<FullScanResult> {
  const scanDir = resolve(options.dir);

  log(`Starting scan of ${scanDir}`, options.verbose);

  // Run all detectors in parallel
  const [mcpConfigs, envVars, codePatterns, dependencies] = await Promise.all([
    detectMcpConfigs(scanDir, options.verbose),
    detectEnvVars(scanDir, options.verbose),
    detectCodePatterns(scanDir, options.verbose),
    detectPackageDeps(scanDir, options.verbose),
  ]);

  const scan: ScanResult = {
    timestamp: new Date().toISOString(),
    scanPath: scanDir,
    mcpConfigs,
    envVars,
    codePatterns,
    dependencies,
  };

  log('Detection complete, running analysis', options.verbose);

  // Run analyzers in parallel
  const [securityFindings, governanceFindings] = await Promise.all([
    analyzeSecurityRisks(scan, scanDir),
    analyzeGovernanceGaps(scan, scanDir),
  ]);

  // Extract unique frameworks from code patterns
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
    agents_sdk: 'Agents SDK',
  };

  const frameworks = [...new Set(
    codePatterns
      .filter(p => !['tool_use', 'mcp_client'].includes(p.framework))
      .map(p => frameworkNames[p.framework] || p.framework)
  )];

  // Count findings by severity
  const countBySeverity = (findings: Array<{ severity: string }>) => ({
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  });

  const analysis: AnalysisResult = {
    securityFindings,
    governanceFindings,
    summary: {
      totalMcpServers: mcpConfigs.reduce((sum, c) => sum + c.servers.length, 0),
      totalEnvVars: envVars.length,
      totalCodePatterns: codePatterns.length,
      totalDependencies: dependencies.length,
      frameworks,
      securityCounts: countBySeverity(securityFindings),
      governanceCounts: countBySeverity(governanceFindings),
    },
  };

  log('Analysis complete', options.verbose);

  // Sprint 3: Write findings to evidence store
  try {
    const store = new EvidenceStore();
    store.init();

    // Record security findings as traces
    for (const finding of securityFindings) {
      store.insertTrace({
        source: 'scan',
        action_type: 'static_analysis',
        tool_name: `security:${finding.category}`,
        request_summary: `Scanned: ${scanDir}`,
        response_summary: `${finding.severity.toUpperCase()}: ${finding.title} - ${finding.description}`,
        blocked: false,
        risk_weight: severityToRiskWeight(finding.severity),
      });
    }

    // Record governance findings as traces
    for (const finding of governanceFindings) {
      store.insertTrace({
        source: 'scan',
        action_type: 'static_analysis',
        tool_name: `governance:${finding.category}`,
        request_summary: `Scanned: ${scanDir}`,
        response_summary: `${finding.severity.toUpperCase()}: ${finding.title} - ${finding.description}`,
        blocked: false,
        risk_weight: severityToRiskWeight(finding.severity),
      });
    }

    const totalFindings = securityFindings.length + governanceFindings.length;
    if (totalFindings > 0) {
      log(`Recorded ${totalFindings} findings to evidence store`, options.verbose);
    }
  } catch (error) {
    // Don't fail scan if evidence store has issues
    log(`Warning: Could not write to evidence store: ${error instanceof Error ? error.message : 'Unknown error'}`, options.verbose);
  }

  return { scan, analysis };
}

/**
 * Convert severity string to risk weight for participation scoring
 */
function severityToRiskWeight(severity: string): number {
  switch (severity.toLowerCase()) {
    case 'critical': return 1.0;
    case 'high': return 0.8;
    case 'medium': return 0.5;
    case 'low': return 0.3;
    default: return 0.2;
  }
}

export function formatScanResult(result: FullScanResult, options: ScanOptions): string {
  const format = options.format || (options.json ? 'json' : 'terminal');

  switch (format) {
    case 'sarif':
      return renderSarifReport(result);
    case 'json':
      return renderJsonReport(result);
    case 'terminal':
    default:
      return renderTerminalReport(result, !options.noColor);
  }
}

export { hasBlockingFindings };
