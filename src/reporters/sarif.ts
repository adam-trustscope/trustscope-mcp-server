import type { FullScanResult, SecurityFinding, GovernanceFinding } from '../types/cli.js';
import { CLI_VERSION } from '../version.js';

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  defaultConfiguration: {
    level: 'error' | 'warning' | 'note' | 'none';
  };
  properties?: {
    tags?: string[];
    'security-severity'?: string;
  };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: {
        uri: string;
        uriBaseId?: string;
      };
      region?: {
        startLine?: number;
        startColumn?: number;
        endLine?: number;
        endColumn?: number;
      };
    };
  }>;
  fingerprints?: Record<string, string>;
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}


// Map severity to SARIF level
// critical, high → error (blocks PR)
// medium → warning
// low → note
function severityToLevel(severity: string): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    default:
      return 'note';
  }
}

// Map severity to security-severity score (0-10)
function severityToScore(severity: string): string {
  switch (severity) {
    case 'critical':
      return '9.0';
    case 'high':
      return '7.0';
    case 'medium':
      return '4.0';
    case 'low':
    default:
      return '2.0';
  }
}

// Generate a unique rule ID based on the finding type
function generateRuleId(finding: SecurityFinding | GovernanceFinding): string {
  const title = finding.title.toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');

  const prefix = 'category' in finding ? 'GOV' : 'SEC';
  return `trustscope/${prefix}/${title}`;
}

// Extract file path from location string
function extractFilePath(location?: string): string | null {
  if (!location) return null;

  // Handle formats like "path/to/file.ts" or "path/to/file.ts:123"
  const match = location.match(/^([^:]+)/);
  return match ? match[1] : location;
}

// Extract line number from location string
function extractLineNumber(location?: string): number | undefined {
  if (!location) return undefined;

  // Handle formats like "path/to/file.ts:123"
  const match = location.match(/:(\d+)$/);
  return match ? parseInt(match[1], 10) : undefined;
}

export function toSarif(result: FullScanResult): SarifReport {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];
  const ruleMap = new Map<string, SarifRule>();

  // Process security findings
  for (const finding of result.analysis.securityFindings) {
    const ruleId = generateRuleId(finding);

    // Add rule if not already added
    if (!ruleMap.has(ruleId)) {
      const rule: SarifRule = {
        id: ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        helpUri: 'https://docs.trustscope.ai/security-rules',
        defaultConfiguration: {
          level: severityToLevel(finding.severity),
        },
        properties: {
          tags: ['security', 'ai-agent', finding.severity],
          'security-severity': severityToScore(finding.severity),
        },
      };
      ruleMap.set(ruleId, rule);
      rules.push(rule);
    }

    // Create result
    const sarifResult: SarifResult = {
      ruleId,
      level: severityToLevel(finding.severity),
      message: { text: finding.description },
    };

    // Add location if available
    const filePath = extractFilePath(finding.location);
    if (filePath) {
      const lineNumber = extractLineNumber(finding.location);
      sarifResult.locations = [{
        physicalLocation: {
          artifactLocation: {
            uri: filePath,
            uriBaseId: '%SRCROOT%',
          },
          ...(lineNumber && {
            region: {
              startLine: lineNumber,
              startColumn: 1,
            },
          }),
        },
      }];
    }

    // Add fingerprint for deduplication
    sarifResult.fingerprints = {
      'trustscope/v1': `${ruleId}:${finding.location || 'global'}`,
    };

    results.push(sarifResult);
  }

  // Process governance findings
  for (const finding of result.analysis.governanceFindings) {
    const ruleId = generateRuleId(finding);

    // Add rule if not already added
    if (!ruleMap.has(ruleId)) {
      const rule: SarifRule = {
        id: ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        helpUri: 'https://docs.trustscope.ai/governance-rules',
        defaultConfiguration: {
          level: severityToLevel(finding.severity),
        },
        properties: {
          tags: ['governance', 'compliance', 'ai-agent', finding.severity],
          'security-severity': severityToScore(finding.severity),
        },
      };
      ruleMap.set(ruleId, rule);
      rules.push(rule);
    }

    // Create result
    const sarifResult: SarifResult = {
      ruleId,
      level: severityToLevel(finding.severity),
      message: { text: finding.description },
    };

    // Governance findings may not have specific locations
    if (finding.location) {
      const filePath = extractFilePath(finding.location);
      if (filePath) {
        sarifResult.locations = [{
          physicalLocation: {
            artifactLocation: {
              uri: filePath,
              uriBaseId: '%SRCROOT%',
            },
          },
        }];
      }
    }

    // Add fingerprint for deduplication
    sarifResult.fingerprints = {
      'trustscope/v1': `${ruleId}:${finding.location || 'global'}`,
    };

    results.push(sarifResult);
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'TrustScope',
          version: CLI_VERSION,
          informationUri: 'https://trustscope.ai',
          rules,
        },
      },
      results,
    }],
  };
}

export function renderSarifReport(result: FullScanResult): string {
  return JSON.stringify(toSarif(result), null, 2);
}

// Check if there are any critical or high severity findings
export function hasBlockingFindings(result: FullScanResult): boolean {
  const { securityCounts, governanceCounts } = result.analysis.summary;
  return (
    securityCounts.critical > 0 ||
    securityCounts.high > 0 ||
    governanceCounts.critical > 0 ||
    governanceCounts.high > 0
  );
}
