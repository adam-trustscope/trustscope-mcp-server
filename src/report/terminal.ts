import chalk from 'chalk';
import boxen from 'boxen';
import type { FullScanResult, SecurityFinding, GovernanceFinding } from '../types/cli.js';

const LOGO = `
████████╗██████╗ ██╗   ██╗███████╗████████╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
   ██║   ██████╔╝██║   ██║███████╗   ██║   
   ██║   ██╔══██╗██║   ██║╚════██║   ██║   
   ██║   ██║  ██║╚██████╔╝███████║   ██║   
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
             S   C   O   P   E             `;

function getSeverityIcon(severity: string): string {
  switch (severity) {
    case 'critical':
      return chalk.red('●');
    case 'high':
      return chalk.hex('#FFA500')('●');
    case 'medium':
      return chalk.yellow('●');
    case 'low':
      return chalk.blue('●');
    default:
      return chalk.gray('●');
  }
}

function getSeverityLabel(severity: string): string {
  switch (severity) {
    case 'critical':
      return chalk.red.bold('CRITICAL');
    case 'high':
      return chalk.hex('#FFA500').bold('HIGH');
    case 'medium':
      return chalk.yellow.bold('MEDIUM');
    case 'low':
      return chalk.blue.bold('LOW');
    default:
      return chalk.gray('UNKNOWN');
  }
}

function formatSecurityFinding(finding: SecurityFinding): string {
  const lines: string[] = [];
  lines.push(`${getSeverityIcon(finding.severity)} ${getSeverityLabel(finding.severity).padEnd(18)} ${finding.title}`);
  if (finding.location) {
    lines.push(chalk.gray(`   └── ${finding.location} - ${finding.description}`));
  } else {
    lines.push(chalk.gray(`   └── ${finding.description}`));
  }
  return lines.join('\n');
}

function formatGovernanceFinding(finding: GovernanceFinding): string {
  const lines: string[] = [];
  const frameworkTag = finding.framework ? chalk.dim(` [${finding.framework}]`) : '';
  lines.push(`${getSeverityIcon(finding.severity)} ${getSeverityLabel(finding.severity).padEnd(18)} ${finding.title}${frameworkTag}`);
  lines.push(chalk.gray(`   └── ${finding.description}`));
  return lines.join('\n');
}

function formatSummaryLine(label: string, value: string | number, width: number = 20): string {
  return `${label.padEnd(width)} ${chalk.bold(value.toString())}`;
}

function createSectionHeader(title: string): string {
  return chalk.bold(title);
}

function createDivider(char: string = '─', length: number = 67): string {
  return chalk.gray(char.repeat(length));
}

function createHeavyDivider(length: number = 67): string {
  return chalk.gray('━'.repeat(length));
}

export function renderTerminalReport(result: FullScanResult, useColor: boolean = true): string {
  // Disable chalk if no color
  if (!useColor) {
    chalk.level = 0;
  }

  const lines: string[] = [];
  const { scan, analysis } = result;

  // Logo Box
  const logoBox = boxen(chalk.cyan(LOGO) + '\n\n' + chalk.dim('AI Agent Security & Governance Scanner'), {
    padding: 1,
    borderStyle: 'round',
    borderColor: 'cyan',
    textAlignment: 'center',
  });
  lines.push(logoBox);
  lines.push('');

  // Scanning path
  lines.push(chalk.dim(`Scanning: ${scan.scanPath}`));
  lines.push(createHeavyDivider());
  lines.push('');

  // Discovery Summary
  lines.push(chalk.cyan.bold('📊 DISCOVERY SUMMARY'));
  lines.push(createDivider());

  // Format frameworks list
  const frameworksList = analysis.summary.frameworks.length > 0
    ? analysis.summary.frameworks.join(', ')
    : 'None detected';

  lines.push(formatSummaryLine('MCP Servers', analysis.summary.totalMcpServers));
  lines.push(formatSummaryLine('AI Frameworks', `${analysis.summary.frameworks.length} detected${analysis.summary.frameworks.length > 0 ? ` (${frameworksList})` : ''}`));
  lines.push(formatSummaryLine('Environment Keys', analysis.summary.totalEnvVars));
  lines.push(formatSummaryLine('Agent Files', `${analysis.summary.totalCodePatterns} files with AI patterns`));
  lines.push('');

  // Security Risks
  const securityCounts = analysis.summary.securityCounts;
  const totalSecurityIssues = securityCounts.critical + securityCounts.high + securityCounts.medium + securityCounts.low;

  if (totalSecurityIssues > 0) {
    const securitySummary = [];
    if (securityCounts.critical > 0) securitySummary.push(chalk.red(`${securityCounts.critical} critical`));
    if (securityCounts.high > 0) securitySummary.push(chalk.hex('#FFA500')(`${securityCounts.high} high`));
    if (securityCounts.medium > 0) securitySummary.push(chalk.yellow(`${securityCounts.medium} medium`));
    if (securityCounts.low > 0) securitySummary.push(chalk.blue(`${securityCounts.low} low`));

    lines.push(chalk.red.bold(`🔴 SECURITY RISKS (${securitySummary.join(', ')})`));
    lines.push(createDivider());

    for (const finding of analysis.securityFindings) {
      lines.push(formatSecurityFinding(finding));
    }
    lines.push('');
  } else {
    lines.push(chalk.green.bold('✅ SECURITY RISKS'));
    lines.push(createDivider());
    lines.push(chalk.green('   No security issues detected'));
    lines.push('');
  }

  // Governance Gaps
  const govCounts = analysis.summary.governanceCounts;
  const totalGovIssues = govCounts.critical + govCounts.high + govCounts.medium + govCounts.low;

  if (totalGovIssues > 0) {
    lines.push(chalk.yellow.bold(`🟡 GOVERNANCE GAPS (${totalGovIssues} found)`));
    lines.push(createDivider());

    for (const finding of analysis.governanceFindings) {
      lines.push(formatGovernanceFinding(finding));
    }
    lines.push('');
  } else {
    lines.push(chalk.green.bold('✅ GOVERNANCE GAPS'));
    lines.push(createDivider());
    lines.push(chalk.green('   No governance gaps detected'));
    lines.push('');
  }

  // Next Steps
  lines.push(createHeavyDivider());
  lines.push(chalk.cyan.bold('📈 NEXT STEPS'));
  lines.push(createDivider());
  lines.push('');

  const hasIssues = totalSecurityIssues > 0 || totalGovIssues > 0;

  if (hasIssues) {
    if (securityCounts.critical > 0) {
      lines.push(chalk.red('  ▸ Fix critical security issues immediately'));
    }
    if (securityCounts.high > 0 || govCounts.high > 0) {
      lines.push(chalk.hex('#FFA500')('  ▸ Address high-severity findings before deployment'));
    }
    lines.push(chalk.white('  ▸ Create free TrustScope account to monitor these agents'));
    lines.push(chalk.white('  ▸ Add TrustScope SDK for automatic governance'));
    lines.push('');
    lines.push(chalk.cyan.bold('  [Create Free Account]') + chalk.dim(' → https://app.trustscope.ai/signup?ref=cli'));
  } else {
    lines.push(chalk.green('  ✨ Great job! No immediate issues found.'));
    lines.push(chalk.white('  ▸ Consider adding TrustScope for continuous monitoring'));
    lines.push('');
    lines.push(chalk.cyan.bold('  [Learn More]') + chalk.dim(' → https://trustscope.ai'));
  }

  lines.push('');
  lines.push(createHeavyDivider());
  lines.push('');

  return lines.join('\n');
}

export function renderJsonReport(result: FullScanResult): string {
  return JSON.stringify(result, null, 2);
}
