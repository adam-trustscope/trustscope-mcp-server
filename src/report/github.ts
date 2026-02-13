import chalk from 'chalk';
import boxen from 'boxen';
import type { GitHubScanResult, AggregatedSecurityFinding, AggregatedGovernanceFinding } from '../types/cli.js';

const GITHUB_LOGO = `
████████╗██████╗ ██╗   ██╗███████╗████████╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
   ██║   ██████╔╝██║   ██║███████╗   ██║   
   ██║   ██╔══██╗██║   ██║╚════██║   ██║   
   ██║   ██║  ██║╚██████╔╝███████║   ██║   
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
             S   C   O   P   E             

      GitHub Organization Scan                 `;

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

function createDivider(char: string = '─', length: number = 67): string {
  return chalk.gray(char.repeat(length));
}

function createHeavyDivider(length: number = 67): string {
  return chalk.gray('━'.repeat(length));
}

function formatSecurityFinding(
  finding: AggregatedSecurityFinding,
  verbose: boolean
): string[] {
  const lines: string[] = [];
  const repoLabel = finding.repoCount === 1 ? 'repo' : 'repos';

  lines.push(
    `${getSeverityIcon(finding.severity)} ${getSeverityLabel(finding.severity).padEnd(18)} ${finding.title} (${finding.repoCount} ${repoLabel})`
  );

  if (verbose) {
    for (const repo of finding.repos) {
      lines.push(chalk.gray(`   ├── ${repo}`));
    }
  } else if (finding.repos.length <= 3) {
    for (const repo of finding.repos) {
      lines.push(chalk.gray(`   ├── ${repo}`));
    }
  } else {
    for (const repo of finding.repos.slice(0, 3)) {
      lines.push(chalk.gray(`   ├── ${repo}`));
    }
    lines.push(chalk.gray(`   └── [View full list with --verbose]`));
  }

  return lines;
}

function formatGovernanceFinding(
  finding: AggregatedGovernanceFinding,
  totalRepos: number
): string {
  const frameworkTag = finding.framework ? chalk.dim(` [${finding.framework}]`) : '';
  return `${getSeverityIcon(finding.severity)} ${getSeverityLabel(finding.severity).padEnd(18)} ${finding.title} (${finding.repoCount} repos - ${finding.percentage}%)${frameworkTag}`;
}

export function renderGitHubTerminalReport(
  result: GitHubScanResult,
  useColor: boolean = true,
  verbose: boolean = false
): string {
  if (!useColor) {
    chalk.level = 0;
  }

  const lines: string[] = [];

  // Logo Box
  const logoBox = boxen(chalk.cyan(GITHUB_LOGO), {
    padding: 1,
    borderStyle: 'round',
    borderColor: 'cyan',
    textAlignment: 'center',
  });
  lines.push(logoBox);
  lines.push('');

  // Organization
  lines.push(`Organization: ${chalk.bold(result.org)}`);
  lines.push(createHeavyDivider());
  lines.push('');

  // Discovery Summary
  lines.push(chalk.cyan.bold('📊 DISCOVERY SUMMARY'));
  lines.push(createDivider());

  const aiPercentage = result.totalRepos > 0
    ? Math.round((result.reposWithAI / result.totalRepos) * 100)
    : 0;

  lines.push(`Repositories Scanned     ${chalk.bold(result.reposScanned.toString())}`);
  lines.push(`Repos with AI Agents     ${chalk.bold(`${result.reposWithAI}`)} (${aiPercentage}%)`);
  lines.push(`Total Agent Files        ${chalk.bold(result.summary.totalAgentFiles.toString())}`);
  lines.push('');

  // By Framework
  if (result.summary.byFramework.length > 0) {
    lines.push(chalk.dim('By Framework:'));
    const maxFrameworks = verbose ? result.summary.byFramework.length : 5;

    for (let i = 0; i < Math.min(maxFrameworks, result.summary.byFramework.length); i++) {
      const fw = result.summary.byFramework[i];
      const isLast = i === Math.min(maxFrameworks, result.summary.byFramework.length) - 1;
      const prefix = isLast ? '└──' : '├──';
      lines.push(
        chalk.dim(`${prefix} ${fw.framework.padEnd(20)} ${fw.fileCount} files across ${fw.repoCount} repos`)
      );
    }

    if (!verbose && result.summary.byFramework.length > maxFrameworks) {
      lines.push(chalk.dim(`    ... and ${result.summary.byFramework.length - maxFrameworks} more`));
    }
    lines.push('');
  }

  // By Team
  if (result.summary.byTeam.length > 0) {
    lines.push(chalk.dim('By Team (based on repo path):'));
    const maxTeams = verbose ? result.summary.byTeam.length : 4;

    for (let i = 0; i < Math.min(maxTeams, result.summary.byTeam.length); i++) {
      const team = result.summary.byTeam[i];
      const isLast = i === Math.min(maxTeams, result.summary.byTeam.length) - 1;
      const prefix = isLast ? '└──' : '├──';
      lines.push(chalk.dim(`${prefix} ${team.team.padEnd(20)} ${team.fileCount} agent files`));
    }

    if (!verbose && result.summary.byTeam.length > maxTeams) {
      lines.push(chalk.dim(`    ... and ${result.summary.byTeam.length - maxTeams} more`));
    }
    lines.push('');
  }

  // Security Risks
  const securityCounts = result.summary.securityCounts;
  const totalSecurityIssues =
    securityCounts.critical + securityCounts.high + securityCounts.medium + securityCounts.low;

  if (totalSecurityIssues > 0) {
    const securitySummary = [];
    if (securityCounts.critical > 0) securitySummary.push(chalk.red(`${securityCounts.critical} critical`));
    if (securityCounts.high > 0) securitySummary.push(chalk.hex('#FFA500')(`${securityCounts.high} high`));
    if (securityCounts.medium > 0) securitySummary.push(chalk.yellow(`${securityCounts.medium} medium`));
    if (securityCounts.low > 0) securitySummary.push(chalk.blue(`${securityCounts.low} low`));

    lines.push(
      chalk.red.bold(`🔴 SECURITY RISKS (${securitySummary.join(', ')} across ${result.reposWithAI} repos)`)
    );
    lines.push(createDivider());

    for (const finding of result.aggregatedFindings.security) {
      lines.push(...formatSecurityFinding(finding, verbose));
    }
    lines.push('');
  } else {
    lines.push(chalk.green.bold('✅ SECURITY RISKS'));
    lines.push(createDivider());
    lines.push(chalk.green('   No security issues detected'));
    lines.push('');
  }

  // Governance Gaps
  const govCounts = result.summary.governanceCounts;
  const totalGovIssues = govCounts.critical + govCounts.high + govCounts.medium + govCounts.low;

  if (totalGovIssues > 0) {
    lines.push(
      chalk.yellow.bold(`🟡 GOVERNANCE GAPS (${result.aggregatedFindings.governance.length} findings across ${result.reposWithAI} repos)`)
    );
    lines.push(createDivider());

    for (const finding of result.aggregatedFindings.governance) {
      lines.push(formatGovernanceFinding(finding, result.reposWithAI));
    }
    lines.push('');
  } else {
    lines.push(chalk.green.bold('✅ GOVERNANCE GAPS'));
    lines.push(createDivider());
    lines.push(chalk.green('   No governance gaps detected'));
    lines.push('');
  }

  // Skipped repos (if any and verbose)
  if (verbose && result.skippedReasons.length > 0) {
    lines.push(chalk.dim.bold(`⚠️  SKIPPED REPOS (${result.skippedReasons.length})`));
    lines.push(createDivider());

    for (const { repo, reason } of result.skippedReasons.slice(0, 10)) {
      lines.push(chalk.dim(`   ${repo}: ${reason}`));
    }

    if (result.skippedReasons.length > 10) {
      lines.push(chalk.dim(`   ... and ${result.skippedReasons.length - 10} more`));
    }
    lines.push('');
  }

  // Footer
  lines.push(createHeavyDivider());

  if (!verbose) {
    lines.push(
      chalk.dim(`[View Full Report] → trustscope scan --github ${result.org} --verbose`)
    );
  }

  lines.push(
    chalk.dim(`[Export JSON]      → trustscope scan --github ${result.org} --json > report.json`)
  );
  lines.push(
    chalk.cyan.bold(`[Create Account]`) +
      chalk.dim(` → https://app.trustscope.ai/signup?ref=cli&org=${result.org}`)
  );

  lines.push(createHeavyDivider());
  lines.push('');

  return lines.join('\n');
}

export function renderGitHubJsonReport(result: GitHubScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function createProgressLine(current: number, total: number, repoName: string): string {
  if (total === 0) {
    return chalk.dim(`${repoName}`);
  }

  const percentage = Math.round((current / total) * 100);
  const barWidth = 20;
  const filledWidth = Math.round((current / total) * barWidth);
  const emptyWidth = barWidth - filledWidth;

  const bar = chalk.cyan('█'.repeat(filledWidth)) + chalk.gray('░'.repeat(emptyWidth));

  return `${bar} ${percentage}% (${current}/${total}) ${chalk.dim(repoName)}`;
}
