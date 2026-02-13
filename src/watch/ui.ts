import chalk from 'chalk';
import type { LLMRequest, WatchAlert, WatchSessionStats } from '../types/cli.js';

const WATCH_HEADER = `
████████╗██████╗ ██╗   ██╗███████╗████████╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
   ██║   ██████╔╝██║   ██║███████╗   ██║   
   ██║   ██╔══██╗██║   ██║╚════██║   ██║   
   ██║   ██║  ██║╚██████╔╝███████║   ██║   
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
             S   C   O   P   E             

          WATCH MODE                           `;

function formatTime(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
}

function formatNumber(n: number): string {
  return n.toLocaleString();
}

function formatCost(cost: number): string {
  return `$${cost.toFixed(2)}`;
}

function getStatusIcon(status?: number, streaming?: boolean): string {
  if (streaming) return chalk.cyan('⏳');
  if (!status) return chalk.gray('○');
  if (status >= 200 && status < 300) return chalk.green('✅');
  if (status >= 400) return chalk.red('❌');
  return chalk.yellow('⚠️');
}

function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

export function clearScreen(): void {
  process.stdout.write('\x1B[2J\x1B[0f');
}

export function renderWatchUI(
  port: number,
  timeRemainingMs: number,
  stats: WatchSessionStats,
  recentRequests: LLMRequest[],
  useColor: boolean = true
): string {
  if (!useColor) {
    chalk.level = 0;
  }

  const lines: string[] = [];
  const width = 67;
  const divider = '─'.repeat(width);
  const heavyDivider = '━'.repeat(width);

  // Header
  lines.push(chalk.cyan(WATCH_HEADER));
  lines.push('');
  lines.push(chalk.gray(heavyDivider));
  lines.push('');

  // Connection info
  const timeRemaining = formatTime(timeRemainingMs);
  const statusIndicator = chalk.green('●') + ' Live';

  lines.push(`  ${chalk.bold('Proxy:')} ${chalk.cyan(`http://localhost:${port}`)}`);
  lines.push(`  ${chalk.bold('Time remaining:')} ${timeRemaining}  ${statusIndicator}`);
  lines.push('');
  lines.push(chalk.dim('  Set your environment:'));
  lines.push(chalk.dim(`  export OPENAI_BASE_URL=http://localhost:${port}/v1`));
  lines.push('');
  lines.push(chalk.gray(divider));
  lines.push('');

  // Session Stats
  lines.push(chalk.cyan.bold('  📊 SESSION STATS'));
  lines.push(chalk.gray(`  ${divider.slice(2)}`));
  lines.push('');

  const statsLine1 = [
    `Requests:     ${chalk.bold(formatNumber(stats.requests))}`.padEnd(28),
    `Tokens In:    ${chalk.bold(formatNumber(stats.tokensIn))}`,
  ].join('');

  const statsLine2 = [
    `Errors:       ${chalk.bold(stats.errors.toString())}`.padEnd(28),
    `Tokens Out:   ${chalk.bold(formatNumber(stats.tokensOut))}`,
  ].join('');

  const statsLine3 = [
    `Tool Calls:   ${chalk.bold(stats.toolCalls.toString())}`.padEnd(28),
    `Est. Cost:    ${chalk.bold(formatCost(stats.estimatedCost))}`,
  ].join('');

  lines.push(`  ${statsLine1}`);
  lines.push(`  ${statsLine2}`);
  lines.push(`  ${statsLine3}`);
  lines.push('');
  lines.push(chalk.gray(divider));
  lines.push('');

  // Live Traffic
  lines.push(chalk.cyan.bold('  📜 LIVE TRAFFIC'));
  lines.push(chalk.gray(`  ${divider.slice(2)}`));
  lines.push('');

  if (recentRequests.length === 0) {
    lines.push(chalk.dim('  Waiting for requests...'));
  } else {
    // Show last 5 requests
    const displayRequests = recentRequests.slice(-5);

    for (const req of displayRequests) {
      const time = new Date(req.timestamp).toLocaleTimeString('en-US', { hour12: false });
      const status = getStatusIcon(req.status, req.streaming && !req.status);

      lines.push(`  ${chalk.dim(time)}  ${chalk.bold(req.method)} ${req.path}`);

      if (req.model) {
        lines.push(`           ${chalk.dim('├──')} Model: ${req.model}`);
      }

      if (req.tokensIn || req.tokensOut) {
        lines.push(`           ${chalk.dim('├──')} Tokens: ${formatNumber(req.tokensIn || 0)} in → ${formatNumber(req.tokensOut || 0)} out`);
      }

      if (req.tools && req.tools.length > 0) {
        lines.push(`           ${chalk.dim('├──')} Tools: ${req.tools.join(', ')}`);
      }

      if (req.toolCalls && req.toolCalls.length > 0) {
        for (const tc of req.toolCalls) {
          const piiWarning = tc.piiDetected
            ? chalk.yellow(` ⚠️  Contains ${tc.piiDetected.join(', ')} (PII)`)
            : '';
          lines.push(`           ${chalk.dim('├──')} Tool Call: ${tc.name}${piiWarning}`);
        }
      }

      if (req.latencyMs) {
        lines.push(`           ${chalk.dim('├──')} Latency: ${(req.latencyMs / 1000).toFixed(1)}s`);
      }

      if (req.error) {
        lines.push(`           ${chalk.dim('└──')} ${chalk.red('❌')} ${req.error}`);
      } else if (req.streaming && !req.status) {
        lines.push(`           ${chalk.dim('└──')} ${chalk.cyan('⏳')} Streaming...`);
      } else {
        lines.push(`           ${chalk.dim('└──')} ${status} ${req.status || ''}`);
      }

      lines.push('');
    }
  }

  // Alerts
  const recentAlerts = stats.alerts.slice(-3);
  if (recentAlerts.length > 0) {
    lines.push(chalk.gray(divider));
    lines.push('');
    lines.push(chalk.yellow.bold(`  ⚠️  ALERTS (${stats.alerts.length} total)`));
    lines.push(chalk.gray(`  ${divider.slice(2)}`));

    for (const alert of recentAlerts) {
      const time = new Date(alert.timestamp).toLocaleTimeString('en-US', { hour12: false });
      const icon = alert.type === 'pii' ? '🔐' : alert.type === 'loop' ? '🔄' : '⚠️';
      lines.push(`  ${chalk.dim(time)}  ${icon} ${truncate(alert.message, 55)}`);
    }
  }

  lines.push('');
  lines.push(chalk.gray(heavyDivider));
  lines.push(chalk.dim("  Press 'q' to quit, 's' for summary"));
  lines.push('');

  return lines.join('\n');
}

export interface SafetySummary {
  blockedCount: number;
  savedCost: number;
  blocksByReason: {
    loop: number;
    velocity: number;
    cost: number;
  };
}

export function renderSessionSummary(
  stats: WatchSessionStats,
  useColor: boolean = true,
  safetySummary?: SafetySummary
): string {
  if (!useColor) {
    chalk.level = 0;
  }

  const lines: string[] = [];
  const width = 67;
  const divider = '─'.repeat(width);
  const heavyDivider = '━'.repeat(width);

  const duration = Date.now() - new Date(stats.startTime).getTime();
  const durationStr = formatTime(duration);

  lines.push('');
  lines.push(chalk.gray(heavyDivider));
  lines.push(chalk.cyan.bold('SESSION COMPLETE'));
  lines.push(chalk.gray(divider));
  lines.push('');
  lines.push(`  Duration:        ${chalk.bold(durationStr)}`);
  lines.push(`  Total Requests:  ${chalk.bold(formatNumber(stats.requests))}`);
  lines.push(`  Total Tokens:    ${chalk.bold(formatNumber(stats.tokensIn))} in / ${chalk.bold(formatNumber(stats.tokensOut))} out`);
  lines.push(`  Estimated Cost:  ${chalk.bold(formatCost(stats.estimatedCost))}`);
  lines.push(`  Tool Calls:      ${chalk.bold(stats.toolCalls.toString())}`);

  const piiAlerts = stats.alerts.filter(a => a.type === 'pii').length;
  const loopAlerts = stats.alerts.filter(a => a.type === 'loop').length;
  const alertSummary = [];
  if (piiAlerts > 0) alertSummary.push(`${piiAlerts} PII`);
  if (loopAlerts > 0) alertSummary.push(`${loopAlerts} potential loop`);

  lines.push(`  Alerts:          ${chalk.bold(stats.alerts.length.toString())}${alertSummary.length > 0 ? ` (${alertSummary.join(', ')})` : ''}`);

  // Show blocked requests and saved cost if any
  if (safetySummary && safetySummary.blockedCount > 0) {
    lines.push('');
    lines.push(chalk.gray(divider));
    lines.push(chalk.green.bold('  🛡️  TRUSTSCOPE PROTECTED YOU FROM:'));
    lines.push('');

    const reasons = [];
    if (safetySummary.blocksByReason.loop > 0) {
      reasons.push(`  ├── ${safetySummary.blocksByReason.loop} infinite loop${safetySummary.blocksByReason.loop > 1 ? 's' : ''} blocked`);
    }
    if (safetySummary.blocksByReason.velocity > 0) {
      reasons.push(`  ├── ${safetySummary.blocksByReason.velocity} rate limit violation${safetySummary.blocksByReason.velocity > 1 ? 's' : ''} blocked`);
    }
    if (safetySummary.blocksByReason.cost > 0) {
      reasons.push(`  ├── ${safetySummary.blocksByReason.cost} cost cap breach${safetySummary.blocksByReason.cost > 1 ? 'es' : ''} blocked`);
    }

    // Change last ├── to └──
    if (reasons.length > 0) {
      reasons[reasons.length - 1] = reasons[reasons.length - 1].replace('├──', '└──');
    }

    lines.push(...reasons);

    if (safetySummary.savedCost > 0) {
      lines.push('');
      lines.push(chalk.green(`  💰 Estimated ${formatCost(safetySummary.savedCost)} in runaway costs avoided`));
    }
  }

  lines.push('');
  lines.push(chalk.gray(divider));
  lines.push(chalk.dim('  This session data was not saved.'));
  lines.push(chalk.dim('  Want 24/7 protection in production?'));
  lines.push('');
  lines.push(`  ${chalk.cyan('→')} Free monitoring: ${chalk.cyan.bold('https://app.trustscope.ai/signup?ref=watch')}`);
  lines.push(chalk.dim('  → 5,000 traces/month, 7-day retention, free forever'));
  lines.push('');
  lines.push(chalk.gray(heavyDivider));
  lines.push('');

  return lines.join('\n');
}
