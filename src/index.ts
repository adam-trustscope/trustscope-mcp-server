import { Command } from 'commander';
import chalk from 'chalk';
import { writeFileSync } from 'node:fs';
import { runScan, formatScanResult, hasBlockingFindings } from './cli/scan.js';
import { scanGitHubOrg, scanGitHubRepo } from './detectors/github.js';
import {
  renderGitHubTerminalReport,
  renderGitHubJsonReport,
  createProgressLine,
} from './report/index.js';
import { startWatchMode } from './watch/index.js';
import { login, logout, getCurrentUser } from './auth/index.js';
import { uploadScanResult, promptForAuth } from './cloud/upload.js';
import { runConnectWizard } from './cli/connect.js';
import { initConfig } from './cli/init.js';
import { runDoctor } from './cli/doctor.js';
import { runCloudConnect, runCloudStatus } from './cli/cloud-connect.js';
import { runOnboardingScan } from './cli/onboarding-scan.js';
import { mcpWrap, mcpList, mcpUnwrap } from './cli/mcp.js';
import { validateScanOptions, validateWatchOptions, validateProjectId } from './validation.js';
import { CLI_VERSION } from './version.js';

const program = new Command();

program
  .name('trustscope')
  .description('AI governance for agents — scan, watch, protect, prove')
  .version(CLI_VERSION);

// Scan command
program
  .command('scan')
  .description('Scan for AI agent configurations, security risks, and governance gaps')
  .option('-d, --dir <path>', 'Directory to scan (local scan)')
  .option('-g, --github <org>', 'GitHub organization to scan')
  .option('-r, --repo <owner/repo>', 'Single GitHub repository to scan')
  .option('-j, --json', 'Output results as JSON', false)
  .option('-f, --format <format>', 'Output format: terminal, json, sarif', 'terminal')
  .option('-o, --output <file>', 'Write output to file instead of stdout')
  .option('-v, --verbose', 'Enable verbose output', false)
  .option('--no-color', 'Disable colored output (for CI environments)')
  .option('--max-repos <n>', 'Maximum number of repos to scan (GitHub org only)', parseInt)
  .option('--no-cache', 'Disable caching for GitHub scans')
  .option('--upload', 'Upload results to TrustScope cloud', false)
  .option('--send', 'Send scan results to TrustScope and open onboarding wizard', false)
  .option('--project <id>', 'Project ID to associate with the scan (used with --send)')
  .action(async (options) => {
    try {
      const validation = validateScanOptions({
        dir: options.dir,
        github: options.github,
        repo: options.repo,
        output: options.output,
        format: options.format,
        maxRepos: options.maxRepos,
      });

      if (!validation.valid) {
        console.error(chalk.red(`Error: ${validation.error}`));
        process.exit(1);
      }

      if (options.project) {
        const projectValidation = validateProjectId(options.project);
        if (!projectValidation.valid) {
          console.error(chalk.red(`Error: ${projectValidation.error}`));
          process.exit(1);
        }
      }

      if (options.send) {
        await runOnboardingScan({
          dir: options.dir || process.cwd(),
          send: true,
          projectId: options.project,
          verbose: options.verbose || false,
        });
        return;
      }

      const isGitHubOrg = !!options.github;
      const isGitHubRepo = !!options.repo;

      if (isGitHubOrg || isGitHubRepo) {
        const useColor = options.color !== false;
        if (!useColor) {
          chalk.level = 0;
        }

        const hasToken = !!(process.env.TRUSTSCOPE_GITHUB_TOKEN || process.env.GITHUB_TOKEN);
        if (!hasToken && !options.json) {
          console.log(
            chalk.yellow('⚠️  No GitHub token found. Set GITHUB_TOKEN or TRUSTSCOPE_GITHUB_TOKEN for better rate limits and private repo access.')
          );
          console.log('');
        }

        let result;

        if (isGitHubOrg) {
          if (!options.json) {
            console.log(chalk.cyan(`Scanning GitHub organization: ${options.github}`));
            console.log('');
          }

          result = await scanGitHubOrg(options.github, {
            verbose: options.verbose,
            maxRepos: options.maxRepos,
            noCache: !options.cache,
            onProgress: options.json
              ? undefined
              : (current: number, total: number, repoName: string) => {
                  process.stdout.write(`\r${createProgressLine(current, total, repoName)}`.padEnd(80));
                },
          });

          if (!options.json) {
            process.stdout.write('\r' + ' '.repeat(80) + '\r');
          }
        } else {
          if (!options.json) {
            console.log(chalk.cyan(`Scanning GitHub repository: ${options.repo}`));
            console.log('');
          }

          result = await scanGitHubRepo(options.repo, {
            verbose: options.verbose,
            noCache: !options.cache,
          });
        }

        if (options.json) {
          console.log(renderGitHubJsonReport(result));
        } else {
          console.log(renderGitHubTerminalReport(result, useColor, options.verbose));
        }

        if (options.upload) {
          const shouldUpload = await promptForAuth();
          if (shouldUpload) {
            await uploadScanResult(result, 'github');
          }
        }

        const criticalCount = result.summary.securityCounts.critical;
        if (criticalCount > 0 && !options.json) {
          process.exit(1);
        }
      } else {
        const scanDir = options.dir || process.cwd();
        const format = options.json ? 'json' : (options.format || 'terminal');

        const result = await runScan({
          dir: scanDir,
          json: options.json || format === 'json',
          verbose: options.verbose,
          noColor: options.color === false,
          format: format as 'terminal' | 'json' | 'sarif',
        });

        const output = formatScanResult(result, {
          dir: scanDir,
          json: options.json || format === 'json',
          verbose: options.verbose,
          noColor: options.color === false,
          format: format as 'terminal' | 'json' | 'sarif',
        });

        if (options.output) {
          writeFileSync(options.output, output);
          if (format !== 'terminal') {
            console.log(chalk.green(`✅ Results written to ${options.output}`));
          }
        } else {
          console.log(output);
        }

        if (options.upload) {
          const shouldUpload = await promptForAuth();
          if (shouldUpload) {
            await uploadScanResult(result, 'local');
          }
        }

        if (format === 'sarif' && hasBlockingFindings(result)) {
          process.exit(1);
        }

        const criticalCount = result.analysis.summary.securityCounts.critical;
        if (criticalCount > 0 && format === 'terminal') {
          process.exit(1);
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));

      if (message.includes('rate limit')) {
        console.error(
          chalk.yellow('\nTip: Set GITHUB_TOKEN environment variable to increase rate limits.')
        );
      }

      process.exit(1);
    }
  });

// Watch command
program
  .command('watch')
  .description('Start ephemeral proxy to monitor and protect LLM traffic in real-time')
  .option('-p, --port <port>', 'Port to run proxy on', '4000')
  .option('-t, --timeout <minutes>', 'Timeout in minutes', '10')
  .option('--max-rpm <n>', 'Max requests per minute before blocking', '60')
  .option('--max-cost <n>', 'Max session cost ($) before blocking', '10')
  .option('--loop-threshold <n>', 'Identical prompts before blocking as loop', '3')
  .option('--no-loop-detection', 'Disable loop detection')
  .option('--no-color', 'Disable colored output')
  .option('--mcp', 'Also start MCP server (hybrid mode)')
  .option('-k, --api-key <key>', 'TrustScope API key for MCP (hybrid mode)')
  .action(async (options) => {
    try {
      const validation = validateWatchOptions({
        port: options.port,
        timeout: options.timeout,
        maxRpm: options.maxRpm,
        maxCost: options.maxCost,
        loopThreshold: options.loopThreshold,
      });

      if (!validation.valid) {
        console.error(chalk.red(`Error: ${validation.error}`));
        process.exit(1);
      }

      if (options.mcp) {
        // Hybrid mode - both watch and MCP
        const { startHybridMode } = await import('./hybrid/index.js');
        await startHybridMode({
          port: parseInt(options.port, 10),
          timeout: parseInt(options.timeout, 10),
          noColor: options.color === false,
          maxRpm: options.maxRpm ? parseInt(options.maxRpm, 10) : undefined,
          maxCost: options.maxCost ? parseFloat(options.maxCost) : undefined,
          loopThreshold: options.loopThreshold ? parseInt(options.loopThreshold, 10) : undefined,
          disableLoopDetection: options.loopDetection === false,
          apiKey: options.apiKey,
        });
      } else {
        await startWatchMode({
          port: parseInt(options.port, 10),
          timeout: parseInt(options.timeout, 10),
          noColor: options.color === false,
          maxRpm: options.maxRpm ? parseInt(options.maxRpm, 10) : undefined,
          maxCost: options.maxCost ? parseFloat(options.maxCost) : undefined,
          loopThreshold: options.loopThreshold ? parseInt(options.loopThreshold, 10) : undefined,
          disableLoopDetection: options.loopDetection === false,
        });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// MCP command - Start MCP governance server
program
  .command('mcp')
  .description('Start MCP governance server (stdio transport)')
  .option('-k, --api-key <key>', 'TrustScope API key (uses TRUSTSCOPE_API_KEY env if not set)')
  .option('--http', 'Use HTTP transport instead of stdio')
  .option('-p, --port <port>', 'HTTP port (default: 3000)', '3000')
  .option('-h, --host <host>', 'HTTP host (default: 0.0.0.0)', '0.0.0.0')
  .option('--watch', 'Also start watch proxy (hybrid mode)')
  .option('--watch-port <port>', 'Watch proxy port for hybrid mode', '4000')
  .option('--timeout <minutes>', 'Hybrid mode timeout in minutes', '60')
  .action(async (options) => {
    try {
      if (options.watch) {
        // Hybrid mode - both MCP and watch
        const { startHybridMode } = await import('./hybrid/index.js');
        await startHybridMode({
          port: options.watchPort ? parseInt(options.watchPort, 10) : 4000,
          timeout: options.timeout ? parseInt(options.timeout, 10) : 60,
          noColor: false,
          apiKey: options.apiKey,
        });
      } else {
        // Normal MCP mode
        const { startMCPServer } = await import('./mcp/server.js');
        await startMCPServer({
          apiKey: options.apiKey,
          http: options.http,
          port: options.port ? parseInt(options.port, 10) : 3000,
          host: options.host || '0.0.0.0',
        });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// Status command
program
  .command('status')
  .description('Show current TrustScope state')
  .action(async () => {
    try {
      const { runStatus } = await import('./cli/status.js');
      await runStatus();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// Verify command
program
  .command('verify')
  .description('Verify evidence chain integrity or attestation signature')
  .option('-v, --verbose', 'Show detailed verification output')
  .option('-q, --quick', 'Quick verification (last 100 traces only)')
  .option('-s, --signature <file>', 'Verify Ed25519 signature on attestation JSON file')
  .action(async (options) => {
    try {
      const { runVerify } = await import('./cli/verify.js');
      await runVerify({
        verbose: options.verbose,
        quick: options.quick,
        signature: options.signature,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// Export command
program
  .command('export')
  .description('Export evidence for auditors')
  .option('-f, --format <format>', 'Output format: json, csv, sarif', 'json')
  .option('-o, --output <file>', 'Output file path')
  .option('--agent <id>', 'Filter by agent ID')
  .option('--start <date>', 'Start date (ISO format)')
  .option('--end <date>', 'End date (ISO format)')
  .action(async (options) => {
    try {
      const { runExport } = await import('./cli/export.js');
      await runExport({
        format: options.format,
        output: options.output,
        agent: options.agent,
        start: options.start,
        end: options.end,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// Login command
program
  .command('login')
  .description('Authenticate with TrustScope cloud')
  .action(async () => {
    try {
      await login();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// Logout command
program
  .command('logout')
  .description('Clear TrustScope credentials')
  .action(async () => {
    try {
      await logout();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// Whoami command
program
  .command('whoami')
  .description('Show current authenticated user')
  .action(() => {
    const user = getCurrentUser();
    if (user) {
      console.log(`\nLogged in as: ${chalk.bold(user.email)}`);
      console.log(`Organization: ${chalk.bold(user.org)}\n`);
    } else {
      console.log(chalk.yellow('\nNot logged in.'));
      console.log(chalk.dim('Run "trustscope login" to authenticate.\n'));
    }
  });

// Connect command
program
  .command('connect')
  .description('Create account and sync evidence to cloud')
  .action(async () => {
    try {
      await runConnectWizard();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// Init command
program
  .command('init')
  .description('Initialize TrustScope config or CI workflow')
  .option('-d, --dir <path>', 'Directory to create files in', process.cwd())
  .option('--ci', 'Create GitHub Actions workflow for CI/CD integration')
  .option('--force', 'Overwrite existing files')
  .action(async (options) => {
    try {
      await initConfig({
        dir: options.dir,
        ci: options.ci,
        force: options.force,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// Doctor command
program
  .command('doctor')
  .description('Check your TrustScope setup and diagnose issues')
  .action(async () => {
    try {
      await runDoctor();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// Cloud command group
const cloudCommand = program
  .command('cloud')
  .description('Manage TrustScope cloud connection and sync');

cloudCommand
  .command('connect')
  .description('Connect to TrustScope cloud and import local traces')
  .option('--import', 'Automatically import local traces without prompting')
  .option('-v, --verbose', 'Enable verbose output')
  .action(async (options) => {
    try {
      await runCloudConnect({
        import: options.import,
        verbose: options.verbose,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

cloudCommand
  .command('status')
  .description('Show TrustScope cloud connection status')
  .action(async () => {
    try {
      await runCloudStatus();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

// MCP wrap command group (for backward compatibility)
const mcpManageCommand = program
  .command('mcp-manage')
  .description('Manage MCP server wrapping for TrustScope monitoring');

mcpManageCommand
  .command('wrap')
  .description('Wrap MCP servers with TrustScope monitoring')
  .option('-c, --config <path>', 'Path to specific MCP config file')
  .option('-p, --project <id>', 'Project ID to associate with traces')
  .option('-v, --verbose', 'Enable verbose output')
  .action(async (options) => {
    try {
      await mcpWrap({
        config: options.config,
        project: options.project,
        verbose: options.verbose,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

mcpManageCommand
  .command('list')
  .description('List MCP servers and their wrap status')
  .option('-v, --verbose', 'Show detailed server configuration')
  .action(async (options) => {
    try {
      await mcpList({
        verbose: options.verbose,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

mcpManageCommand
  .command('unwrap')
  .description('Remove TrustScope wrapping from MCP servers')
  .option('-a, --all', 'Unwrap all servers')
  .option('-c, --config <path>', 'Path to specific MCP config file')
  .option('-v, --verbose', 'Enable verbose output')
  .action(async (options) => {
    try {
      await mcpUnwrap({
        all: options.all,
        config: options.config,
        verbose: options.verbose,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(1);
    }
  });

program.parse();
