import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import chalk from 'chalk';
import boxen from 'boxen';
import { getCredentials, login } from '../auth/index.js';
import { detectMcpConfigs } from '../detectors/index.js';

const CONNECT_HEADER = `
████████╗██████╗ ██╗   ██╗███████╗████████╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
   ██║   ██████╔╝██║   ██║███████╗   ██║   
   ██║   ██╔══██╗██║   ██║╚════██║   ██║   
   ██║   ██║  ██║╚██████╔╝███████║   ██║   
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
             S   C   O   P   E             

         SETUP WIZARD                          `;

interface MCPServerConfig {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
}

export async function runConnectWizard(): Promise<void> {
  // Dynamic import for inquirer
  const inquirer = await import('inquirer');

  console.log(boxen(chalk.cyan(CONNECT_HEADER), {
    padding: 1,
    borderStyle: 'round',
    borderColor: 'cyan',
    textAlignment: 'center',
  }));

  console.log(chalk.dim("\nLet's connect your agents to TrustScope.\n"));

  // Check authentication
  let creds = getCredentials();
  if (!creds) {
    const { wantLogin } = await inquirer.default.prompt([
      {
        type: 'confirm',
        name: 'wantLogin',
        message: 'You need to login first. Continue?',
        default: true,
      },
    ]);

    if (!wantLogin) {
      console.log(chalk.dim('\nRun "trustscope login" when ready.\n'));
      return;
    }

    await login();
    creds = getCredentials();

    if (!creds) {
      console.log(chalk.red('\nLogin failed. Please try again.\n'));
      return;
    }
  }

  // Choose integration method
  const { integrationMethod } = await inquirer.default.prompt([
    {
      type: 'list',
      name: 'integrationMethod',
      message: 'How do you want to integrate?',
      choices: [
        { name: 'Gateway Proxy (recommended) - Route LLM traffic through TrustScope', value: 'gateway' },
        { name: 'SDK Integration - Add TrustScope to your code', value: 'sdk' },
        { name: 'MCP Wrapper - Wrap your MCP servers', value: 'mcp' },
      ],
    },
  ]);

  if (integrationMethod === 'gateway') {
    await setupGatewayProxy(inquirer.default);
  } else if (integrationMethod === 'sdk') {
    await setupSDKIntegration(inquirer.default);
  } else if (integrationMethod === 'mcp') {
    await setupMCPWrapper(inquirer.default);
  }
}

async function setupGatewayProxy(inquirer: typeof import('inquirer').default): Promise<void> {
  const { provider } = await inquirer.prompt([
    {
      type: 'list',
      name: 'provider',
      message: 'Which LLM provider do you use?',
      choices: [
        { name: 'OpenAI', value: 'openai' },
        { name: 'Anthropic', value: 'anthropic' },
        { name: 'Both', value: 'both' },
        { name: 'Other', value: 'other' },
      ],
    },
  ]);

  // Get API key from environment or prompt user
  let apiKey = process.env.TRUSTSCOPE_API_KEY;

  if (!apiKey) {
    console.log(chalk.yellow('\n⚠️  No API key found.'));
    console.log(chalk.dim('Create a project at https://app.trustscope.ai/onboarding to get your API key.\n'));

    const { enteredKey } = await inquirer.prompt([
      {
        type: 'input',
        name: 'enteredKey',
        message: 'Enter your TrustScope API key (ts_live_xxx):',
        validate: (input: string) => {
          if (!input) return 'API key is required';
          if (!input.startsWith('ts_live_') && !input.startsWith('ts_test_')) {
            return 'API key should start with ts_live_ or ts_test_';
          }
          return true;
        },
      },
    ]);
    apiKey = enteredKey;
  }

  console.log(chalk.green("\n✅ Great! Here's how to connect:\n"));
  console.log(chalk.bold('1. Add these environment variables:\n'));

  if (provider === 'openai' || provider === 'both') {
    console.log(chalk.cyan('   export OPENAI_BASE_URL=https://gateway.trustscope.ai/v1'));
  }
  if (provider === 'anthropic' || provider === 'both') {
    console.log(chalk.cyan('   export ANTHROPIC_BASE_URL=https://gateway.trustscope.ai'));
  }
  console.log(chalk.cyan(`   export TRUSTSCOPE_API_KEY=${apiKey}`));

  console.log(chalk.bold("\n2. That's it! Your existing LLM calls will now flow through TrustScope.\n"));

  const { addToProfile } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'addToProfile',
      message: 'Would you like me to add these to your shell profile?',
      default: false,
    },
  ]);

  if (addToProfile) {
    const shell = process.env.SHELL || '/bin/zsh';
    const profileFile = shell.includes('zsh')
      ? join(homedir(), '.zshrc')
      : join(homedir(), '.bashrc');

    const envLines = [
      '',
      '# TrustScope configuration',
    ];

    if (provider === 'openai' || provider === 'both') {
      envLines.push('export OPENAI_BASE_URL=https://gateway.trustscope.ai/v1');
    }
    if (provider === 'anthropic' || provider === 'both') {
      envLines.push('export ANTHROPIC_BASE_URL=https://gateway.trustscope.ai');
    }
    envLines.push(`export TRUSTSCOPE_API_KEY=${apiKey}`);
    envLines.push('');

    try {
      appendFileSync(profileFile, envLines.join('\n'));
      console.log(chalk.green(`\n✅ Added to ${profileFile}`));
      console.log(chalk.dim(`Run "source ${profileFile}" to apply changes.\n`));
    } catch (error) {
      console.log(chalk.yellow(`\n⚠️  Could not write to ${profileFile}`));
      console.log(chalk.dim('Please add the environment variables manually.\n'));
    }
  }

  printSetupComplete();
}

async function setupSDKIntegration(inquirer: typeof import('inquirer').default): Promise<void> {
  const { language } = await inquirer.prompt([
    {
      type: 'list',
      name: 'language',
      message: 'Which language?',
      choices: [
        { name: 'Python', value: 'python' },
        { name: 'TypeScript/JavaScript', value: 'typescript' },
      ],
    },
  ]);

  // Get API key from environment or prompt user
  let apiKey = process.env.TRUSTSCOPE_API_KEY;

  if (!apiKey) {
    console.log(chalk.yellow('\n⚠️  No API key found.'));
    console.log(chalk.dim('Create a project at https://app.trustscope.ai/onboarding to get your API key.\n'));

    const { enteredKey } = await inquirer.prompt([
      {
        type: 'input',
        name: 'enteredKey',
        message: 'Enter your TrustScope API key (ts_live_xxx):',
        validate: (input: string) => {
          if (!input) return 'API key is required';
          if (!input.startsWith('ts_live_') && !input.startsWith('ts_test_')) {
            return 'API key should start with ts_live_ or ts_test_';
          }
          return true;
        },
      },
    ]);
    apiKey = enteredKey;
  }

  console.log('');

  if (language === 'python') {
    console.log(chalk.bold('Install the SDK:'));
    console.log(chalk.cyan('\n   pip install trustscope\n'));

    console.log(chalk.bold('Add to your agent:'));
    console.log(chalk.dim(`
   from trustscope import TrustScope

   ts = TrustScope(api_key="${apiKey}")  # or set TRUSTSCOPE_API_KEY

   # Wrap your LLM client
   client = ts.wrap(OpenAI())

   # Use as normal - all calls are now tracked
   response = client.chat.completions.create(...)`));
  } else {
    console.log(chalk.bold('Install the SDK:'));
    console.log(chalk.cyan('\n   npm install @trustscope/sdk\n'));

    console.log(chalk.bold('Add to your agent:'));
    console.log(chalk.dim(`
   import { TrustScope } from '@trustscope/sdk';
   import OpenAI from 'openai';

   const ts = new TrustScope({ apiKey: '${apiKey}' });  // or set TRUSTSCOPE_API_KEY

   // Wrap your LLM client
   const client = ts.wrap(new OpenAI());

   // Use as normal - all calls are now tracked
   const response = await client.chat.completions.create(...);`));
  }

  console.log('');
  console.log(chalk.dim(`Docs: https://docs.trustscope.ai/sdk/${language}\n`));

  printSetupComplete();
}

async function setupMCPWrapper(inquirer: typeof import('inquirer').default): Promise<void> {
  console.log(chalk.dim('\nSearching for MCP configurations...\n'));

  // Find MCP configs
  const mcpConfigs = await detectMcpConfigs(process.cwd(), false);

  if (mcpConfigs.length === 0) {
    console.log(chalk.yellow('No MCP configurations found.\n'));
    console.log(chalk.dim('MCP configs are typically located at:'));
    console.log(chalk.dim('  - ~/.config/claude/claude_desktop_config.json'));
    console.log(chalk.dim('  - ~/.cursor/mcp.json'));
    console.log(chalk.dim('  - .mcp.json in your project\n'));
    return;
  }

  // Get API key from environment or prompt user
  let apiKey = process.env.TRUSTSCOPE_API_KEY;

  if (!apiKey) {
    console.log(chalk.yellow('⚠️  No API key found.'));
    console.log(chalk.dim('Create a project at https://app.trustscope.ai/onboarding to get your API key.\n'));

    const { enteredKey } = await inquirer.prompt([
      {
        type: 'input',
        name: 'enteredKey',
        message: 'Enter your TrustScope API key (ts_live_xxx):',
        validate: (input: string) => {
          if (!input) return 'API key is required';
          if (!input.startsWith('ts_live_') && !input.startsWith('ts_test_')) {
            return 'API key should start with ts_live_ or ts_test_';
          }
          return true;
        },
      },
    ]);
    apiKey = enteredKey;
  }

  // Type guard: at this point apiKey is definitely set
  if (!apiKey) {
    console.log(chalk.red('API key is required.'));
    return;
  }

  console.log(chalk.green('Found MCP configurations:\n'));

  const choices = mcpConfigs.map(config => {
    const serverCount = config.servers.length;
    return {
      name: `${config.source} (${serverCount} server${serverCount !== 1 ? 's' : ''})`,
      value: config.source,
      short: config.source,
    };
  });

  const { selectedConfigs } = await inquirer.prompt([
    {
      type: 'checkbox',
      name: 'selectedConfigs',
      message: 'Which would you like to wrap?',
      choices,
      validate: (answer: string[]) => {
        if (answer.length < 1) {
          return 'Please select at least one configuration.';
        }
        return true;
      },
    },
  ]);

  if (selectedConfigs.length === 0) {
    console.log(chalk.dim('\nNo configurations selected.\n'));
    return;
  }

  // Process each selected config
  for (const configPath of selectedConfigs) {
    const config = mcpConfigs.find(c => c.source === configPath);
    if (!config) continue;

    console.log(chalk.dim(`\nUpdating ${configPath}...`));

    try {
      const content = readFileSync(configPath, 'utf-8');
      const configData = JSON.parse(content);

      // Wrap each server
      let wrappedCount = 0;
      const mcpServers = configData.mcpServers || {};

      for (const [name, server] of Object.entries(mcpServers)) {
        const serverConfig = server as MCPServerConfig;

        // Skip if already wrapped
        if (serverConfig.env?.TRUSTSCOPE_ENABLED) {
          console.log(chalk.dim(`  ⏭️  ${name} (already wrapped)`));
          continue;
        }

        // Add TrustScope wrapper env
        serverConfig.env = {
          ...serverConfig.env,
          TRUSTSCOPE_ENABLED: 'true',
          TRUSTSCOPE_API_KEY: apiKey,
        };

        wrappedCount++;
        console.log(chalk.green(`  ✅ ${name}`));
      }

      // Save updated config
      writeFileSync(configPath, JSON.stringify(configData, null, 2));

      console.log(chalk.green(`\nWrapped ${wrappedCount} server${wrappedCount !== 1 ? 's' : ''} in ${configPath}`));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      console.log(chalk.red(`  ❌ Failed to update: ${message}`));
    }
  }

  console.log(chalk.yellow('\n⚠️  Please restart your MCP client for changes to take effect.\n'));

  printSetupComplete();
}

function printSetupComplete(): void {
  console.log(chalk.green.bold('✅ Setup complete!\n'));
  console.log('Your agents are now connected to TrustScope.');
  console.log(`View your dashboard: ${chalk.cyan.bold('https://app.trustscope.ai/dashboard')}\n`);

  console.log(chalk.dim('Tips:'));
  console.log(chalk.dim('- First 5,000 traces/month are free'));
  console.log(chalk.dim('- Upgrade to enable blocking: https://app.trustscope.ai/upgrade\n'));
}
