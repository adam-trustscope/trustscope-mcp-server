/**
 * TrustScope MCP Server Entry Point
 *
 * This is the direct entry point for the MCP server, equivalent to `trustscope mcp`.
 * It's provided as a separate binary for MCP registry compatibility.
 *
 * Usage:
 *   trustscope-mcp                    # Start in stdio mode (default)
 *   trustscope-mcp --http             # Start in HTTP mode
 *   trustscope-mcp --http --port 3001 # Start HTTP on custom port
 */

import { Command } from 'commander';
import { startMCPServer } from './mcp/server.js';
import { CLI_VERSION } from './version.js';

const program = new Command();

program
  .name('trustscope-mcp')
  .description('TrustScope MCP governance server')
  .version(CLI_VERSION)
  .option('-k, --api-key <key>', 'TrustScope API key (uses TRUSTSCOPE_API_KEY env if not set)')
  .option('--http', 'Use HTTP transport instead of stdio')
  .option('-p, --port <port>', 'HTTP port (default: 3000)', '3000')
  .option('-h, --host <host>', 'HTTP host (default: 0.0.0.0)', '0.0.0.0')
  .action(async (options) => {
    try {
      await startMCPServer({
        apiKey: options.apiKey,
        http: options.http,
        port: options.port ? parseInt(options.port, 10) : 3000,
        host: options.host || '0.0.0.0',
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`Error: ${message}`);
      process.exit(1);
    }
  });

program.parse();
