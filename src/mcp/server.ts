/**
 * TrustScope MCP Server
 *
 * Supports two modes:
 * - Local: No API key, uses SQLite storage and local detection engines
 * - Connected: With API key, syncs to TrustScope cloud
 *
 * 11 governance tools available in both modes.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';

import { TOOL_DEFINITIONS, LocalToolExecutor } from './tools/index.js';
import { EvidenceStore } from '../evidence/store.js';
import { loadConfig } from '../config/index.js';
import type {
  CheckPolicyInput,
  CheckDetectionInput,
  LogActionInput,
  ListTracesInput,
  ListPoliciesInput,
  ListApprovalsInput,
  ApproveInput,
  GetAgentDNAInput,
  GetComplianceInput,
  ExplainBehaviorInput,
  GetAttestationInput,
} from './types.js';

export type MCPMode = 'local' | 'connected';

export interface TrustScopeMCPServerOptions {
  apiKey?: string;
  baseUrl?: string;
  serverName?: string;
  serverVersion?: string;
  /** External evidence store for hybrid mode */
  store?: EvidenceStore;
}

export interface StartMCPServerOptions {
  apiKey?: string;
  http?: boolean;
  port?: number;
  host?: string;
}

export class TrustScopeMCPServer {
  private server: Server;
  private mode: MCPMode;
  private store: EvidenceStore;
  private localExecutor: LocalToolExecutor;
  private options: {
    apiKey: string | null;
    baseUrl: string;
    serverName: string;
    serverVersion: string;
  };

  constructor(options: TrustScopeMCPServerOptions = {}) {
    // Load config and merge with options
    const config = loadConfig();
    const apiKey = options.apiKey || config.apiKey || process.env.TRUSTSCOPE_API_KEY || null;

    // Determine mode based on API key presence
    this.mode = apiKey ? 'connected' : 'local';

    this.options = {
      apiKey,
      baseUrl: options.baseUrl || config.baseUrl || process.env.TRUSTSCOPE_BASE_URL || 'https://api.trustscope.ai',
      serverName: options.serverName || 'trustscope-mcp',
      serverVersion: options.serverVersion || '1.0.0',
    };

    // Use external store if provided (for hybrid mode), otherwise create new
    this.store = options.store || new EvidenceStore();

    // Initialize local executor
    this.localExecutor = new LocalToolExecutor(this.store);

    // Create MCP server
    this.server = new Server(
      {
        name: this.options.serverName,
        version: this.options.serverVersion,
      },
      {
        capabilities: {
          tools: {},
        },
      },
    );

    this.setupHandlers();
  }

  getMode(): MCPMode {
    return this.mode;
  }

  private setupHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const tools: Tool[] = TOOL_DEFINITIONS.map((def) => ({
        name: def.name,
        description: def.description,
        inputSchema: def.inputSchema,
      }));

      return { tools };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const result = await this.callTool(name, args || {});

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(
                {
                  error: errorMessage,
                  tool: name,
                  mode: this.mode,
                  entry_point: 'mcp',
                },
                null,
                2,
              ),
            },
          ],
          isError: true,
        };
      }
    });
  }

  private async callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
    // In connected mode, could call cloud API (not implemented yet)
    // For now, always use local executor
    if (this.mode === 'connected') {
      // TODO: Implement cloud API calls when needed
      // For now, fall through to local mode
      console.error(`[TrustScope] Connected mode uses local execution (cloud sync coming soon)`);
    }

    // Local execution using LocalToolExecutor
    switch (name) {
      case 'trustscope_check_policy':
        return this.localExecutor.checkPolicy(args as unknown as CheckPolicyInput);

      case 'trustscope_check_detection':
        return this.localExecutor.checkDetection(args as unknown as CheckDetectionInput);

      case 'trustscope_log_action':
        return this.localExecutor.logAction(args as unknown as LogActionInput);

      case 'trustscope_list_traces':
        return this.localExecutor.listTraces(args as unknown as ListTracesInput);

      case 'trustscope_list_policies':
        return this.localExecutor.listPolicies(args as unknown as ListPoliciesInput);

      case 'trustscope_list_approvals':
        return this.localExecutor.listApprovals(args as unknown as ListApprovalsInput);

      case 'trustscope_approve':
        return this.localExecutor.approve(args as unknown as ApproveInput);

      case 'trustscope_get_agent_dna':
        return this.localExecutor.getAgentDNA(args as unknown as GetAgentDNAInput);

      case 'trustscope_get_compliance':
        return this.localExecutor.getCompliance(args as unknown as GetComplianceInput);

      case 'trustscope_explain_behavior':
        return this.localExecutor.explainBehavior(args as unknown as ExplainBehaviorInput);

      case 'trustscope_get_attestation':
        return this.localExecutor.getAttestation(args as unknown as GetAttestationInput);

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  async runStdio(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);

    // Log mode to stderr (stdout is for MCP protocol)
    console.error(`[TrustScope] MCP server started (${this.mode} mode)`);
    console.error(`[TrustScope] 11 tools available`);
    console.error(`[TrustScope] Evidence: ${this.store.getDbPath()}`);

    // Handle graceful shutdown
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });

    process.on('SIGTERM', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  getServer(): Server {
    return this.server;
  }

  getStore(): EvidenceStore {
    return this.store;
  }
}

export function createServer(options?: TrustScopeMCPServerOptions): TrustScopeMCPServer {
  return new TrustScopeMCPServer(options);
}

/**
 * Start the MCP server (CLI entry point)
 */
export async function startMCPServer(options: StartMCPServerOptions = {}): Promise<void> {
  const server = createServer({
    apiKey: options.apiKey,
  });

  if (options.http) {
    // HTTP transport - dynamic import to avoid loading express for stdio mode
    const { createHttpServer } = await import('./http-transport.js');
    const httpServer = createHttpServer(server, {
      port: options.port || 3000,
      host: options.host || '0.0.0.0',
    });
    await httpServer.start();
  } else {
    // Default: stdio transport
    await server.runStdio();
  }
}

// Export for direct use
export { Server };
