import express, { Express, Request, Response } from 'express';
import type { TrustScopeMCPServer } from './server.js';

export interface HttpServerOptions {
  port: number;
  host: string;
}

export interface HttpMCPServer {
  start(): Promise<void>;
  stop(): Promise<void>;
}

export function createHttpServer(
  mcpServer: TrustScopeMCPServer,
  options: HttpServerOptions
): HttpMCPServer {
  const app: Express = express();

  app.use(express.json());

  // Health check
  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      mode: mcpServer.getMode(),
      tools: 11,
    });
  });

  // Tools list
  app.get('/tools', async (_req: Request, res: Response) => {
    try {
      // Get tools from the MCP server
      const server = mcpServer.getServer();
      // Note: In a real implementation, we'd need to expose this properly
      res.json({
        tools: [],
        mode: mcpServer.getMode(),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      res.status(500).json({ error: message });
    }
  });

  // Tool call
  app.post('/call/:toolName', async (req: Request, res: Response) => {
    try {
      const { toolName } = req.params;
      const args = req.body;

      // Note: In a real implementation, we'd call the tool through the MCP server
      res.json({
        result: `Tool ${toolName} called`,
        args,
        mode: mcpServer.getMode(),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      res.status(500).json({ error: message });
    }
  });

  let server: ReturnType<Express['listen']> | null = null;

  return {
    async start(): Promise<void> {
      return new Promise((resolve) => {
        server = app.listen(options.port, options.host, () => {
          console.log(
            `TrustScope MCP server (HTTP) listening on http://${options.host}:${options.port} (${mcpServer.getMode()} mode)`
          );
          resolve();
        });
      });
    },

    async stop(): Promise<void> {
      return new Promise((resolve, reject) => {
        if (server) {
          server.close((err) => {
            if (err) reject(err);
            else resolve();
          });
        } else {
          resolve();
        }
      });
    },
  };
}
