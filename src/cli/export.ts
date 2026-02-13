/**
 * TrustScope Export Command
 *
 * Exports evidence to JSON, CSV, or SARIF format for auditors.
 */

import chalk from 'chalk';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { EvidenceStore } from '../evidence/store.js';
import type { Trace } from '../types/evidence.js';

export interface ExportOptions {
  format?: 'json' | 'csv' | 'sarif';
  output?: string;
  agent?: string;
  start?: string;
  end?: string;
}

/**
 * Convert trace to CSV row
 */
function traceToCSV(trace: Trace): string {
  const fields = [
    trace.id,
    trace.source,
    trace.agent_id || '',
    trace.session_id || '',
    trace.action_type || '',
    trace.tool_name || '',
    trace.blocked ? 'true' : 'false',
    trace.timestamp,
    trace.audit_hash,
  ];

  // Escape fields that contain commas or quotes
  return fields.map((f) => {
    const str = String(f);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  }).join(',');
}

/**
 * Generate CSV header
 */
function getCSVHeader(): string {
  return 'id,source,agent_id,session_id,action_type,tool_name,blocked,timestamp,audit_hash';
}

/**
 * Convert traces to SARIF format
 */
function tracesToSARIF(traces: Trace[]): object {
  const blockedTraces = traces.filter((t) => t.blocked);

  const results = blockedTraces.map((trace) => ({
    ruleId: trace.action_type || 'unknown',
    level: 'warning' as const,
    message: {
      text: `Blocked action: ${trace.action_type || 'unknown'} by ${trace.agent_id || 'unknown agent'}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: `.trustscope/evidence.db`,
          },
        },
      },
    ],
    properties: {
      trace_id: trace.id,
      agent_id: trace.agent_id,
      session_id: trace.session_id,
      tool_name: trace.tool_name,
      timestamp: trace.timestamp,
      audit_hash: trace.audit_hash,
    },
  }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'TrustScope Evidence Export',
            version: '1.0.0',
            informationUri: 'https://trustscope.ai',
            rules: [
              {
                id: 'blocked-action',
                name: 'Blocked Action',
                shortDescription: {
                  text: 'An action was blocked by TrustScope policy',
                },
                fullDescription: {
                  text: 'TrustScope blocked this action based on configured policies. Review the evidence for details.',
                },
                defaultConfiguration: {
                  level: 'warning',
                },
              },
            ],
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: traces.length > 0 ? traces[traces.length - 1]?.timestamp : new Date().toISOString(),
            endTimeUtc: traces.length > 0 ? traces[0]?.timestamp : new Date().toISOString(),
          },
        ],
      },
    ],
  };
}

/**
 * Export evidence for auditors
 */
export async function runExport(options?: ExportOptions): Promise<void> {
  const format = options?.format || 'json';
  const outputFile = options?.output;
  const agentFilter = options?.agent;
  const startDate = options?.start;
  const endDate = options?.end;

  const dbPath = join(process.cwd(), '.trustscope', 'evidence.db');

  // Check if evidence store exists
  if (!existsSync(dbPath)) {
    if (outputFile) {
      // Silent mode when outputting to file
      console.error(chalk.red('Error: No evidence store found'));
      process.exit(1);
    }

    console.log('');
    console.log(chalk.bold('  Evidence Export'));
    console.log(chalk.dim('  ───────────────'));
    console.log('');
    console.log(`  ${chalk.yellow('⚠')}  No evidence store found at .trustscope/evidence.db`);
    console.log('');
    console.log(chalk.dim('  Run trustscope mcp or trustscope watch to start generating evidence.'));
    console.log('');
    process.exit(0);
    return;
  }

  try {
    const store = new EvidenceStore();

    // Get traces with filters
    let traces = store.listTraces({
      agent_id: agentFilter,
      limit: 100000, // High limit for export
    });

    // Apply date filters
    if (startDate || endDate) {
      traces = traces.filter((trace) => {
        const ts = trace.timestamp as string;
        if (startDate && ts < startDate) return false;
        if (endDate && ts > endDate) return false;
        return true;
      });
    }

    if (traces.length === 0) {
      if (outputFile) {
        console.error(chalk.yellow('Warning: No traces match the filters'));
        // Still output empty data
      } else {
        console.log(chalk.yellow('No traces match the specified filters.'));
        console.log('');
        return;
      }
    }

    // Generate output
    let output: string;

    switch (format) {
      case 'json':
        output = JSON.stringify(
          {
            exported_at: new Date().toISOString(),
            filters: {
              agent: agentFilter || null,
              start: startDate || null,
              end: endDate || null,
            },
            trace_count: traces.length,
            traces: traces.map((t) => ({
              id: t.id,
              source: t.source,
              agent_id: t.agent_id,
              session_id: t.session_id,
              action_type: t.action_type,
              tool_name: t.tool_name,
              blocked: t.blocked,
              timestamp: t.timestamp,
              prev_hash: t.prev_hash,
              audit_hash: t.audit_hash,
              request_summary: t.request_summary,
              response_summary: t.response_summary,
            })),
          },
          null,
          2,
        );
        break;

      case 'csv':
        const csvLines = [getCSVHeader()];
        for (const trace of traces) {
          csvLines.push(traceToCSV(trace));
        }
        output = csvLines.join('\n');
        break;

      case 'sarif':
        output = JSON.stringify(tracesToSARIF(traces), null, 2);
        break;

      default:
        console.error(chalk.red(`Unknown format: ${format}`));
        process.exit(1);
        return;
    }

    // Output
    if (outputFile) {
      writeFileSync(outputFile, output);
      console.log(chalk.green(`✅ Exported ${traces.length} traces to ${outputFile}`));
    } else {
      console.log(output);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(chalk.red(`Export failed: ${message}`));
    process.exit(1);
  }
}
