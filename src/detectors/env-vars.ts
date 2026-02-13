import { join } from 'node:path';
import type { EnvVarFinding } from '../types/cli.js';
import { fileExists, log, readTextFile } from '../utils.js';

const AI_ENV_VARS = [
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'GOOGLE_API_KEY',
  'AZURE_OPENAI_API_KEY',
  'AZURE_OPENAI_ENDPOINT',
  'MISTRAL_API_KEY',
  'COHERE_API_KEY',
  'HUGGINGFACE_API_KEY',
  'HUGGINGFACE_TOKEN',
  'REPLICATE_API_TOKEN',
  'TOGETHER_API_KEY',
  'GROQ_API_KEY',
  'PERPLEXITY_API_KEY',
  'FIREWORKS_API_KEY',
  'DEEPINFRA_API_KEY',
  'ANYSCALE_API_KEY',
] as const;

const DOTENV_FILES = [
  '.env',
  '.env.local',
  '.env.development',
  '.env.development.local',
] as const;

function parseDotenvFile(content: string): Map<string, boolean> {
  const vars = new Map<string, boolean>();
  const lines = content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    // Parse KEY=value or KEY="value" or KEY='value'
    const match = trimmed.match(/^([A-Z_][A-Z0-9_]*)=/i);
    if (match) {
      vars.set(match[1], true);
    }
  }

  return vars;
}

export async function detectEnvVars(scanDir: string, verbose: boolean = false): Promise<EnvVarFinding[]> {
  const findings: EnvVarFinding[] = [];

  // Check process environment variables
  log('Checking process environment variables', verbose);
  for (const envVar of AI_ENV_VARS) {
    if (process.env[envVar]) {
      log(`Found ${envVar} in environment`, verbose);
      findings.push({
        name: envVar,
        source: 'environment',
      });
    }
  }

  // Check dotenv files in scan directory
  for (const dotenvFile of DOTENV_FILES) {
    const filePath = join(scanDir, dotenvFile);
    log(`Checking ${filePath}`, verbose);

    if (!fileExists(filePath)) {
      continue;
    }

    const content = readTextFile(filePath);
    if (!content) {
      continue;
    }

    const vars = parseDotenvFile(content);

    for (const envVar of AI_ENV_VARS) {
      if (vars.has(envVar)) {
        log(`Found ${envVar} in ${dotenvFile}`, verbose);
        findings.push({
          name: envVar,
          source: 'dotenv',
          file: filePath,
        });
      }
    }

    // Also check for common AI key patterns that might not be in our list
    const additionalPatterns = [
      /^[A-Z_]*API[_]?KEY$/,
      /^[A-Z_]*SECRET[_]?KEY$/,
      /^[A-Z_]*TOKEN$/,
    ];

    for (const [varName] of vars) {
      // Skip if already in our known list
      if (AI_ENV_VARS.includes(varName as typeof AI_ENV_VARS[number])) {
        continue;
      }

      // Check if it matches AI-related patterns
      for (const pattern of additionalPatterns) {
        if (pattern.test(varName)) {
          log(`Found potential AI key ${varName} in ${dotenvFile}`, verbose);
          findings.push({
            name: varName,
            source: 'dotenv',
            file: filePath,
          });
          break;
        }
      }
    }
  }

  // Deduplicate findings (same var might be in env and dotenv)
  const seen = new Set<string>();
  const deduplicated: EnvVarFinding[] = [];

  for (const finding of findings) {
    const key = `${finding.name}-${finding.source}-${finding.file || ''}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduplicated.push(finding);
    }
  }

  return deduplicated;
}
