import { join } from 'node:path';
import type { DependencyFinding } from '../types/cli.js';
import { fileExists, log, readJsonFile, readTextFile } from '../utils.js';

/**
 * Comprehensive list of AI-related packages across ecosystems.
 *
 * These are packages that indicate AI agent or LLM usage in a codebase,
 * organized by package manager and category.
 */
const AI_PACKAGES = {
  npm: [
    // === LLM Provider SDKs ===
    'openai',
    '@anthropic-ai/sdk',
    '@google/generative-ai',
    '@google-cloud/aiplatform',
    '@mistralai/mistralai',
    'cohere-ai',
    'groq-sdk',
    'replicate',
    '@huggingface/inference',
    '@azure/openai',
    '@aws-sdk/client-bedrock-runtime',
    '@aws-sdk/client-bedrock',
    'together-ai',

    // === Orchestration Frameworks ===
    'langchain',
    '@langchain/core',
    '@langchain/openai',
    '@langchain/anthropic',
    '@langchain/google-genai',
    '@langchain/google-vertexai',
    '@langchain/community',
    '@langchain/pinecone',
    '@langchain/weaviate',
    'llamaindex',
    'ai',
    '@ai-sdk/openai',
    '@ai-sdk/anthropic',
    '@ai-sdk/google',
    '@ai-sdk/google-vertex',
    '@ai-sdk/mistral',
    '@ai-sdk/cohere',
    '@ai-sdk/amazon-bedrock',
    '@ai-sdk/azure',

    // === Agent Frameworks ===
    'agents',
    '@openai/agents',
    '@modelcontextprotocol/sdk',

    // === Vector Databases ===
    '@pinecone-database/pinecone',
    'weaviate-ts-client',
    '@qdrant/js-client-rest',
    'chromadb',
    '@zilliz/milvus2-sdk-node',

    // === Prompt Engineering ===
    'promptfoo',
    'langfuse',
    'instructor-js',

    // === AI Utilities ===
    'tiktoken',
    'gpt-tokenizer',
    '@dqbd/tiktoken',
    'pdf-parse',          // Often used with AI for document processing
    'unstructured-client', // Document processing for RAG
  ],
  pip: [
    // === LLM Provider SDKs ===
    'openai',
    'anthropic',
    'google-generativeai',
    'google-cloud-aiplatform',
    'vertexai',
    'mistralai',
    'cohere',
    'groq',
    'replicate',
    'huggingface-hub',
    'transformers',
    'together',
    'boto3',              // When used with Bedrock

    // === Orchestration Frameworks ===
    'langchain',
    'langchain-core',
    'langchain-openai',
    'langchain-anthropic',
    'langchain-google-genai',
    'langchain-google-vertexai',
    'langchain-community',
    'langchain-experimental',
    'llama-index',
    'llama-index-core',
    'llama-index-llms-openai',
    'llama-index-llms-anthropic',
    'llama-index-embeddings-openai',
    'llama-index-vector-stores-pinecone',

    // === Agent Frameworks ===
    'crewai',
    'crewai-tools',
    'autogen',
    'pyautogen',
    'autogen-agentchat',
    'autogen-ext',
    'haystack-ai',
    'semantic-kernel',
    'pydantic-ai',
    'smolagents',
    'dspy-ai',
    'instructor',
    'marvin',
    'guidance',
    'outlines',

    // === MCP ===
    'mcp',
    'anthropic-tools',

    // === Vector Databases ===
    'pinecone-client',
    'pinecone',
    'weaviate-client',
    'qdrant-client',
    'chromadb',
    'pymilvus',
    'faiss-cpu',
    'faiss-gpu',
    'pgvector',
    'lancedb',

    // === RAG & Document Processing ===
    'unstructured',
    'unstructured-client',
    'pypdf',
    'pymupdf',
    'docx2txt',
    'tiktoken',

    // === Prompt Engineering & Evaluation ===
    'promptfoo',
    'langfuse',
    'langsmith',
    'phoenix-ai',
    'arize',
    'deepeval',
    'ragas',

    // === Fine-tuning & Training ===
    'peft',
    'trl',
    'datasets',
    'accelerate',
    'bitsandbytes',

    // === Inference ===
    'vllm',
    'text-generation-inference',
    'llama-cpp-python',
    'ollama',
  ],
} as const;

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function parseRequirementsTxt(content: string): Array<{ name: string; version?: string }> {
  const deps: Array<{ name: string; version?: string }> = [];
  const lines = content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines, comments, and options
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
      continue;
    }

    // Handle package specifications
    // Examples: package, package==1.0.0, package>=1.0.0, package[extra], package @ url
    const match = trimmed.match(/^([a-zA-Z0-9_-]+)(?:\[.*?\])?(?:\s*(?:==|>=|<=|~=|!=|>|<|@)\s*(.*))?/);
    if (match) {
      deps.push({
        name: match[1].toLowerCase(),
        version: match[2]?.trim(),
      });
    }
  }

  return deps;
}

export async function detectPackageDeps(
  scanDir: string,
  verbose: boolean = false
): Promise<DependencyFinding[]> {
  const findings: DependencyFinding[] = [];

  // Check package.json
  const packageJsonPath = join(scanDir, 'package.json');
  log(`Checking ${packageJsonPath}`, verbose);

  if (fileExists(packageJsonPath)) {
    const packageJson = readJsonFile<PackageJson>(packageJsonPath);

    if (packageJson) {
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
      };

      for (const [name, version] of Object.entries(allDeps)) {
        // Check if it's an AI package
        const normalizedName = name.toLowerCase();
        const isAiPackage = AI_PACKAGES.npm.some(
          (pkg) => pkg.toLowerCase() === normalizedName
        );

        if (isAiPackage) {
          log(`Found npm AI dependency: ${name}@${version}`, verbose);
          findings.push({
            name,
            version: version || undefined,
            source: 'npm',
            file: packageJsonPath,
          });
        }
      }
    }
  }

  // Check requirements.txt
  const requirementsTxtPath = join(scanDir, 'requirements.txt');
  log(`Checking ${requirementsTxtPath}`, verbose);

  if (fileExists(requirementsTxtPath)) {
    const content = readTextFile(requirementsTxtPath);

    if (content) {
      const deps = parseRequirementsTxt(content);

      for (const dep of deps) {
        const isAiPackage = AI_PACKAGES.pip.some(
          (pkg) => pkg.toLowerCase() === dep.name
        );

        if (isAiPackage) {
          log(`Found pip AI dependency: ${dep.name}${dep.version ? `==${dep.version}` : ''}`, verbose);
          findings.push({
            name: dep.name,
            version: dep.version,
            source: 'pip',
            file: requirementsTxtPath,
          });
        }
      }
    }
  }

  // Check pyproject.toml for Python projects
  const pyprojectPath = join(scanDir, 'pyproject.toml');
  log(`Checking ${pyprojectPath}`, verbose);

  if (fileExists(pyprojectPath)) {
    const content = readTextFile(pyprojectPath);

    if (content) {
      // Simple regex-based parsing for dependencies
      // This handles both [project.dependencies] and [tool.poetry.dependencies]
      for (const aiPackage of AI_PACKAGES.pip) {
        const patterns = [
          new RegExp(`["']${aiPackage}["']`, 'i'),
          new RegExp(`^${aiPackage}\\s*=`, 'im'),
          new RegExp(`["']${aiPackage}[><=~!@\\[\\s]`, 'i'),
        ];

        for (const pattern of patterns) {
          if (pattern.test(content)) {
            log(`Found pip AI dependency in pyproject.toml: ${aiPackage}`, verbose);
            findings.push({
              name: aiPackage,
              source: 'pip',
              file: pyprojectPath,
            });
            break;
          }
        }
      }
    }
  }

  // Deduplicate (same package might be in requirements.txt and pyproject.toml)
  const seen = new Set<string>();
  const deduplicated: DependencyFinding[] = [];

  for (const finding of findings) {
    const key = `${finding.name}-${finding.source}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduplicated.push(finding);
    }
  }

  return deduplicated;
}
