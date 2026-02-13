import { readFile } from 'node:fs/promises';
import { glob } from 'glob';
import type { CodePatternFinding } from '../types/cli.js';
import { getRelativePath, log } from '../utils.js';

/**
 * Comprehensive AI agent and LLM framework detection patterns.
 *
 * Each pattern is designed to catch both Python and JavaScript/TypeScript imports
 * while minimizing false positives.
 */
const AGENT_PATTERNS: Record<string, RegExp> = {
  // === ORCHESTRATION FRAMEWORKS ===

  // LangChain - Most popular agent orchestration framework
  langchain: /from\s+langchain|from\s+['"]@?langchain|require\(['"]@?langchain/,

  // CrewAI - Multi-agent orchestration
  crewai: /from\s+crewai|from\s+['"]crewai/,

  // AutoGen - Microsoft's multi-agent framework
  autogen: /from\s+autogen|from\s+['"]autogen|AssistantAgent|UserProxyAgent/,

  // Microsoft Semantic Kernel - Enterprise AI orchestration
  semantic_kernel: /from\s+semantic_kernel|from\s+['"]semantic-kernel|import\s+.*Kernel.*from|SKContext/,

  // LlamaIndex - RAG and agent framework
  llamaindex: /from\s+llama_index|from\s+['"]llama-?index|VectorStoreIndex|SimpleDirectoryReader/,

  // Haystack - NLP/AI framework by deepset
  haystack: /from\s+haystack|from\s+['"]haystack|Pipeline|PromptNode/,

  // Vercel AI SDK - Popular web AI framework
  vercel_ai: /from\s+['"]ai['"]|import\s+\{[^}]*\}\s+from\s+['"]ai['"]|useChat|useCompletion|streamText/,

  // OpenAI Agents SDK
  agents_sdk: /from\s+agents\s|from\s+['"]@?openai\/agents|require\(['"]@?openai\/agents/,

  // Pydantic AI - Type-safe agent framework
  pydantic_ai: /from\s+pydantic_ai|from\s+['"]pydantic-ai/,

  // smolagents - Hugging Face's agent framework
  smolagents: /from\s+smolagents|from\s+['"]smolagents/,

  // Instructor - Structured extraction with LLMs
  instructor: /from\s+instructor|from\s+['"]instructor|import\s+instructor/,

  // DSPy - Declarative Language Model Programs
  dspy: /from\s+dspy|import\s+dspy|dspy\.Signature|dspy\.Module/,

  // === LLM PROVIDER SDKs ===

  // OpenAI SDK
  openai_sdk: /from\s+openai\s|from\s+['"]openai['"]|require\(['"]openai['"]\)|new\s+OpenAI\(|ChatCompletion|Completion\./,

  // Anthropic SDK
  anthropic_sdk: /from\s+anthropic|from\s+['"]@?anthropic|require\(['"]@?anthropic|new\s+Anthropic\(/,

  // Google AI (Gemini)
  google_ai: /from\s+google\.generativeai|from\s+['"]@google\/generative-ai|GoogleGenerativeAI|genai\.GenerativeModel/,

  // Google Vertex AI
  vertex_ai: /from\s+google\.cloud\.aiplatform|from\s+['"]@google-cloud\/aiplatform|vertexai|VertexAI/,

  // Mistral AI
  mistral_ai: /from\s+mistralai|from\s+['"]@mistralai|Mistral\(/,

  // Cohere
  cohere: /from\s+cohere|from\s+['"]cohere-ai|require\(['"]cohere|new\s+Cohere\(/,

  // Groq
  groq_sdk: /from\s+groq|from\s+['"]groq-sdk|Groq\(/,

  // Together AI
  together_ai: /from\s+together|from\s+['"]together-ai|Together\(/,

  // Replicate
  replicate: /from\s+replicate|from\s+['"]replicate|Replicate\(/,

  // Hugging Face
  huggingface: /from\s+transformers|from\s+['"]@huggingface|HfInference|InferenceClient/,

  // AWS Bedrock
  bedrock: /from\s+['"]@aws-sdk\/client-bedrock|BedrockRuntimeClient|InvokeModelCommand/,

  // Azure OpenAI
  azure_openai: /from\s+['"]@azure\/openai|AzureOpenAI|azure\.ai\.openai/,

  // === AGENT CAPABILITIES ===

  // Tool/Function calling patterns
  tool_use: /tools\s*[=:]\s*\[|\.bind_tools\(|function_call|tool_choice|tool_calls|create_function|@tool/,

  // MCP (Model Context Protocol) clients
  mcp_client: /MCPClient|mcp\.client|from\s+['"]@?modelcontextprotocol|from\s+mcp\s|StdioServerTransport/,

  // Agent memory patterns
  agent_memory: /ConversationBuffer|ChatMessageHistory|MemoryStore|persistence|BaseChatMemory|save_context/,

  // RAG (Retrieval Augmented Generation) patterns
  rag: /VectorStore|FAISS|Pinecone|Weaviate|Chroma|Qdrant|retriever|RetrievalQA|embed_documents/,

  // Prompt templates and management
  prompt_templates: /PromptTemplate|ChatPromptTemplate|FewShotPrompt|MessagesPlaceholder|SystemMessage/,

  // Agent executors and chains
  agent_executor: /AgentExecutor|create_agent|initialize_agent|RunnableSequence|RunnableParallel/,

  // Streaming patterns (important for real-time monitoring)
  streaming: /stream\s*[=:]\s*true|\.stream\(|createStream|StreamingResponse|AsyncIterator/,

  // === EMERGING PATTERNS ===

  // Browser automation with AI (Playwright AI, etc.)
  browser_ai: /playwright.*ai|puppeteer.*ai|browser_use|WebAgent|BrowserAgent/,

  // Code execution agents
  code_execution: /exec\(|subprocess|PythonREPL|ShellTool|CodeInterpreter|execute_code/,

  // File system access in agents
  file_access: /FileSystemTools|ReadFileTool|WriteFileTool|DirectoryLoader|file_path.*agent/i,
};

const CODE_EXTENSIONS = ['**/*.py', '**/*.ts', '**/*.js', '**/*.tsx', '**/*.jsx'];

const IGNORE_PATTERNS = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/venv/**',
  '**/.venv/**',
  '**/env/**',
  '**/__pycache__/**',
  '**/.pytest_cache/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.bundle.js',
];

const MAX_DEPTH = 5;

function countDepth(path: string, basePath: string): number {
  const relativePath = getRelativePath(basePath, path);
  return relativePath.split('/').filter(Boolean).length;
}

export async function detectCodePatterns(
  scanDir: string,
  verbose: boolean = false
): Promise<CodePatternFinding[]> {
  const findings: CodePatternFinding[] = [];

  log(`Scanning for code patterns in ${scanDir}`, verbose);

  // Find all matching files
  const files: string[] = [];
  for (const pattern of CODE_EXTENSIONS) {
    const matches = await glob(pattern, {
      cwd: scanDir,
      absolute: true,
      ignore: IGNORE_PATTERNS,
      nodir: true,
    });
    files.push(...matches);
  }

  log(`Found ${files.length} code files to scan`, verbose);

  // Filter by max depth and deduplicate
  const uniqueFiles = [...new Set(files)].filter(
    (file) => countDepth(file, scanDir) <= MAX_DEPTH
  );

  log(`Scanning ${uniqueFiles.length} files after depth filter`, verbose);

  await Promise.all(uniqueFiles.map(async (filePath) => {
    try {
      const content = await readFile(filePath, 'utf-8');
      const lines = content.split('\n');

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];

        for (const [framework, pattern] of Object.entries(AGENT_PATTERNS)) {
          if (pattern.test(line)) {
            const relativePath = getRelativePath(scanDir, filePath);
            log(`Found ${framework} pattern in ${relativePath}:${lineIndex + 1}`, verbose);

            findings.push({
              file: relativePath,
              line: lineIndex + 1,
              pattern: line.trim().slice(0, 100), // Limit pattern length
              framework,
            });
          }
        }
      }
    } catch (error) {
      // Skip files that can't be read (binary files, permission issues, etc.)
      log(`Could not read file: ${filePath}`, verbose);
    }
  }));

  // Sort findings by file and line
  findings.sort((a, b) => {
    if (a.file !== b.file) {
      return a.file.localeCompare(b.file);
    }
    return a.line - b.line;
  });

  return findings;
}
