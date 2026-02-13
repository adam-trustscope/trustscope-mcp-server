/**
 * Command Firewall - Block dangerous shell, SQL, and code execution patterns
 *
 * Categories:
 * - Destructive Shell Commands (rm -rf, sudo, dd, etc.)
 * - Destructive SQL Commands (DROP, TRUNCATE, DELETE without WHERE)
 * - Code Execution Functions (eval, exec, system)
 * - Secrets & Environment Access
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
  CommandMatch,
  CommandCategory,
  Severity,
} from '../types.js';

interface CommandPattern {
  pattern: RegExp;
  category: CommandCategory;
  severity: Severity;
  description: string;
}

const COMMAND_PATTERNS: Record<string, CommandPattern> = {
  // Shell - Destructive
  rm_rf_root: {
    pattern: /\brm\s+-r[f]?\s*\//gi,
    category: 'shell',
    severity: 'critical',
    description: 'rm -rf / command',
  },
  rm_rf_wildcard: {
    pattern: /\brm\s+-r[f]?\s+\*/gi,
    category: 'shell',
    severity: 'critical',
    description: 'rm -rf * command',
  },
  rm_rf_home: {
    pattern: /\brm\s+-r[f]?\s+~/gi,
    category: 'shell',
    severity: 'critical',
    description: 'rm -rf ~ command',
  },
  rmdir_recursive: {
    pattern: /\brmdir\s+\/s/gi,
    category: 'shell',
    severity: 'critical',
    description: 'rmdir /s command',
  },

  // Shell - Privilege escalation
  sudo: {
    pattern: /\bsudo\s+/gi,
    category: 'shell',
    severity: 'high',
    description: 'sudo command',
  },
  su_root: {
    pattern: /\bsu\s+root/gi,
    category: 'shell',
    severity: 'high',
    description: 'su root command',
  },
  chmod_777: {
    pattern: /\bchmod\s+(-R\s+)?777/gi,
    category: 'shell',
    severity: 'high',
    description: 'chmod 777 (overly permissive)',
  },

  // Shell - Remote code execution
  curl_pipe_bash: {
    pattern: /curl\s+[^\s]+\s*\|\s*(bash|sh)/gi,
    category: 'shell',
    severity: 'high',
    description: 'curl | bash pattern',
  },
  wget_pipe_sh: {
    pattern: /wget\s+[^\s]+\s*\|\s*(bash|sh)/gi,
    category: 'shell',
    severity: 'critical',
    description: 'wget | sh pattern',
  },

  // Shell - Disk operations
  dd_command: {
    pattern: /\bdd\s+if=/gi,
    category: 'shell',
    severity: 'critical',
    description: 'dd if= (disk destroyer)',
  },
  mkfs: {
    pattern: /\bmkfs/gi,
    category: 'shell',
    severity: 'critical',
    description: 'mkfs (format filesystem)',
  },
  overwrite_disk: {
    pattern: />\s*\/dev\/sd[a-z]/gi,
    category: 'shell',
    severity: 'critical',
    description: '> /dev/sda (overwrite disk)',
  },

  // Shell - Fork bomb
  fork_bomb: {
    pattern: /:\(\)\{:\|:&\};:/g,
    category: 'shell',
    severity: 'critical',
    description: 'Fork bomb',
  },

  // Shell - Reverse shells
  nc_reverse_shell: {
    pattern: /\bnc\s+-e/gi,
    category: 'shell',
    severity: 'critical',
    description: 'nc -e (reverse shell)',
  },
  netcat_reverse_shell: {
    pattern: /\bnetcat\s+-e/gi,
    category: 'shell',
    severity: 'critical',
    description: 'netcat -e (reverse shell)',
  },
  mkfifo_reverse_shell: {
    pattern: /mkfifo.*nc\s+/gi,
    category: 'shell',
    severity: 'critical',
    description: 'mkfifo reverse shell',
  },

  // Shell - PowerShell
  powershell_remove_recurse: {
    pattern: /Remove-Item\s+-Recurse/gi,
    category: 'shell',
    severity: 'critical',
    description: 'PowerShell Remove-Item -Recurse',
  },
  invoke_expression: {
    pattern: /Invoke-Expression/gi,
    category: 'shell',
    severity: 'high',
    description: 'PowerShell Invoke-Expression',
  },
  bypass_execution_policy: {
    pattern: /-ExecutionPolicy\s+Bypass/gi,
    category: 'shell',
    severity: 'high',
    description: 'PowerShell -ExecutionPolicy Bypass',
  },

  // SQL - Destructive
  drop_table: {
    pattern: /\bDROP\s+(TABLE|DATABASE|SCHEMA)\b/gi,
    category: 'sql',
    severity: 'critical',
    description: 'DROP TABLE/DATABASE/SCHEMA',
  },
  truncate_table: {
    pattern: /\bTRUNCATE\s+TABLE\b/gi,
    category: 'sql',
    severity: 'critical',
    description: 'TRUNCATE TABLE',
  },
  delete_no_where: {
    pattern: /\bDELETE\s+FROM\s+\w+\s*(?!WHERE)/gi,
    category: 'sql',
    severity: 'high',
    description: 'DELETE FROM without WHERE',
  },
  update_no_where: {
    pattern: /\bUPDATE\s+\w+\s+SET\s+[^;]+(?!WHERE)/gi,
    category: 'sql',
    severity: 'high',
    description: 'UPDATE SET without WHERE',
  },
  alter_table_drop: {
    pattern: /\bALTER\s+TABLE\s+\w+\s+DROP/gi,
    category: 'sql',
    severity: 'high',
    description: 'ALTER TABLE ... DROP',
  },
  grant_all: {
    pattern: /\bGRANT\s+ALL/gi,
    category: 'sql',
    severity: 'warning',
    description: 'GRANT ALL',
  },

  // SQL - Injection patterns
  sql_injection_drop: {
    pattern: /;\s*DROP\s+/gi,
    category: 'sql',
    severity: 'critical',
    description: 'SQL injection with DROP',
  },
  sql_injection_or: {
    pattern: /\bOR\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/gi,
    category: 'sql',
    severity: 'warning',
    description: 'SQL injection with OR condition',
  },

  // Code Execution - Python
  eval_call: {
    pattern: /\beval\s*\(/gi,
    category: 'code_exec',
    severity: 'critical',
    description: 'eval() call',
  },
  python_exec: {
    pattern: /\bexec\s*\(/gi,
    category: 'code_exec',
    severity: 'critical',
    description: 'Python exec()',
  },
  python_os_system: {
    pattern: /\bos\.system\s*\(/gi,
    category: 'code_exec',
    severity: 'critical',
    description: 'Python os.system()',
  },
  python_subprocess: {
    pattern: /\bsubprocess\.(call|run|Popen|check_output)/gi,
    category: 'code_exec',
    severity: 'high',
    description: 'Python subprocess',
  },
  python_import: {
    pattern: /__import__\s*\(/gi,
    category: 'code_exec',
    severity: 'high',
    description: 'Python __import__()',
  },

  // Code Execution - JavaScript
  js_new_function: {
    pattern: /\bnew\s+Function\s*\(/gi,
    category: 'code_exec',
    severity: 'critical',
    description: 'JavaScript new Function()',
  },

  // Code Execution - PHP
  php_exec: {
    pattern: /\bexec\s*\(/gi,
    category: 'code_exec',
    severity: 'critical',
    description: 'PHP exec()',
  },
  php_system: {
    pattern: /\bsystem\s*\(/gi,
    category: 'code_exec',
    severity: 'critical',
    description: 'PHP system()',
  },
  php_shell_exec: {
    pattern: /\bshell_exec\s*\(/gi,
    category: 'code_exec',
    severity: 'critical',
    description: 'PHP shell_exec()',
  },

  // Code Execution - Java
  java_runtime_exec: {
    pattern: /Runtime\.getRuntime\(\)\.exec/gi,
    category: 'code_exec',
    severity: 'critical',
    description: 'Java Runtime.exec()',
  },
  java_processbuilder: {
    pattern: /\bProcessBuilder/gi,
    category: 'code_exec',
    severity: 'high',
    description: 'Java ProcessBuilder',
  },

  // Secrets Access
  python_os_environ: {
    pattern: /\bos\.environ\b/gi,
    category: 'secrets',
    severity: 'high',
    description: 'Python os.environ access',
  },
  nodejs_process_env: {
    pattern: /\bprocess\.env\b/gi,
    category: 'secrets',
    severity: 'high',
    description: 'Node.js process.env access',
  },
  getenv: {
    pattern: /\bgetenv\s*\(/gi,
    category: 'secrets',
    severity: 'high',
    description: 'getenv() call',
  },
  dotenv_file: {
    pattern: /\.env(\.local|\.production|\.development)?/gi,
    category: 'secrets',
    severity: 'high',
    description: '.env file access',
  },
  etc_passwd: {
    pattern: /\/etc\/passwd/gi,
    category: 'secrets',
    severity: 'critical',
    description: '/etc/passwd access',
  },
  etc_shadow: {
    pattern: /\/etc\/shadow/gi,
    category: 'secrets',
    severity: 'critical',
    description: '/etc/shadow access',
  },
  ssh_directory: {
    pattern: /~\/\.ssh\//gi,
    category: 'secrets',
    severity: 'high',
    description: '~/.ssh/ access',
  },
  aws_metadata: {
    pattern: /169\.254\.169\.254/g,
    category: 'secrets',
    severity: 'critical',
    description: 'AWS metadata endpoint',
  },
};

function getSeverityLevel(severity: Severity): number {
  const levels: Record<Severity, number> = {
    info: 0,
    warning: 1,
    high: 2,
    critical: 3,
  };
  return levels[severity] ?? 0;
}

export class CommandFirewall implements DetectionEngine {
  name = 'command_firewall';

  check(
    content: string,
    _context: DetectionContext,
    config: DetectionConfig,
  ): DetectionResult {
    if (!config.enabled || !content) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: {},
      };
    }

    const blockedPatterns = (config.blockedPatterns as string[] | undefined) || [];
    // Note: categories config is available for filtering but all patterns are checked by default

    const matches: CommandMatch[] = [];
    let highestSeverity: Severity = 'info';

    for (const [patternName, patternConfig] of Object.entries(COMMAND_PATTERNS)) {
      // Skip if pattern is not in blocked patterns (if specified)
      if (blockedPatterns.length > 0 && !blockedPatterns.includes(patternName)) {
        continue;
      }

      // Reset regex lastIndex
      patternConfig.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = patternConfig.pattern.exec(content)) !== null) {
        const matchedText = match[0];

        // Get snippet around match
        const start = Math.max(0, match.index - 20);
        const end = Math.min(content.length, match.index + matchedText.length + 20);
        const snippet = content.slice(start, end).trim();

        matches.push({
          patternName,
          matchedText,
          start: match.index,
          end: match.index + matchedText.length,
          confidence: 0.9,
          commandCategory: patternConfig.category,
          severity: patternConfig.severity,
          description: patternConfig.description,
          category: patternConfig.category,
          redacted: snippet.slice(0, 100),
        });

        if (getSeverityLevel(patternConfig.severity) > getSeverityLevel(highestSeverity)) {
          highestSeverity = patternConfig.severity;
        }
      }
    }

    const triggered = matches.length > 0;

    // Only block for HIGH and CRITICAL severity
    const shouldBlock = triggered && (highestSeverity === 'high' || highestSeverity === 'critical');

    // Group by category
    const categoriesTriggered = [...new Set(matches.map((m) => m.commandCategory))];

    return {
      engine: this.name,
      triggered,
      blocked: shouldBlock,
      severity: highestSeverity,
      confidence: triggered ? 0.9 : 0,
      details: {
        matches: matches.map((m) => ({
          category: m.commandCategory,
          pattern: m.patternName,
          snippet: m.redacted,
          severity: m.severity,
          description: m.description,
        })),
        matchCount: matches.length,
        categoriesTriggered,
        highestSeverity,
      },
      message: triggered
        ? `Detected ${matches.length} dangerous pattern(s) across ${categoriesTriggered.length} category(ies)`
        : undefined,
    };
  }
}

export const commandFirewall = new CommandFirewall();
