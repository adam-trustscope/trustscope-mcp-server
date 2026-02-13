import { defineConfig } from 'tsup';

export default defineConfig([
  // CLI entry points with shebang
  {
    entry: {
      index: 'src/index.ts',
      'mcp-entry': 'src/mcp-entry.ts',
    },
    format: ['esm'],
    dts: true,
    sourcemap: true,
    clean: true,
    splitting: false,
    shims: true,
    banner: {
      js: '#!/usr/bin/env node',
    },
    external: ['better-sqlite3'],
  },
  // Library entry points without shebang
  {
    entry: {
      'evidence/index': 'src/evidence/index.ts',
      'detection/index': 'src/detection/index.ts',
      'policy/index': 'src/policy/index.ts',
    },
    format: ['cjs', 'esm'],
    dts: true,
    sourcemap: true,
    clean: false, // Don't clean since we already cleaned in first config
    splitting: false,
    shims: true,
    external: ['better-sqlite3'],
  },
]);
