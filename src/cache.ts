import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync, readdirSync, renameSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, basename } from 'node:path';
import { createHash } from 'node:crypto';
import type { CacheData, CacheEntry, RepoScanResult } from './types.js';

const CACHE_VERSION = '1.0.0';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_CACHE_ENTRIES = 1000; // Prevent unbounded cache growth
const MAX_ORG_NAME_LENGTH = 256; // Reasonable limit for org names

function getCacheDir(): string {
  const cacheDir = join(homedir(), '.trustscope', 'cache');
  if (!existsSync(cacheDir)) {
    mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
  }
  return cacheDir;
}

/**
 * Generate a safe cache file path using a hash of the org name.
 * This prevents path traversal attacks and handles any characters in org names.
 */
function getCacheFilePath(org: string): string {
  // Validate and sanitize input
  if (!org || typeof org !== 'string') {
    throw new Error('Invalid organization name');
  }

  if (org.length > MAX_ORG_NAME_LENGTH) {
    throw new Error(`Organization name too long (max ${MAX_ORG_NAME_LENGTH} characters)`);
  }

  // Use hash-based naming for security (prevents path traversal)
  const hash = createHash('sha256').update(org.toLowerCase()).digest('hex').slice(0, 16);
  const safeName = `org_${hash}.json`;

  // Double-check the filename is safe
  const fileName = basename(safeName);
  if (fileName !== safeName || fileName.includes('..')) {
    throw new Error('Invalid cache file name generated');
  }

  return join(getCacheDir(), fileName);
}

function loadCache(org: string): CacheData {
  let filePath: string;
  try {
    filePath = getCacheFilePath(org);
  } catch {
    return { version: CACHE_VERSION, entries: {} };
  }

  if (!existsSync(filePath)) {
    return { version: CACHE_VERSION, entries: {} };
  }

  try {
    const content = readFileSync(filePath, 'utf-8');

    // Limit content size to prevent DoS via large cache files
    const MAX_CACHE_FILE_SIZE = 50 * 1024 * 1024; // 50MB
    if (content.length > MAX_CACHE_FILE_SIZE) {
      console.warn(`Cache file too large, resetting: ${filePath}`);
      return { version: CACHE_VERSION, entries: {} };
    }

    const data = JSON.parse(content) as CacheData;

    // Validate structure
    if (!data || typeof data !== 'object') {
      return { version: CACHE_VERSION, entries: {} };
    }

    // Check version compatibility
    if (data.version !== CACHE_VERSION) {
      return { version: CACHE_VERSION, entries: {} };
    }

    // Validate entries is an object
    if (!data.entries || typeof data.entries !== 'object' || Array.isArray(data.entries)) {
      return { version: CACHE_VERSION, entries: {} };
    }

    // Limit number of entries to prevent memory issues
    const entryCount = Object.keys(data.entries).length;
    if (entryCount > MAX_CACHE_ENTRIES) {
      console.warn(`Cache has too many entries (${entryCount}), pruning old entries`);
      const entries = Object.entries(data.entries)
        .sort(([, a], [, b]) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, MAX_CACHE_ENTRIES);
      data.entries = Object.fromEntries(entries);
    }

    return data;
  } catch (error) {
    // Log error but don't expose details
    console.warn('Failed to load cache, starting fresh');
    return { version: CACHE_VERSION, entries: {} };
  }
}

function saveCache(org: string, data: CacheData): void {
  let filePath: string;
  try {
    filePath = getCacheFilePath(org);
  } catch (error) {
    console.warn('Failed to generate cache file path:', error instanceof Error ? error.message : 'unknown error');
    return;
  }

  try {
    // Prune old entries before saving
    const entries = Object.entries(data.entries)
      .sort(([, a], [, b]) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, MAX_CACHE_ENTRIES);
    const prunedData: CacheData = {
      version: data.version,
      entries: Object.fromEntries(entries),
    };

    const content = JSON.stringify(prunedData, null, 2);

    // Atomic write: write to temp file first, then rename
    // This prevents corruption if two processes write simultaneously
    const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    writeFileSync(tempPath, content, { mode: 0o600 });
    renameSync(tempPath, filePath);
  } catch (error) {
    console.warn('Failed to save cache:', error instanceof Error ? error.message : 'unknown error');
  }
}

export function getCachedResult(
  org: string,
  repo: string,
  repoUpdatedAt: string
): RepoScanResult | null {
  const cache = loadCache(org);
  const entry = cache.entries[repo];

  if (!entry) {
    return null;
  }

  // Check if cache is expired (24 hours)
  const cacheAge = Date.now() - new Date(entry.timestamp).getTime();
  if (cacheAge > CACHE_TTL_MS) {
    return null;
  }

  // Check if repo has been updated since cache
  if (entry.repoUpdatedAt !== repoUpdatedAt) {
    return null;
  }

  return entry.result;
}

export function setCachedResult(
  org: string,
  repo: string,
  repoUpdatedAt: string,
  result: RepoScanResult
): void {
  const cache = loadCache(org);

  const entry: CacheEntry = {
    timestamp: new Date().toISOString(),
    repoUpdatedAt,
    result,
  };

  cache.entries[repo] = entry;
  saveCache(org, cache);
}

export function clearCache(org?: string): void {
  if (org) {
    try {
      const filePath = getCacheFilePath(org);
      if (existsSync(filePath)) {
        unlinkSync(filePath);
      }
    } catch (error) {
      console.warn('Failed to clear cache for org:', error instanceof Error ? error.message : 'unknown error');
    }
  } else {
    // Clear all caches
    try {
      const cacheDir = getCacheDir();
      const files = readdirSync(cacheDir);
      for (const file of files) {
        // Only delete JSON files that match our naming pattern
        if (file.endsWith('.json') && file.startsWith('org_')) {
          const filePath = join(cacheDir, basename(file));
          try {
            unlinkSync(filePath);
          } catch {
            // Continue with other files
          }
        }
      }
    } catch (error) {
      console.warn('Failed to clear cache:', error instanceof Error ? error.message : 'unknown error');
    }
  }
}

export function getCacheStats(org: string): { entries: number; oldestEntry: string | null } {
  const cache = loadCache(org);
  const entries = Object.keys(cache.entries).length;

  let oldestEntry: string | null = null;
  let oldestTime = Infinity;

  for (const entry of Object.values(cache.entries)) {
    const time = new Date(entry.timestamp).getTime();
    if (time < oldestTime) {
      oldestTime = time;
      oldestEntry = entry.timestamp;
    }
  }

  return { entries, oldestEntry };
}
