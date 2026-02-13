/**
 * Policy Evaluation Cache
 *
 * LRU cache with TTL for policy evaluation results.
 * Caches deterministic pattern-based evaluations to reduce redundant computation.
 */

import { createHash } from 'node:crypto';
import type { PolicyEvaluationResultSet, PolicyEvaluationInput } from './types.js';

interface CacheEntry<T> {
  value: T;
  createdAt: number;
  hits: number;
}

export interface PolicyCacheConfig {
  /** Maximum number of entries (default: 100) */
  maxEntries?: number;
  /** TTL in milliseconds (default: 300000 = 5 minutes) */
  ttlMs?: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  entries: number;
  hitRate: number;
}

/**
 * LRU Cache with TTL for policy evaluation results
 */
export class PolicyCache<T = PolicyEvaluationResultSet> {
  private cache: Map<string, CacheEntry<T>>;
  private maxEntries: number;
  private ttlMs: number;
  private policyVersion: string;
  private hits: number = 0;
  private misses: number = 0;

  constructor(policyVersion: string = '1.0.0', config: PolicyCacheConfig = {}) {
    this.cache = new Map();
    this.maxEntries = config.maxEntries ?? 100;
    this.ttlMs = config.ttlMs ?? 300_000; // 5 minutes default
    this.policyVersion = policyVersion;
  }

  /**
   * Generate a cache key from action type and input parameters
   * Uses SHA-256 hash of deterministic inputs
   */
  generateKey(actionType: string, input: PolicyEvaluationInput): string {
    const keyData = {
      actionType,
      policyVersion: this.policyVersion,
      content: input.content,
      context: input.context ? this.sortObject(input.context) : null,
    };

    const hash = createHash('sha256');
    hash.update(JSON.stringify(keyData));
    return hash.digest('hex').substring(0, 32); // Use first 32 chars for readability
  }

  /**
   * Sort object keys recursively for deterministic JSON stringification
   */
  private sortObject(obj: Record<string, unknown>): Record<string, unknown> {
    const sorted: Record<string, unknown> = {};
    const keys = Object.keys(obj).sort();
    for (const key of keys) {
      const value = obj[key];
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        sorted[key] = this.sortObject(value as Record<string, unknown>);
      } else {
        sorted[key] = value;
      }
    }
    return sorted;
  }

  /**
   * Get a value from the cache
   * Returns null if not found or expired
   */
  get(key: string): T | null {
    const entry = this.cache.get(key);

    if (!entry) {
      this.misses++;
      return null;
    }

    // Check TTL
    const now = Date.now();
    if (now - entry.createdAt > this.ttlMs) {
      this.cache.delete(key);
      this.misses++;
      return null;
    }

    // Update hits and move to end (most recently used)
    entry.hits++;
    this.cache.delete(key);
    this.cache.set(key, entry);
    this.hits++;

    return entry.value;
  }

  /**
   * Set a value in the cache
   * Evicts LRU entry if at capacity
   */
  set(key: string, value: T): void {
    // If key exists, delete it first (will be re-added at end)
    if (this.cache.has(key)) {
      this.cache.delete(key);
    }

    // Evict LRU entries if at capacity
    while (this.cache.size >= this.maxEntries) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }

    // Add new entry
    this.cache.set(key, {
      value,
      createdAt: Date.now(),
      hits: 0,
    });
  }

  /**
   * Check if a key exists and is not expired
   */
  has(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) return false;

    const now = Date.now();
    if (now - entry.createdAt > this.ttlMs) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Invalidate entire cache when policy version changes
   */
  invalidateOnPolicyChange(newVersion: string): void {
    if (newVersion !== this.policyVersion) {
      this.cache.clear();
      this.policyVersion = newVersion;
      this.hits = 0;
      this.misses = 0;
    }
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.cache.clear();
    this.hits = 0;
    this.misses = 0;
  }

  /**
   * Get current policy version
   */
  getPolicyVersion(): string {
    return this.policyVersion;
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const total = this.hits + this.misses;
    return {
      hits: this.hits,
      misses: this.misses,
      entries: this.cache.size,
      hitRate: total > 0 ? this.hits / total : 0,
    };
  }

  /**
   * Remove expired entries (manual cleanup)
   */
  prune(): number {
    const now = Date.now();
    let removed = 0;

    for (const [key, entry] of this.cache) {
      if (now - entry.createdAt > this.ttlMs) {
        this.cache.delete(key);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Get number of entries
   */
  get size(): number {
    return this.cache.size;
  }
}

/**
 * Create a new policy cache instance
 */
export function createPolicyCache(
  policyVersion?: string,
  config?: PolicyCacheConfig,
): PolicyCache {
  return new PolicyCache(policyVersion, config);
}
