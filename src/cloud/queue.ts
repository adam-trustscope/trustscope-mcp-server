/**
 * TrustScope Sync Queue
 *
 * SQLite-backed persistent queue for cloud trace sync.
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const TRUSTSCOPE_DIR = join(homedir(), '.trustscope');
const QUEUE_DB_PATH = join(TRUSTSCOPE_DIR, 'sync_queue.db');

export interface QueuedTrace {
  id: number;
  trace_json: string;
  created_at: string;
  retry_count: number;
  failed_at: string | null;
}

export class TraceQueue {
  private db: Database.Database;

  constructor(dbPath?: string) {
    // Ensure directory exists
    if (!existsSync(TRUSTSCOPE_DIR)) {
      mkdirSync(TRUSTSCOPE_DIR, { recursive: true });
    }

    this.db = new Database(dbPath || QUEUE_DB_PATH);
    this.init();
  }

  private init(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sync_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_json TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        failed_at TEXT,
        retry_count INTEGER DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_sync_queue_failed ON sync_queue(failed_at);
    `);
  }

  /**
   * Add a trace to the queue
   */
  add(trace: Record<string, unknown>): void {
    const stmt = this.db.prepare('INSERT INTO sync_queue (trace_json) VALUES (?)');
    stmt.run(JSON.stringify(trace));
  }

  /**
   * Get traces ready for sync (not failed)
   */
  peek(limit: number): Array<{ id: number; trace: Record<string, unknown> }> {
    const stmt = this.db.prepare(`
      SELECT id, trace_json
      FROM sync_queue
      WHERE failed_at IS NULL
      ORDER BY id
      LIMIT ?
    `);
    const rows = stmt.all(limit) as Array<{ id: number; trace_json: string }>;
    return rows.map(r => ({
      id: r.id,
      trace: JSON.parse(r.trace_json) as Record<string, unknown>,
    }));
  }

  /**
   * Remove successfully synced traces
   */
  remove(ids: number[]): void {
    if (ids.length === 0) return;
    const placeholders = ids.map(() => '?').join(',');
    const stmt = this.db.prepare(`DELETE FROM sync_queue WHERE id IN (${placeholders})`);
    stmt.run(...ids);
  }

  /**
   * Mark traces as failed (for retry later)
   */
  markFailed(ids: number[]): void {
    if (ids.length === 0) return;
    const placeholders = ids.map(() => '?').join(',');
    const stmt = this.db.prepare(`
      UPDATE sync_queue
      SET failed_at = CURRENT_TIMESTAMP, retry_count = retry_count + 1
      WHERE id IN (${placeholders})
    `);
    stmt.run(...ids);
  }

  /**
   * Reset failed traces for retry (after backoff period)
   */
  resetFailed(maxRetries: number = 5): void {
    const stmt = this.db.prepare(`
      UPDATE sync_queue
      SET failed_at = NULL
      WHERE failed_at IS NOT NULL
        AND retry_count < ?
        AND datetime(failed_at, '+' || (retry_count * retry_count) || ' minutes') < datetime('now')
    `);
    stmt.run(maxRetries);
  }

  /**
   * Get queue size (pending traces)
   */
  size(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM sync_queue WHERE failed_at IS NULL');
    const result = stmt.get() as { count: number };
    return result.count;
  }

  /**
   * Get total queue size including failed
   */
  totalSize(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM sync_queue');
    const result = stmt.get() as { count: number };
    return result.count;
  }

  /**
   * Get failed trace count
   */
  failedCount(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM sync_queue WHERE failed_at IS NOT NULL');
    const result = stmt.get() as { count: number };
    return result.count;
  }

  /**
   * Clear all queued traces
   */
  clear(): void {
    this.db.exec('DELETE FROM sync_queue');
  }

  /**
   * Close the database connection
   */
  close(): void {
    this.db.close();
  }
}
