/**
 * SQLite Evidence Store
 *
 * Provides persistent storage for traces, agent DNA, participation data,
 * and attestations with SHA-256 hash chain integrity.
 */

import Database from 'better-sqlite3';
import { mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { nanoid } from 'nanoid';
import type {
  Trace,
  TraceInput,
  TraceFilter,
  AgentDNA,
  AgentDNAStrands,
  Participation,
  Attestation,
  AttestationInput,
  ChainAnchor,
  ChainVerificationResult,
  ChainStats,
} from '../types/evidence.js';
import { computeTraceHash, GENESIS_HASH } from './hash-chain.js';
import { enqueueForSync } from '../cloud/sync.js';

// Schema SQL
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS traces (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    agent_id TEXT,
    session_id TEXT,
    action_type TEXT,
    tool_name TEXT,
    request_summary TEXT,
    response_summary TEXT,
    blocked INTEGER DEFAULT 0,
    simulated INTEGER DEFAULT 0,
    cached INTEGER DEFAULT 0,
    original_trace TEXT,
    detection_results TEXT,
    policies_checked TEXT,
    risk_weight REAL,
    prev_hash TEXT NOT NULL,
    audit_hash TEXT NOT NULL,
    timestamp TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS agent_dna (
    agent_id TEXT NOT NULL,
    computed_at TEXT NOT NULL,
    strand_data TEXT,
    trace_count INTEGER,
    PRIMARY KEY (agent_id, computed_at)
);

CREATE TABLE IF NOT EXISTS participation (
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    governance_calls INTEGER DEFAULT 0,
    risk_boundary_actions INTEGER DEFAULT 0,
    weighted_score REAL DEFAULT 0,
    computed_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (agent_id, session_id)
);

CREATE TABLE IF NOT EXISTS attestations (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    window_start TEXT,
    window_end TEXT,
    claims TEXT,
    evidence_root TEXT,
    signed INTEGER DEFAULT 0,
    signature TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chain_anchors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_trace_id TEXT NOT NULL,
    last_trace_id TEXT NOT NULL,
    trace_count INTEGER NOT NULL,
    root_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_traces_agent ON traces(agent_id);
CREATE INDEX IF NOT EXISTS idx_traces_session ON traces(session_id);
CREATE INDEX IF NOT EXISTS idx_traces_timestamp ON traces(timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_source ON traces(source);
CREATE INDEX IF NOT EXISTS idx_agent_dna_agent ON agent_dna(agent_id);
CREATE INDEX IF NOT EXISTS idx_attestations_agent ON attestations(agent_id);
`;

export class EvidenceStore {
  private db: Database.Database | null = null;
  private dbPath: string;
  private initialized: boolean = false;

  constructor(dbPath: string = '.trustscope/evidence.db') {
    // Resolve to absolute path
    this.dbPath = resolve(process.cwd(), dbPath);
  }

  /**
   * Initialize the evidence store, creating tables if needed
   */
  init(): void {
    if (this.initialized && this.db) {
      return;
    }

    // Create directory if it doesn't exist
    const dir = dirname(this.dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    // Open database with WAL mode for better concurrent reads
    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');

    // Create schema
    this.db.exec(SCHEMA_SQL);

    this.initialized = true;
  }

  /**
   * Ensure the database is initialized
   */
  private ensureInit(): Database.Database {
    if (!this.db) {
      this.init();
    }
    return this.db!;
  }

  /**
   * Generate a trace ID
   */
  private generateTraceId(): string {
    return `trc_${nanoid(12)}`;
  }

  /**
   * Generate an attestation ID
   */
  private generateAttestationId(): string {
    return `att_${nanoid(12)}`;
  }

  /**
   * Insert a new trace and compute its hash
   */
  insertTrace(input: TraceInput): Trace {
    const db = this.ensureInit();
    const now = new Date().toISOString();

    // Get the previous hash
    const lastTrace = db.prepare(
      'SELECT audit_hash FROM traces ORDER BY rowid DESC LIMIT 1'
    ).get() as { audit_hash: string } | undefined;
    const prevHash = lastTrace?.audit_hash || GENESIS_HASH;

    // Generate ID and prepare trace
    const id = this.generateTraceId();
    const trace: Trace = {
      id,
      source: input.source,
      agent_id: input.agent_id || null,
      session_id: input.session_id || null,
      action_type: input.action_type || null,
      tool_name: input.tool_name || null,
      request_summary: input.request_summary || null,
      response_summary: input.response_summary || null,
      blocked: input.blocked || false,
      simulated: input.simulated || false,
      cached: input.cached || false,
      original_trace: input.original_trace || null,
      detection_results: input.detection_results || null,
      policies_checked: input.policies_checked || null,
      risk_weight: input.risk_weight || null,
      prev_hash: prevHash,
      audit_hash: '', // Will be computed
      timestamp: now,
    };

    // Compute the hash
    trace.audit_hash = computeTraceHash({
      id: trace.id,
      source: trace.source,
      agent_id: trace.agent_id,
      action_type: trace.action_type,
      request_summary: trace.request_summary,
      response_summary: trace.response_summary,
      timestamp: trace.timestamp,
      prev_hash: trace.prev_hash,
    });

    // Insert into database
    const stmt = db.prepare(`
      INSERT INTO traces (
        id, source, agent_id, session_id, action_type, tool_name,
        request_summary, response_summary, blocked, simulated, cached,
        original_trace, detection_results, policies_checked, risk_weight,
        prev_hash, audit_hash, timestamp
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?
      )
    `);

    stmt.run(
      trace.id,
      trace.source,
      trace.agent_id,
      trace.session_id,
      trace.action_type,
      trace.tool_name,
      trace.request_summary,
      trace.response_summary,
      trace.blocked ? 1 : 0,
      trace.simulated ? 1 : 0,
      trace.cached ? 1 : 0,
      trace.original_trace,
      trace.detection_results ? JSON.stringify(trace.detection_results) : null,
      trace.policies_checked ? JSON.stringify(trace.policies_checked) : null,
      trace.risk_weight,
      trace.prev_hash,
      trace.audit_hash,
      trace.timestamp
    );

    // Sprint 3: Queue trace for cloud sync (fire and forget)
    try {
      enqueueForSync(trace as unknown as Record<string, unknown>);
    } catch {
      // Silently fail - local storage is primary, cloud is secondary
    }

    return trace;
  }

  /**
   * Get a trace by ID
   */
  getTrace(id: string): Trace | null {
    const db = this.ensureInit();
    const row = db.prepare('SELECT * FROM traces WHERE id = ?').get(id) as DbTraceRow | undefined;
    return row ? this.rowToTrace(row) : null;
  }

  /**
   * List traces with optional filters
   */
  listTraces(filter?: TraceFilter): Trace[] {
    const db = this.ensureInit();

    let sql = 'SELECT * FROM traces WHERE 1=1';
    const params: (string | number)[] = [];

    if (filter?.agent_id) {
      sql += ' AND agent_id = ?';
      params.push(filter.agent_id);
    }

    if (filter?.session_id) {
      sql += ' AND session_id = ?';
      params.push(filter.session_id);
    }

    if (filter?.source) {
      sql += ' AND source = ?';
      params.push(filter.source);
    }

    sql += ' ORDER BY rowid ASC';

    if (filter?.limit) {
      sql += ' LIMIT ?';
      params.push(filter.limit);
    }

    if (filter?.offset) {
      sql += ' OFFSET ?';
      params.push(filter.offset);
    }

    const rows = db.prepare(sql).all(...params) as DbTraceRow[];
    return rows.map((row) => this.rowToTrace(row));
  }

  /**
   * Get total trace count
   */
  getTraceCount(): number {
    const db = this.ensureInit();
    const row = db.prepare('SELECT COUNT(*) as count FROM traces').get() as { count: number };
    return row.count;
  }

  /**
   * Get the hash of the last trace
   */
  getLastHash(): string | null {
    const db = this.ensureInit();
    const row = db.prepare(
      'SELECT audit_hash FROM traces ORDER BY rowid DESC LIMIT 1'
    ).get() as { audit_hash: string } | undefined;
    return row?.audit_hash || null;
  }

  /**
   * Get length of the hash chain
   */
  getChainLength(): number {
    return this.getTraceCount();
  }

  /**
   * Verify the entire hash chain
   */
  verifyChain(): ChainVerificationResult {
    const db = this.ensureInit();
    const traces = db.prepare('SELECT * FROM traces ORDER BY rowid ASC').all() as DbTraceRow[];

    if (traces.length === 0) {
      return { valid: true, checked: 0 };
    }

    let prevHash = GENESIS_HASH;

    for (let i = 0; i < traces.length; i++) {
      const trace = this.rowToTrace(traces[i]);

      // Check prev_hash links correctly
      if (trace.prev_hash !== prevHash) {
        return {
          valid: false,
          checked: i,
          broken_at: trace.id,
          expected_hash: prevHash,
          actual_hash: trace.prev_hash,
        };
      }

      // Check audit_hash is correct
      const expectedHash = computeTraceHash({
        id: trace.id,
        source: trace.source,
        agent_id: trace.agent_id,
        action_type: trace.action_type,
        request_summary: trace.request_summary,
        response_summary: trace.response_summary,
        timestamp: trace.timestamp,
        prev_hash: trace.prev_hash,
      });

      if (expectedHash !== trace.audit_hash) {
        return {
          valid: false,
          checked: i,
          broken_at: trace.id,
          expected_hash: expectedHash,
          actual_hash: trace.audit_hash,
        };
      }

      prevHash = trace.audit_hash;
    }

    return { valid: true, checked: traces.length };
  }

  /**
   * Upsert agent DNA
   */
  upsertDNA(agentId: string, strandData: AgentDNAStrands, traceCount: number): void {
    const db = this.ensureInit();
    const now = new Date().toISOString();

    const stmt = db.prepare(`
      INSERT INTO agent_dna (agent_id, computed_at, strand_data, trace_count)
      VALUES (?, ?, ?, ?)
    `);

    stmt.run(agentId, now, JSON.stringify(strandData), traceCount);
  }

  /**
   * Get latest agent DNA
   */
  getDNA(agentId: string): AgentDNA | null {
    const db = this.ensureInit();
    const row = db.prepare(`
      SELECT * FROM agent_dna WHERE agent_id = ? ORDER BY computed_at DESC LIMIT 1
    `).get(agentId) as DbAgentDNARow | undefined;

    if (!row) return null;

    return {
      agent_id: row.agent_id,
      computed_at: row.computed_at,
      strand_data: JSON.parse(row.strand_data || '{}'),
      trace_count: row.trace_count,
    };
  }

  /**
   * Get agent DNA history
   */
  getDNAHistory(agentId: string): AgentDNA[] {
    const db = this.ensureInit();
    const rows = db.prepare(`
      SELECT * FROM agent_dna WHERE agent_id = ? ORDER BY computed_at DESC
    `).all(agentId) as DbAgentDNARow[];

    return rows.map((row) => ({
      agent_id: row.agent_id,
      computed_at: row.computed_at,
      strand_data: JSON.parse(row.strand_data || '{}'),
      trace_count: row.trace_count,
    }));
  }

  /**
   * Update participation metrics
   */
  updateParticipation(
    agentId: string,
    sessionId: string,
    governanceCall: boolean,
    riskWeight: number
  ): void {
    const db = this.ensureInit();
    const now = new Date().toISOString();

    // Try to update existing record
    const existing = db.prepare(`
      SELECT * FROM participation WHERE agent_id = ? AND session_id = ?
    `).get(agentId, sessionId) as DbParticipationRow | undefined;

    if (existing) {
      const stmt = db.prepare(`
        UPDATE participation
        SET governance_calls = governance_calls + ?,
            risk_boundary_actions = risk_boundary_actions + ?,
            weighted_score = weighted_score + ?,
            computed_at = ?
        WHERE agent_id = ? AND session_id = ?
      `);
      stmt.run(
        governanceCall ? 1 : 0,
        riskWeight > 0.5 ? 1 : 0,
        riskWeight,
        now,
        agentId,
        sessionId
      );
    } else {
      const stmt = db.prepare(`
        INSERT INTO participation (agent_id, session_id, governance_calls, risk_boundary_actions, weighted_score, computed_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        agentId,
        sessionId,
        governanceCall ? 1 : 0,
        riskWeight > 0.5 ? 1 : 0,
        riskWeight,
        now
      );
    }
  }

  /**
   * Get participation data
   */
  getParticipation(agentId: string, sessionId?: string): Participation | null {
    const db = this.ensureInit();

    let row: DbParticipationRow | undefined;

    if (sessionId) {
      row = db.prepare(`
        SELECT * FROM participation WHERE agent_id = ? AND session_id = ?
      `).get(agentId, sessionId) as DbParticipationRow | undefined;
    } else {
      // Aggregate across all sessions
      row = db.prepare(`
        SELECT
          agent_id,
          'all' as session_id,
          SUM(governance_calls) as governance_calls,
          SUM(risk_boundary_actions) as risk_boundary_actions,
          SUM(weighted_score) as weighted_score,
          MAX(computed_at) as computed_at
        FROM participation
        WHERE agent_id = ?
        GROUP BY agent_id
      `).get(agentId) as DbParticipationRow | undefined;
    }

    if (!row) return null;

    return {
      agent_id: row.agent_id,
      session_id: row.session_id,
      governance_calls: row.governance_calls,
      risk_boundary_actions: row.risk_boundary_actions,
      weighted_score: row.weighted_score,
      computed_at: row.computed_at,
    };
  }

  /**
   * Compute participation score using risk-weighted formula
   * Score = Σ(governed_actions × risk_weight) / Σ(all_risk_actions × risk_weight) × 100
   */
  computeParticipationScore(
    agentId: string,
    sessionId?: string,
  ): { score: number; level: 'critical' | 'low' | 'medium' | 'high'; details: Participation | null } {
    const participation = this.getParticipation(agentId, sessionId);

    if (!participation) {
      return {
        score: 100, // No data = fully governed (or no actions)
        level: 'high',
        details: null,
      };
    }

    // Calculate weighted score
    // governance_calls represents governed actions
    // weighted_score tracks total risk weight accumulated
    const totalRiskWeight = participation.weighted_score || 0;
    const governanceRatio = participation.governance_calls > 0 && totalRiskWeight > 0
      ? Math.min(1, (participation.governance_calls * 0.5) / totalRiskWeight)
      : participation.governance_calls > 0 ? 1 : 0;

    const score = Math.round(governanceRatio * 100);

    // Determine level
    let level: 'critical' | 'low' | 'medium' | 'high';
    if (score >= 80) {
      level = 'high';
    } else if (score >= 50) {
      level = 'medium';
    } else if (score >= 20) {
      level = 'low';
    } else {
      level = 'critical';
    }

    return { score, level, details: participation };
  }

  /**
   * Insert an attestation
   */
  insertAttestation(input: AttestationInput): string {
    const db = this.ensureInit();
    const id = this.generateAttestationId();
    const now = new Date().toISOString();

    const stmt = db.prepare(`
      INSERT INTO attestations (id, agent_id, window_start, window_end, claims, evidence_root, signed, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?)
    `);

    stmt.run(
      id,
      input.agent_id,
      input.window_start,
      input.window_end,
      JSON.stringify(input.claims),
      input.evidence_root,
      now
    );

    return id;
  }

  /**
   * Get an attestation by ID
   */
  getAttestation(id: string): Attestation | null {
    const db = this.ensureInit();
    const row = db.prepare('SELECT * FROM attestations WHERE id = ?').get(id) as DbAttestationRow | undefined;

    if (!row) return null;

    return {
      id: row.id,
      agent_id: row.agent_id,
      window_start: row.window_start,
      window_end: row.window_end,
      claims: JSON.parse(row.claims || '{}'),
      evidence_root: row.evidence_root,
      signed: row.signed === 1,
      signature: row.signature,
      created_at: row.created_at,
    };
  }

  /**
   * Insert a chain anchor
   */
  insertAnchor(anchor: Omit<ChainAnchor, 'id' | 'created_at'>): number {
    const db = this.ensureInit();

    const stmt = db.prepare(`
      INSERT INTO chain_anchors (first_trace_id, last_trace_id, trace_count, root_hash)
      VALUES (?, ?, ?, ?)
    `);

    const result = stmt.run(
      anchor.first_trace_id,
      anchor.last_trace_id,
      anchor.trace_count,
      anchor.root_hash
    );

    return Number(result.lastInsertRowid);
  }

  /**
   * Get the latest chain anchor
   */
  getLatestAnchor(): ChainAnchor | null {
    const db = this.ensureInit();
    const row = db.prepare(`
      SELECT * FROM chain_anchors ORDER BY id DESC LIMIT 1
    `).get() as DbChainAnchorRow | undefined;

    if (!row) return null;

    return {
      id: row.id,
      first_trace_id: row.first_trace_id,
      last_trace_id: row.last_trace_id,
      trace_count: row.trace_count,
      root_hash: row.root_hash,
      created_at: row.created_at,
    };
  }

  /**
   * Get chain statistics
   */
  getChainStats(): ChainStats {
    const db = this.ensureInit();

    const countRow = db.prepare('SELECT COUNT(*) as count FROM traces').get() as { count: number };
    const firstRow = db.prepare('SELECT id, audit_hash FROM traces ORDER BY rowid ASC LIMIT 1').get() as
      | { id: string; audit_hash: string }
      | undefined;
    const lastRow = db.prepare('SELECT id, audit_hash FROM traces ORDER BY rowid DESC LIMIT 1').get() as
      | { id: string; audit_hash: string }
      | undefined;

    // Quick verification: check last 10 traces
    const verification = this.verifyChainQuick(10);

    return {
      total_traces: countRow.count,
      latest_hash: lastRow?.audit_hash || null,
      first_trace_id: firstRow?.id || null,
      last_trace_id: lastRow?.id || null,
      is_valid: verification.valid,
    };
  }

  /**
   * Quick chain verification (check last N traces)
   */
  private verifyChainQuick(n: number): ChainVerificationResult {
    const db = this.ensureInit();
    const traces = db.prepare(`
      SELECT * FROM traces ORDER BY rowid DESC LIMIT ?
    `).all(n) as DbTraceRow[];

    if (traces.length === 0) {
      return { valid: true, checked: 0 };
    }

    // Reverse to get chronological order
    traces.reverse();

    for (let i = 1; i < traces.length; i++) {
      const prevTrace = this.rowToTrace(traces[i - 1]);
      const trace = this.rowToTrace(traces[i]);

      // Check prev_hash links correctly
      if (trace.prev_hash !== prevTrace.audit_hash) {
        return {
          valid: false,
          checked: i,
          broken_at: trace.id,
          expected_hash: prevTrace.audit_hash,
          actual_hash: trace.prev_hash,
        };
      }
    }

    return { valid: true, checked: traces.length };
  }

  /**
   * List all unique agent IDs
   */
  listAgents(): Array<{ agent_id: string; trace_count: number }> {
    const db = this.ensureInit();
    const rows = db.prepare(`
      SELECT agent_id, COUNT(*) as trace_count
      FROM traces
      WHERE agent_id IS NOT NULL
      GROUP BY agent_id
      ORDER BY trace_count DESC
    `).all() as Array<{ agent_id: string; trace_count: number }>;

    return rows;
  }

  /**
   * Close the database connection
   */
  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
      this.initialized = false;
    }
  }

  /**
   * Check if database exists
   */
  exists(): boolean {
    return existsSync(this.dbPath);
  }

  /**
   * Get database path
   */
  getPath(): string {
    return this.dbPath;
  }

  // ============================================
  // Sprint 3: Enhanced attestation claim helpers
  // ============================================

  /**
   * Get count of governed traces (from MCP or gateway)
   */
  getGovernedTraceCount(): number {
    const db = this.ensureInit();
    const result = db.prepare(
      "SELECT COUNT(*) as count FROM traces WHERE source IN ('mcp', 'gateway')"
    ).get() as { count: number };
    return result.count;
  }

  /**
   * Get count of policy checks performed
   */
  getPolicyCheckCount(): number {
    const db = this.ensureInit();
    const result = db.prepare(
      "SELECT COUNT(*) as count FROM traces WHERE action_type = 'policy_check'"
    ).get() as { count: number };
    return result.count;
  }

  /**
   * Get count of policy violations (blocked traces)
   */
  getPolicyViolationCount(): number {
    const db = this.ensureInit();
    const result = db.prepare(
      'SELECT COUNT(*) as count FROM traces WHERE blocked = 1'
    ).get() as { count: number };
    return result.count;
  }

  /**
   * Get count of traces that triggered detection engines
   */
  getDetectionTriggerCount(): number {
    const db = this.ensureInit();
    const result = db.prepare(
      "SELECT COUNT(*) as count FROM traces WHERE detection_results IS NOT NULL AND detection_results != '[]' AND detection_results != 'null'"
    ).get() as { count: number };
    return result.count;
  }

  /**
   * Check if initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Convert database row to Trace object
   */
  private rowToTrace(row: DbTraceRow): Trace {
    return {
      id: row.id,
      source: row.source as Trace['source'],
      agent_id: row.agent_id,
      session_id: row.session_id,
      action_type: row.action_type,
      tool_name: row.tool_name,
      request_summary: row.request_summary,
      response_summary: row.response_summary,
      blocked: row.blocked === 1,
      simulated: row.simulated === 1,
      cached: row.cached === 1,
      original_trace: row.original_trace,
      detection_results: row.detection_results ? JSON.parse(row.detection_results) : null,
      policies_checked: row.policies_checked ? JSON.parse(row.policies_checked) : null,
      risk_weight: row.risk_weight,
      prev_hash: row.prev_hash,
      audit_hash: row.audit_hash,
      timestamp: row.timestamp,
    };
  }
}

// Database row types
interface DbTraceRow {
  id: string;
  source: string;
  agent_id: string | null;
  session_id: string | null;
  action_type: string | null;
  tool_name: string | null;
  request_summary: string | null;
  response_summary: string | null;
  blocked: number;
  simulated: number;
  cached: number;
  original_trace: string | null;
  detection_results: string | null;
  policies_checked: string | null;
  risk_weight: number | null;
  prev_hash: string;
  audit_hash: string;
  timestamp: string;
}

interface DbAgentDNARow {
  agent_id: string;
  computed_at: string;
  strand_data: string | null;
  trace_count: number;
}

interface DbParticipationRow {
  agent_id: string;
  session_id: string;
  governance_calls: number;
  risk_boundary_actions: number;
  weighted_score: number;
  computed_at: string;
}

interface DbAttestationRow {
  id: string;
  agent_id: string;
  window_start: string;
  window_end: string;
  claims: string | null;
  evidence_root: string;
  signed: number;
  signature: string | null;
  created_at: string;
}

interface DbChainAnchorRow {
  id: number;
  first_trace_id: string;
  last_trace_id: string;
  trace_count: number;
  root_hash: string;
  created_at: string;
}

// Singleton instance
let storeInstance: EvidenceStore | null = null;

/**
 * Get or create the evidence store instance
 */
export function getEvidenceStore(dbPath?: string): EvidenceStore {
  if (!storeInstance) {
    storeInstance = new EvidenceStore(dbPath);
  }
  return storeInstance;
}

/**
 * Create a new evidence store instance (for testing)
 */
export function createEvidenceStore(dbPath?: string): EvidenceStore {
  return new EvidenceStore(dbPath);
}

/**
 * Reset the singleton instance (for testing)
 */
export function resetEvidenceStore(): void {
  if (storeInstance) {
    storeInstance.close();
    storeInstance = null;
  }
}
