/**
 * Local Tool Implementations
 *
 * Implements all 11 MCP tools using local SQLite storage and detection engines.
 * No network calls - everything runs offline.
 */

import { nanoid } from 'nanoid';
import { EvidenceStore } from '../../evidence/store.js';
import type { DetectionResultSet, PolicyCheckResult } from '../../types/evidence.js';
import { PolicyEngine, DEFAULT_POLICY_CONFIGS } from '../../policy/index.js';
import {
  runAllDetections,
  runPatternDetections,
  getEngineNames,
  type DetectionConfig,
  type SessionState,
} from '../../detection/index.js';
import { analyzeBehavior, type ExplainBehaviorResponse } from '../../analysis/index.js';
import { getLayer2Diagnosis, mergeDiagnoses, isLayer2Available } from '../../cloud/diagnosis.js';
import { signAttestation, hasSigningKeys, getOrCreateKeyPair } from '../../crypto/signing.js';
import {
  redactToolArgs,
  generateGuidance,
  estimateCost,
  type RedactionMatch,
} from './redaction.js';
import { detectEnforcementSync } from '../../enforcement/detector.js';
import type {
  CheckPolicyInput,
  CheckDetectionInput,
  LogActionInput,
  ListTracesInput,
  ListPoliciesInput,
  ListApprovalsInput,
  ApproveInput,
  GetAgentDNAInput,
  GetComplianceInput,
  ExplainBehaviorInput,
  GetAttestationInput,
} from '../types.js';

/**
 * Local tool executor
 */
export class LocalToolExecutor {
  private store: EvidenceStore;
  private policyEngine: PolicyEngine;
  private sessionStates: Map<string, SessionState>;

  constructor(store: EvidenceStore) {
    this.store = store;
    this.policyEngine = new PolicyEngine();
    this.sessionStates = new Map();
  }

  // Sprint 3: Tier definitions for upgrade triggers
  private static readonly TIER_LEVELS: Record<string, number> = {
    monitor: 1,
    protect: 2,
    protect_plus: 3,
    enterprise: 4,
  };

  private static readonly FEATURE_TIERS: Record<string, string> = {
    check_policy: 'monitor',
    check_detection: 'monitor',
    get_attestation: 'monitor',
    explain_behavior: 'protect',
    nl_diagnosis: 'protect_plus',
    signed_attestations: 'protect_plus',
    siem_integration: 'enterprise',
    custom_policies: 'enterprise',
  };

  /**
   * Get tier upgrade info if feature requires higher tier
   */
  private getTierUpgrade(feature: string, currentTier?: string): Record<string, unknown> | null {
    const requiredTier = LocalToolExecutor.FEATURE_TIERS[feature];
    if (!requiredTier) return null;

    const current = currentTier || 'monitor';
    const requiredLevel = LocalToolExecutor.TIER_LEVELS[requiredTier] || 1;
    const currentLevel = LocalToolExecutor.TIER_LEVELS[current] || 1;

    if (requiredLevel > currentLevel) {
      return {
        required_tier: requiredTier,
        current_tier: current,
        feature,
        upgrade_url: 'https://trustscope.ai/pricing',
        message: `${feature} requires ${requiredTier} tier. Upgrade at https://trustscope.ai/pricing`,
      };
    }

    return null;
  }

  /**
   * Get or create session state
   */
  private getSessionState(sessionId: string): SessionState {
    let state = this.sessionStates.get(sessionId);
    if (!state) {
      state = {
        requestHashes: [],
        recentActions: [],
        totalCost: 0,
        actionCount: 0,
        errorCount: 0,
        startTime: Date.now(),
        tokenCounts: [],
        contextSizes: [],
      };
      this.sessionStates.set(sessionId, state);
    }
    return state;
  }

  /**
   * Update session state after an action
   */
  private updateSessionState(sessionId: string, actionType: string): void {
    const state = this.getSessionState(sessionId);
    state.actionCount++;
    state.recentActions.push(actionType);
    if (state.recentActions.length > 100) {
      state.recentActions.shift();
    }
  }

  /**
   * trustscope_check_policy - Evaluate content against policies
   */
  async checkPolicy(input: CheckPolicyInput): Promise<unknown> {
    const { agent_id, session_id, action_type, tool_name, tool_args, content } = input;

    const sessionId = session_id || `session_${nanoid(8)}`;
    const sessionState = this.getSessionState(sessionId);

    // Build content to check
    const contentToCheck = content || JSON.stringify(tool_args || {});

    // Run policy evaluation
    const result = this.policyEngine.evaluate(
      {
        content: contentToCheck,
        context: {
          agentId: agent_id,
          sessionId,
          actionType: action_type,
          toolName: tool_name,
          direction: 'input',
          source: 'mcp',
        },
      },
      sessionState,
    );

    // Generate redacted/safe args
    let safeArgs: Record<string, unknown> | undefined;
    let redactions: RedactionMatch[] = [];

    if (tool_args) {
      const redactionResult = redactToolArgs(tool_args);
      safeArgs = redactionResult.safe_args;
      redactions = redactionResult.redactions;
    }

    // Generate guidance
    const guidance = generateGuidance(
      result.results.map((r) => ({
        engine: r.engine,
        triggered: r.triggered,
        details: r.details,
      })),
      redactions,
    );

    // Estimate cost
    const costEstimate = estimateCost(contentToCheck);

    // Log the check as a trace
    const trace = this.store.insertTrace({
      source: 'mcp',
      agent_id,
      session_id: sessionId,
      action_type: 'policy_check',
      tool_name: tool_name || action_type,
      request_summary: `Policy check for ${action_type}`,
      response_summary: result.summary,
      blocked: result.anyBlocked,
      simulated: false,
      cached: false,
      original_trace: null,
      detection_results: result.results as unknown as DetectionResultSet,
      policies_checked: result.results.map((r) => ({
        engine: r.engine,
        triggered: r.triggered,
        action: r.action,
      })) as unknown as PolicyCheckResult[],
      risk_weight: result.anyBlocked ? 1.0 : result.anyTriggered ? 0.5 : 0.0,
    });

    // trace is already the full Trace object from insertTrace

    // Update session state
    this.updateSessionState(sessionId, action_type);

    // Update participation
    this.store.updateParticipation(
      agent_id,
      sessionId,
      true, // This is a governance call
      result.anyBlocked ? 1.0 : result.anyTriggered ? 0.5 : 0.3,
    );

    return {
      decision: result.finalAction,
      blocked: result.anyBlocked,
      severity: result.highestSeverity,
      alerts: result.results.filter((r) => r.triggered).map((r) => ({
        policy: r.engine,
        field: redactions.find((red) => red.field)?.field,
        detail: r.message || `${r.engine} triggered`,
      })),
      safe_args: safeArgs,
      guidance,
      cost_estimate: costEstimate,
      enforcement: detectEnforcementSync(true),
      evidence: {
        trace_id: trace.id,
        audit_hash: trace.audit_hash ? `sha256:${trace.audit_hash.substring(0, 16)}...` : undefined,
        timestamp: trace.timestamp,
      },
    };
  }

  /**
   * trustscope_check_detection - Run detection engines
   */
  async checkDetection(input: CheckDetectionInput): Promise<unknown> {
    const { content, context, engines } = input;

    // Build detection configs
    const configs: Record<string, DetectionConfig> = {};
    const allEngineNames = getEngineNames();
    const enginesToRun = engines || allEngineNames;

    for (const engineName of enginesToRun) {
      if (allEngineNames.includes(engineName)) {
        configs[engineName] = { enabled: true };
      }
    }

    // Run detections
    const sessionState = context?.session_id
      ? this.getSessionState(context.session_id)
      : undefined;

    const results = runAllDetections(
      content,
      {
        agentId: context?.agent_id,
        sessionId: context?.session_id,
        actionType: context?.action_type,
        toolName: context?.tool_name,
        direction: context?.direction,
      },
      configs,
      sessionState,
    );

    // Compute confidence as average of triggered detections
    const triggeredResults = results.results.filter((r) => r.triggered);
    const avgConfidence = triggeredResults.length > 0
      ? triggeredResults.reduce((sum, r) => sum + (r.confidence || 0.5), 0) / triggeredResults.length
      : 0;

    // Determine recommended action
    let recommendedAction: 'allow' | 'alert' | 'block' = 'allow';
    if (results.anyBlocked) {
      recommendedAction = 'block';
    } else if (results.anyTriggered) {
      recommendedAction = 'alert';
    }

    return {
      triggered: results.anyTriggered,
      severity: results.highestSeverity,
      detections: results.results
        .filter((r) => r.triggered)
        .map((r) => ({
          engine: r.engine,
          severity: r.severity,
          message: r.message,
          details: r.details,
          confidence: r.confidence,
        })),
      confidence: Math.round(avgConfidence * 100) / 100,
      recommended_action: recommendedAction,
      summary: results.summary,
      engines_run: enginesToRun.length,
    };
  }

  /**
   * trustscope_log_action - Log action to evidence store
   */
  async logAction(input: LogActionInput): Promise<unknown> {
    const {
      agent_id,
      session_id,
      action_type,
      tool_name,
      request_summary,
      response_summary,
      blocked,
      simulated,
      metadata,
    } = input;

    const sessionId = session_id || `session_${nanoid(8)}`;

    const loggedTrace = this.store.insertTrace({
      source: 'mcp',
      agent_id,
      session_id: sessionId,
      action_type,
      tool_name,
      request_summary,
      response_summary,
      blocked: !!blocked,
      simulated: !!simulated,
      cached: false,
      original_trace: metadata ? JSON.stringify(metadata) : null,
      risk_weight: blocked ? 1.0 : 0.5,
    });

    // Update session state
    this.updateSessionState(sessionId, action_type);

    return {
      success: true,
      trace_id: loggedTrace.id,
      message: 'Action logged successfully',
    };
  }

  /**
   * trustscope_list_traces - Query evidence store
   */
  async listTraces(input: ListTracesInput): Promise<unknown> {
    const { agent_id, session_id, limit, offset, blocked_only } = input;

    const traces = this.store.listTraces({
      agent_id,
      session_id,
      limit: limit || 100,
      offset: offset || 0,
    });

    const filteredTraces = blocked_only
      ? traces.filter((t) => t.blocked === 1)
      : traces;

    return {
      traces: filteredTraces.map((t) => ({
        id: t.id,
        source: t.source,
        agent_id: t.agent_id,
        session_id: t.session_id,
        action_type: t.action_type,
        tool_name: t.tool_name,
        blocked: t.blocked === 1,
        timestamp: t.timestamp,
        audit_hash: t.audit_hash?.slice(0, 16),
      })),
      total: filteredTraces.length,
      has_more: filteredTraces.length === (limit || 100),
    };
  }

  /**
   * trustscope_list_policies - Return configured policies
   */
  async listPolicies(input: ListPoliciesInput): Promise<unknown> {
    const { engine } = input;

    const policies = this.policyEngine.getPolicies();

    if (engine) {
      const policy = policies[engine];
      return policy
        ? { policies: { [engine]: policy } }
        : { error: `Engine '${engine}' not found` };
    }

    return {
      policies,
      total: Object.keys(policies).length,
      mode: 'local',
    };
  }

  /**
   * trustscope_list_approvals - Query pending approvals
   */
  async listApprovals(input: ListApprovalsInput): Promise<unknown> {
    // In local mode, approvals are stored in the evidence store
    // For now, return empty since approvals require manual intervention
    const { agent_id, status, limit } = input;

    // This would query a pending_approvals table if we had one
    // For MVP, return empty list with explanation
    return {
      approvals: [],
      total: 0,
      message: 'Local mode: Approvals are handled synchronously. No pending approvals.',
      filters: { agent_id, status, limit },
    };
  }

  /**
   * trustscope_approve - Process approval decision
   */
  async approve(input: ApproveInput): Promise<unknown> {
    const { approval_id, approved, reason } = input;

    // In local mode, log the approval decision as a trace
    const approvalTrace = this.store.insertTrace({
      source: 'mcp',
      action_type: 'approval_decision',
      request_summary: `Approval ${approval_id}: ${approved ? 'APPROVED' : 'REJECTED'}`,
      response_summary: reason || 'No reason provided',
      blocked: false,
      simulated: false,
      cached: false,
      original_trace: null,
      risk_weight: approved ? 0.3 : 0.7,
    });

    return {
      success: true,
      approval_id,
      decision: approved ? 'approved' : 'rejected',
      reason,
      trace_id: approvalTrace.id,
    };
  }

  /**
   * trustscope_get_agent_dna - Compute behavioral fingerprint
   */
  async getAgentDNA(input: GetAgentDNAInput): Promise<unknown> {
    const { agent_id } = input;

    // Get traces for this agent
    const traces = this.store.listTraces({ agent_id, limit: 1000 });

    if (traces.length === 0) {
      return {
        agent_id,
        dna: null,
        message: 'No traces found for this agent',
      };
    }

    // Compute DNA strands from trace history
    const dna = this.computeAgentDNA(traces);

    // Store DNA snapshot
    this.store.upsertDNA(agent_id, dna, traces.length);

    return {
      agent_id,
      trace_count: traces.length,
      computed_at: new Date().toISOString(),
      dna,
    };
  }

  /**
   * Compute 8 DNA strands from traces
   */
  private computeAgentDNA(traces: Array<Record<string, unknown>>): Record<string, unknown> {
    const totalTraces = traces.length;
    const blockedCount = traces.filter((t) => t.blocked === 1).length;

    // Tool usage distribution
    const toolCounts: Record<string, number> = {};
    for (const trace of traces) {
      const tool = (trace.tool_name as string) || 'unknown';
      toolCounts[tool] = (toolCounts[tool] || 0) + 1;
    }

    // Action type distribution
    const actionCounts: Record<string, number> = {};
    for (const trace of traces) {
      const action = (trace.action_type as string) || 'unknown';
      actionCounts[action] = (actionCounts[action] || 0) + 1;
    }

    // Session patterns
    const sessionIds = [...new Set(traces.map((t) => t.session_id as string))];

    // Time distribution (hour of day)
    const hourCounts: Record<number, number> = {};
    for (const trace of traces) {
      const timestamp = trace.timestamp as string;
      if (timestamp) {
        const hour = new Date(timestamp).getHours();
        hourCounts[hour] = (hourCounts[hour] || 0) + 1;
      }
    }

    return {
      // Strand 1: Tool preference
      tool_preference: {
        distribution: toolCounts,
        unique_tools: Object.keys(toolCounts).length,
        most_used: Object.entries(toolCounts).sort((a, b) => b[1] - a[1])[0]?.[0],
      },
      // Strand 2: Action patterns
      action_patterns: {
        distribution: actionCounts,
        unique_actions: Object.keys(actionCounts).length,
        most_common: Object.entries(actionCounts).sort((a, b) => b[1] - a[1])[0]?.[0],
      },
      // Strand 3: Risk profile
      risk_profile: {
        block_rate: blockedCount / totalTraces,
        blocked_count: blockedCount,
        total_actions: totalTraces,
      },
      // Strand 4: Session behavior
      session_behavior: {
        total_sessions: sessionIds.length,
        avg_actions_per_session: totalTraces / Math.max(sessionIds.length, 1),
      },
      // Strand 5: Temporal patterns
      temporal_patterns: {
        hour_distribution: hourCounts,
        peak_hour: Object.entries(hourCounts).sort((a, b) => b[1] - a[1])[0]?.[0],
      },
      // Strand 6: Governance compliance
      governance: {
        governance_calls: traces.filter((t) => t.source === 'mcp').length,
        compliance_rate: 1 - blockedCount / totalTraces,
      },
      // Strand 7: Velocity
      velocity: {
        total_actions: totalTraces,
        // Would compute rate over time with more data
      },
      // Strand 8: Error patterns
      error_patterns: {
        // Would track error types if we had that data
        blocked_actions: blockedCount,
      },
    };
  }

  /**
   * trustscope_get_compliance - Evidence summary and chain status
   */
  async getCompliance(input: GetComplianceInput): Promise<unknown> {
    const { agent_id, session_id } = input;

    // Get trace statistics
    const allTraces = this.store.listTraces({ agent_id, session_id, limit: 10000 });
    const blockedTraces = allTraces.filter((t) => t.blocked === 1);

    // Verify hash chain
    const chainStatus = this.store.verifyChain();

    // Get detection summary
    const detectionSummary: Record<string, number> = {};
    for (const trace of allTraces) {
      const results = trace.detection_results as string;
      if (results) {
        try {
          const parsed = JSON.parse(results);
          for (const result of parsed) {
            if (result.triggered) {
              detectionSummary[result.engine] = (detectionSummary[result.engine] || 0) + 1;
            }
          }
        } catch {
          // Ignore parse errors
        }
      }
    }

    return {
      mode: 'local',
      evidence: {
        total_traces: allTraces.length,
        blocked_traces: blockedTraces.length,
        block_rate: allTraces.length > 0 ? blockedTraces.length / allTraces.length : 0,
      },
      chain: {
        valid: chainStatus.valid,
        broken_at: chainStatus.broken_at,
        last_verified: new Date().toISOString(),
      },
      detections: {
        summary: detectionSummary,
        engines_triggered: Object.keys(detectionSummary).length,
      },
      filters: { agent_id, session_id },
    };
  }

  /**
   * trustscope_explain_behavior - Statistical analysis with z-scores
   */
  async explainBehavior(input: ExplainBehaviorInput): Promise<ExplainBehaviorResponse> {
    const { agent_id, session_id, window_hours } = input;

    const hoursBack = window_hours || 24;
    const cutoff = new Date(Date.now() - hoursBack * 60 * 60 * 1000).toISOString();

    // Get traces in window
    const allTraces = this.store.listTraces({ agent_id, session_id, limit: 10000 });
    const windowTraces = allTraces.filter(
      (t) => (t.timestamp as string) >= cutoff,
    );

    if (windowTraces.length === 0) {
      return {
        risk_level: 'low',
        risk_score: 0,
        signals: [],
        diagnosis: [],
        recommended_actions: ['No traces in analysis window'],
        participation: {
          score: 100,
          level: 'high',
          governance_calls: 0,
          risk_actions: 0,
          weighted_governed: 0,
          weighted_total: 0,
        },
        evidence: {
          trace_count: 0,
          window_start: cutoff,
          window_end: new Date().toISOString(),
          blocked_count: 0,
        },
      };
    }

    // Get agent DNA baseline
    const dna = this.store.getDNA(agent_id);
    const baseline = dna?.strand_data || null;

    // Count governance calls (traces with source = 'mcp')
    const governanceCalls = windowTraces.filter(
      (t) => (t.source as string) === 'mcp',
    ).length;

    // Run behavioral analysis
    const result = analyzeBehavior(
      windowTraces as any[], // Cast to expected Trace type
      baseline,
      hoursBack,
      governanceCalls,
    );

    // Sprint 3: Add tier upgrade info for enhanced features
    const tierUpgrade = this.getTierUpgrade('explain_behavior');
    if (tierUpgrade) {
      (result as Record<string, unknown>).tier_upgrade = tierUpgrade;
    }

    // Sprint 3 TASK 8: Layer 2 NL Diagnosis via cloud API
    // Layer 2 requires protect_plus tier and cloud connection
    const nlDiagnosisUpgrade = this.getTierUpgrade('nl_diagnosis');

    if (isLayer2Available() && !nlDiagnosisUpgrade) {
      // User has cloud connection and appropriate tier - get NL diagnosis
      try {
        const recentActions = windowTraces.slice(-20).map(t => {
          const toolName = t.tool_name as string || 'unknown';
          const actionType = t.action_type as string || 'action';
          return `${actionType}:${toolName}`;
        });

        const layer2Result = await getLayer2Diagnosis(
          result.signals,
          {
            agentId: agent_id,
            sessionId: session_id,
            recentActions,
            windowHours: hoursBack,
          },
        );

        if (layer2Result.available) {
          // Merge Layer 2 NL explanations into diagnoses
          result.diagnosis = mergeDiagnoses(result.diagnosis, layer2Result);
          (result as Record<string, unknown>).layer2_available = true;
        } else if (layer2Result.tier_required) {
          // Cloud returned tier restriction
          result.diagnosis = result.diagnosis.map(d => ({
            ...d,
            explanation: d.explanation || `Upgrade to ${layer2Result.tier_required} for detailed NL diagnosis`,
          }));
          (result as Record<string, unknown>).tier_upgrade = {
            required_tier: layer2Result.tier_required,
            feature: 'nl_diagnosis',
            upgrade_url: 'https://trustscope.ai/pricing',
          };
        }
      } catch {
        // Layer 2 failed - fail open, return Layer 1 only
        (result as Record<string, unknown>).layer2_available = false;
        (result as Record<string, unknown>).layer2_error = 'Cloud diagnosis unavailable';
      }
    } else if (nlDiagnosisUpgrade) {
      // User needs to upgrade tier for NL diagnosis
      result.diagnosis = result.diagnosis.map(d => ({
        ...d,
        explanation: d.explanation || `Upgrade to ${nlDiagnosisUpgrade.required_tier} for detailed NL diagnosis`,
      }));
      (result as Record<string, unknown>).tier_upgrade = nlDiagnosisUpgrade;
    } else {
      // Not connected to cloud - show how to connect
      result.diagnosis = result.diagnosis.map(d => ({
        ...d,
        explanation: d.explanation || 'Connect to TrustScope cloud for NL diagnosis: trustscope cloud connect',
      }));
      (result as Record<string, unknown>).layer2_available = false;
    }

    return result;
  }

  /**
   * trustscope_get_attestation - Generate unsigned attestation
   */
  async getAttestation(input: GetAttestationInput): Promise<unknown> {
    const { agent_id, window_start, window_end, sign: requestSign } = input;

    const start = window_start || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const end = window_end || new Date().toISOString();

    // Get traces in window
    const allTraces = this.store.listTraces({ agent_id, limit: 10000 });
    const windowTraces = allTraces.filter((t) => {
      const ts = t.timestamp as string;
      return ts >= start && ts <= end;
    });

    if (windowTraces.length === 0) {
      return {
        agent_id,
        attestation: null,
        message: 'No traces in attestation window',
      };
    }

    // Build claims
    const firstTrace = windowTraces[0];
    const lastTrace = windowTraces[windowTraces.length - 1];
    const blockedCount = windowTraces.filter((t) => t.blocked).length;

    // Verify chain for these traces
    const chainStatus = this.store.verifyChain();

    // Sprint 3: Get enhanced attestation data
    const participation = this.store.computeParticipationScore();
    const enforcement = detectEnforcementSync();

    // Build attestation claims
    const claims = {
      // Original claims
      trace_count: windowTraces.length,
      blocked_count: blockedCount,
      compliance_rate: 1 - blockedCount / windowTraces.length,
      chain_valid: chainStatus.valid,
      first_trace: firstTrace?.id,
      last_trace: lastTrace?.id,
      evidence_root: lastTrace?.audit_hash,
      // Sprint 3: Enhanced claims
      traces_governed: this.store.getGovernedTraceCount(),
      policy_checks: this.store.getPolicyCheckCount(),
      policy_violations: this.store.getPolicyViolationCount(),
      detections_triggered: this.store.getDetectionTriggerCount(),
      participation_score: participation.score,
      hash_chain_intact: chainStatus.valid,
      enforcement_coverage: enforcement.coverage,
    };

    const attestation: Record<string, unknown> = {
      id: `att_${nanoid(12)}`,
      agent_id,
      window: {
        start,
        end,
      },
      claims,
      signed: false,
      signature: null as string | null,
      public_key: null as string | null,
      created_at: new Date().toISOString(),
    };

    // Sprint 3 TASK 9: Ed25519 Signed Attestations
    if (requestSign) {
      const signUpgrade = this.getTierUpgrade('signed_attestations');

      if (signUpgrade) {
        // User needs higher tier for signed attestations
        attestation.tier_upgrade = signUpgrade;
        attestation.note = `Signing requires ${signUpgrade.required_tier} tier. Upgrade at https://trustscope.ai/pricing`;
      } else {
        // User has appropriate tier - sign the attestation
        // Ensure keys exist (creates them if not)
        if (!hasSigningKeys()) {
          getOrCreateKeyPair();
        }

        const signedData = signAttestation(claims as Record<string, unknown>);
        if (signedData) {
          attestation.signed = true;
          attestation.signature = signedData.signature;
          attestation.public_key = signedData.public_key;
          attestation.note = 'Ed25519 signed attestation. Verify with trustscope verify --signature';
        } else {
          attestation.note = 'Signing failed - key generation error';
        }
      }
    } else {
      attestation.note = 'Unsigned attestation - use sign:true to request Ed25519 signature';
    }

    // Store attestation
    this.store.insertAttestation({
      agent_id: agent_id || 'unknown',
      window_start: start,
      window_end: end,
      claims,
      evidence_root: (claims.evidence_root as string) || '',
    });

    return attestation;
  }
}
