/**
 * Behavioral Analysis Module
 *
 * Layer 1 statistical analysis with z-scores against DNA baseline.
 * Computes risk scores, signals, and diagnosis labels.
 */

import type { AgentDNAStrands, Trace, RISK_WEIGHTS } from '../types/evidence.js';

/**
 * Severity levels for signals
 */
export type SignalSeverity = 'info' | 'warning' | 'high' | 'critical';

/**
 * Risk levels for overall assessment
 */
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

/**
 * Participation levels based on score
 */
export type ParticipationLevel = 'critical' | 'low' | 'medium' | 'high';

/**
 * Signal detected during analysis
 */
export interface Signal {
  name: string;
  value: number;
  baseline: number;
  z_score: number;
  severity: SignalSeverity;
  description?: string;
}

/**
 * Diagnosis (pattern label) with confidence
 */
export interface Diagnosis {
  label: string;
  confidence: number;
  explanation: string | null; // null in local mode, filled by Layer 2 (cloud)
}

/**
 * Participation scoring result
 */
export interface ParticipationResult {
  score: number;
  level: ParticipationLevel;
  governance_calls: number;
  risk_actions: number;
  weighted_governed: number;
  weighted_total: number;
}

/**
 * Evidence summary
 */
export interface EvidenceSummary {
  trace_count: number;
  window_start: string;
  window_end: string;
  blocked_count: number;
}

/**
 * Full explain_behavior response
 */
export interface ExplainBehaviorResponse {
  risk_level: RiskLevel;
  risk_score: number;
  signals: Signal[];
  diagnosis: Diagnosis[];
  recommended_actions: string[];
  participation: ParticipationResult;
  evidence: EvidenceSummary;
}

/**
 * Risk weight factors for scoring
 */
const RISK_SIGNAL_WEIGHTS = {
  token_output_zscore_gt3: 0.30,
  new_tool_not_in_baseline: 0.20,
  detection_engine_hit: 0.25,
  cost_spike_zscore_gt3: 0.15,
  cross_agent_anomaly: 0.10,
};

/**
 * Action type risk weights for participation
 */
const ACTION_RISK_WEIGHTS: Record<string, number> = {
  read_only_query: 0.1,
  internal_compute: 0.1,
  data_read: 0.3,
  external_api_call: 0.5,
  data_mutation: 0.7,
  pii_handling: 0.8,
  financial_action: 0.9,
  data_deletion: 1.0,
  cross_agent_delegation: 1.0,
};

/**
 * Get severity from z-score
 */
function getSeverityFromZScore(zScore: number): SignalSeverity {
  const absZ = Math.abs(zScore);
  if (absZ >= 4) return 'critical';
  if (absZ >= 3) return 'high';
  if (absZ >= 2) return 'warning';
  return 'info';
}

/**
 * Compute z-score
 */
function computeZScore(value: number, mean: number, stdDev: number): number {
  if (stdDev === 0 || isNaN(stdDev)) {
    // No variation in baseline - if different from mean, flag as anomaly
    return value === mean ? 0 : value > mean ? 3 : -3;
  }
  return (value - mean) / stdDev;
}

/**
 * Compute risk level from score
 */
export function computeRiskLevel(score: number): RiskLevel {
  if (score >= 0.8) return 'critical';
  if (score >= 0.6) return 'high';
  if (score >= 0.3) return 'medium';
  return 'low';
}

/**
 * Compute participation level from score
 */
export function computeParticipationLevel(score: number): ParticipationLevel {
  if (score >= 80) return 'high';
  if (score >= 50) return 'medium';
  if (score >= 20) return 'low';
  return 'critical';
}

/**
 * Analyze behavioral signals against baseline
 */
export function analyzeSignals(
  traces: Trace[],
  baseline: AgentDNAStrands | null,
  windowHours: number,
): Signal[] {
  const signals: Signal[] = [];

  if (traces.length === 0) {
    return signals;
  }

  // Current window statistics
  const toolCounts: Record<string, number> = {};
  let blockedCount = 0;
  let totalTokens = 0;
  let tokenSamples = 0;

  for (const trace of traces) {
    const tool = (trace.tool_name as string) || 'unknown';
    toolCounts[tool] = (toolCounts[tool] || 0) + 1;
    if (trace.blocked) blockedCount++;

    // Estimate tokens from summaries if available
    if (trace.response_summary) {
      totalTokens += (trace.response_summary as string).length / 4; // rough estimate
      tokenSamples++;
    }
  }

  const currentVelocity = traces.length / windowHours;
  const currentTools = Object.keys(toolCounts);
  const avgTokensPerAction = tokenSamples > 0 ? totalTokens / tokenSamples : 0;

  // If we have baseline, compute z-scores
  if (baseline) {
    // Velocity signal
    const baselineVelocity =
      baseline.session_patterns?.avg_actions_per_session || traces.length;
    const velocityStdDev = baselineVelocity * 0.3; // Estimate 30% std dev
    const velocityZScore = computeZScore(currentVelocity, baselineVelocity / windowHours, velocityStdDev / windowHours);

    if (Math.abs(velocityZScore) >= 2) {
      signals.push({
        name: 'velocity',
        value: currentVelocity,
        baseline: baselineVelocity / windowHours,
        z_score: Math.round(velocityZScore * 100) / 100,
        severity: getSeverityFromZScore(velocityZScore),
        description: `Action velocity is ${velocityZScore > 0 ? 'above' : 'below'} baseline`,
      });
    }

    // Token output signal
    if (baseline.token_patterns) {
      const baselineTokens = baseline.token_patterns.avg_output_tokens || 100;
      const tokenStdDev = baseline.token_patterns.std_dev_output || 50;
      const tokenZScore = computeZScore(avgTokensPerAction, baselineTokens, tokenStdDev);

      if (Math.abs(tokenZScore) >= 2) {
        signals.push({
          name: 'token_output',
          value: avgTokensPerAction,
          baseline: baselineTokens,
          z_score: Math.round(tokenZScore * 100) / 100,
          severity: getSeverityFromZScore(tokenZScore),
          description: `Output tokens ${tokenZScore > 0 ? 'elevated' : 'reduced'} vs baseline`,
        });
      }
    }

    // New tools not in baseline
    const baselineTools = new Set(baseline.tool_repertoire || []);
    const newTools = currentTools.filter((t) => !baselineTools.has(t));

    if (newTools.length > 0) {
      signals.push({
        name: 'new_tools',
        value: newTools.length,
        baseline: 0,
        z_score: newTools.length * 2, // Each new tool adds to z-score
        severity: newTools.length >= 3 ? 'high' : newTools.length >= 2 ? 'warning' : 'info',
        description: `Using ${newTools.length} tool(s) not in baseline: ${newTools.slice(0, 3).join(', ')}`,
      });
    }

    // Error/blocked rate signal
    if (baseline.error_rates) {
      const baselineErrorRate = baseline.error_rates.error_rate || 0;
      const currentBlockRate = blockedCount / traces.length;
      const errorZScore = computeZScore(currentBlockRate, baselineErrorRate, 0.1);

      if (Math.abs(errorZScore) >= 2) {
        signals.push({
          name: 'block_rate',
          value: currentBlockRate,
          baseline: baselineErrorRate,
          z_score: Math.round(errorZScore * 100) / 100,
          severity: getSeverityFromZScore(errorZScore),
          description: `Block rate ${errorZScore > 0 ? 'elevated' : 'reduced'} vs baseline`,
        });
      }
    }
  } else {
    // No baseline - use heuristics
    if (currentVelocity > 100) {
      signals.push({
        name: 'velocity',
        value: currentVelocity,
        baseline: 50, // assumed normal
        z_score: 3,
        severity: 'high',
        description: 'High action velocity (no baseline for comparison)',
      });
    }

    if (blockedCount > 0) {
      const blockRate = blockedCount / traces.length;
      signals.push({
        name: 'block_rate',
        value: blockRate,
        baseline: 0,
        z_score: blockRate > 0.1 ? 3 : 2,
        severity: blockRate > 0.1 ? 'high' : 'warning',
        description: `${blockedCount} blocked action(s) in window`,
      });
    }
  }

  return signals;
}

/**
 * Generate diagnosis labels from signals
 */
export function generateDiagnosis(signals: Signal[]): Diagnosis[] {
  const diagnoses: Diagnosis[] = [];

  // Check for specific patterns
  const hasVelocitySpike = signals.find((s) => s.name === 'velocity' && s.z_score > 2);
  const hasTokenSpike = signals.find((s) => s.name === 'token_output' && s.z_score > 3);
  const hasNewTools = signals.find((s) => s.name === 'new_tools');
  const hasBlockSpike = signals.find((s) => s.name === 'block_rate' && s.z_score > 2);

  if (hasVelocitySpike && hasTokenSpike) {
    diagnoses.push({
      label: 'possible_exfiltration_via_verbosity',
      confidence: 0.72,
      explanation: null, // Layer 2 (cloud) fills this
    });
  }

  if (hasVelocitySpike) {
    diagnoses.push({
      label: 'elevated_velocity',
      confidence: Math.min(0.9, 0.5 + hasVelocitySpike.z_score * 0.1),
      explanation: null,
    });
  }

  if (hasNewTools) {
    diagnoses.push({
      label: 'capability_expansion',
      confidence: Math.min(0.85, 0.6 + (hasNewTools.value as number) * 0.1),
      explanation: null,
    });
  }

  if (hasBlockSpike) {
    diagnoses.push({
      label: 'policy_boundary_probing',
      confidence: Math.min(0.8, 0.5 + hasBlockSpike.z_score * 0.1),
      explanation: null,
    });
  }

  // If no specific patterns, add a general assessment
  if (diagnoses.length === 0 && signals.length > 0) {
    diagnoses.push({
      label: 'minor_deviation',
      confidence: 0.5,
      explanation: null,
    });
  }

  return diagnoses;
}

/**
 * Compute risk score from signals
 */
export function computeRiskScore(signals: Signal[]): number {
  let score = 0;

  for (const signal of signals) {
    const normalizedZ = Math.min(Math.abs(signal.z_score) / 4, 1); // Cap at z=4

    // Apply weights based on signal type
    if (signal.name === 'token_output' && signal.z_score > 3) {
      score += normalizedZ * RISK_SIGNAL_WEIGHTS.token_output_zscore_gt3;
    } else if (signal.name === 'new_tools') {
      score += normalizedZ * RISK_SIGNAL_WEIGHTS.new_tool_not_in_baseline;
    } else if (signal.name === 'block_rate') {
      score += normalizedZ * RISK_SIGNAL_WEIGHTS.detection_engine_hit;
    } else if (signal.name === 'velocity') {
      score += normalizedZ * RISK_SIGNAL_WEIGHTS.cost_spike_zscore_gt3;
    }
  }

  return Math.min(1, score);
}

/**
 * Generate recommended actions based on risk level
 */
export function generateRecommendedActions(
  riskLevel: RiskLevel,
  signals: Signal[],
  participation: ParticipationResult,
): string[] {
  const actions: string[] = [];

  if (riskLevel === 'critical') {
    actions.push('Immediately review agent activity');
    actions.push('Consider pausing agent operations');
    actions.push('Enable watch proxy for defense in depth');
  } else if (riskLevel === 'high') {
    actions.push('Review recent tool usage');
    actions.push('Enable watch proxy for defense in depth');
  } else if (riskLevel === 'medium') {
    actions.push('Monitor agent behavior');
    if (signals.find((s) => s.name === 'new_tools')) {
      actions.push('Verify new tool usage is authorized');
    }
  }

  if (participation.level === 'critical' || participation.level === 'low') {
    actions.push('Increase governance coverage with trustscope watch');
  }

  if (actions.length === 0) {
    actions.push('No immediate action required');
  }

  return actions;
}

/**
 * Compute participation score
 */
export function computeParticipation(
  traces: Trace[],
  governanceCalls: number,
): ParticipationResult {
  let weightedGoverned = 0;
  let weightedTotal = 0;
  let riskActions = 0;

  for (const trace of traces) {
    const actionType = (trace.action_type as string) || 'internal_compute';
    const weight = ACTION_RISK_WEIGHTS[actionType] || 0.3;

    weightedTotal += weight;

    if (weight >= 0.5) {
      riskActions++;
    }
  }

  // Governance calls contribute to weighted_governed
  // Assume each governance call covers one action with its weight
  weightedGoverned = Math.min(weightedTotal, governanceCalls * 0.5);

  const score = weightedTotal > 0 ? (weightedGoverned / weightedTotal) * 100 : 100;

  return {
    score: Math.round(score),
    level: computeParticipationLevel(score),
    governance_calls: governanceCalls,
    risk_actions: riskActions,
    weighted_governed: Math.round(weightedGoverned * 100) / 100,
    weighted_total: Math.round(weightedTotal * 100) / 100,
  };
}

/**
 * Full behavioral analysis
 */
export function analyzeBehavior(
  traces: Trace[],
  baseline: AgentDNAStrands | null,
  windowHours: number,
  governanceCalls: number,
): ExplainBehaviorResponse {
  const signals = analyzeSignals(traces, baseline, windowHours);
  const diagnosis = generateDiagnosis(signals);
  const riskScore = computeRiskScore(signals);
  const riskLevel = computeRiskLevel(riskScore);
  const participation = computeParticipation(traces, governanceCalls);
  const recommendedActions = generateRecommendedActions(riskLevel, signals, participation);

  // Evidence summary
  const timestamps = traces.map((t) => t.timestamp as string).sort();
  const blockedCount = traces.filter((t) => t.blocked).length;

  const evidence: EvidenceSummary = {
    trace_count: traces.length,
    window_start: timestamps[0] || new Date().toISOString(),
    window_end: timestamps[timestamps.length - 1] || new Date().toISOString(),
    blocked_count: blockedCount,
  };

  return {
    risk_level: riskLevel,
    risk_score: Math.round(riskScore * 100) / 100,
    signals,
    diagnosis,
    recommended_actions: recommendedActions,
    participation,
    evidence,
  };
}
