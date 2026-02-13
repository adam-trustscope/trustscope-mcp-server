/**
 * TrustScope Cloud Diagnosis (Layer 2)
 *
 * LLM-powered natural language diagnosis via cloud API.
 * Enhances Layer 1 statistical analysis with detailed explanations.
 */

import { getCredentials } from '../auth/index.js';
import type { Signal, Diagnosis } from '../analysis/behavior.js';

const API_BASE_URL = process.env.TRUSTSCOPE_API_URL || 'https://api.trustscope.ai';

export interface SessionContext {
  agentId?: string;
  sessionId?: string;
  recentActions: string[];
  windowHours: number;
}

export interface Layer2DiagnosisResult {
  diagnoses: Diagnosis[];
  available: boolean;
  tier_required?: string;
}

/**
 * Get Layer 2 NL diagnosis from cloud API
 *
 * @param signals - Array of signals from Layer 1 analysis
 * @param context - Session context for the diagnosis
 * @returns Diagnosis array with NL explanations, or null if unavailable
 */
export async function getLayer2Diagnosis(
  signals: Signal[],
  context: SessionContext
): Promise<Layer2DiagnosisResult> {
  const credentials = getCredentials();

  // Not connected to cloud - Layer 2 not available
  if (!credentials) {
    return {
      diagnoses: [],
      available: false,
      tier_required: 'protect_plus',
    };
  }

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/explain/diagnose`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${credentials.accessToken}`,
      },
      body: JSON.stringify({
        signals: signals.map(s => ({
          name: s.name,
          value: s.value,
          baseline: s.baseline,
          z_score: s.z_score,
          severity: s.severity,
        })),
        context: {
          agent_id: context.agentId,
          session_id: context.sessionId,
          recent_actions: context.recentActions.slice(-20), // Last 20 actions
          window_hours: context.windowHours,
        },
      }),
    });

    if (response.ok) {
      const data = await response.json() as {
        diagnoses: Array<{
          label: string;
          confidence: number;
          explanation: string;
        }>;
      };

      return {
        diagnoses: data.diagnoses.map(d => ({
          label: d.label,
          confidence: d.confidence,
          explanation: d.explanation,
        })),
        available: true,
      };
    }

    // Handle specific error codes
    if (response.status === 403) {
      // Tier restriction
      return {
        diagnoses: [],
        available: false,
        tier_required: 'protect_plus',
      };
    }

    // Other errors - fail open
    return {
      diagnoses: [],
      available: false,
    };
  } catch (error) {
    // Network error - fail open
    console.error('Layer 2 diagnosis failed:', error instanceof Error ? error.message : 'Unknown error');
    return {
      diagnoses: [],
      available: false,
    };
  }
}

/**
 * Merge Layer 1 diagnoses with Layer 2 NL explanations
 *
 * @param layer1Diagnoses - Diagnoses from statistical analysis
 * @param layer2Result - Result from cloud diagnosis API
 * @returns Merged diagnoses with NL explanations where available
 */
export function mergeDiagnoses(
  layer1Diagnoses: Diagnosis[],
  layer2Result: Layer2DiagnosisResult
): Diagnosis[] {
  if (!layer2Result.available || layer2Result.diagnoses.length === 0) {
    // Return Layer 1 diagnoses with null explanations
    return layer1Diagnoses;
  }

  // Create a map of Layer 2 diagnoses by label
  const layer2Map = new Map(
    layer2Result.diagnoses.map(d => [d.label, d])
  );

  // Merge Layer 2 explanations into Layer 1 diagnoses
  return layer1Diagnoses.map(d => {
    const layer2Match = layer2Map.get(d.label);
    if (layer2Match) {
      return {
        ...d,
        explanation: layer2Match.explanation,
        confidence: Math.max(d.confidence, layer2Match.confidence), // Use higher confidence
      };
    }
    return d;
  });
}

/**
 * Check if Layer 2 diagnosis is available
 */
export function isLayer2Available(): boolean {
  return getCredentials() !== null;
}
