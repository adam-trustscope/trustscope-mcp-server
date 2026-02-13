/**
 * Detection Engine Registry
 *
 * 18 detection engines:
 * - 10 statistical engines for behavioral analysis
 * - 8 pattern engines for content scanning
 */

import { statisticalEngines } from './statistical/index.js';
import { patternEngines } from './pattern/index.js';
import type {
  DetectionEngine,
  DetectionResult,
  DetectionResultSet,
  DetectionContext,
  DetectionConfig,
  SessionState,
  Severity,
} from './types.js';

export * from './types.js';
export { statisticalEngines } from './statistical/index.js';
export { patternEngines } from './pattern/index.js';

/**
 * All detection engines (18 total)
 */
export const allEngines: Record<string, DetectionEngine> = {
  ...statisticalEngines,
  ...patternEngines,
};

/**
 * Get a specific engine by name
 */
export function getEngine(name: string): DetectionEngine | undefined {
  return allEngines[name];
}

/**
 * Get list of all engine names
 */
export function getEngineNames(): string[] {
  return Object.keys(allEngines);
}

/**
 * Severity levels for comparison
 */
const SEVERITY_LEVELS: Record<Severity, number> = {
  info: 0,
  warning: 1,
  high: 2,
  critical: 3,
};

/**
 * Run a single detection engine
 */
export function runDetection(
  engineName: string,
  content: string,
  context: DetectionContext,
  config: DetectionConfig,
  sessionState?: SessionState,
): DetectionResult | null {
  const engine = allEngines[engineName];
  if (!engine) {
    return null;
  }

  return engine.check(content, context, config, sessionState);
}

/**
 * Run all detection engines and aggregate results
 */
export function runAllDetections(
  content: string,
  context: DetectionContext,
  configs: Record<string, DetectionConfig>,
  sessionState?: SessionState,
): DetectionResultSet {
  const results: DetectionResult[] = [];
  let anyTriggered = false;
  let anyBlocked = false;
  let highestSeverity: Severity = 'info';

  for (const [engineName, engine] of Object.entries(allEngines)) {
    const config = configs[engineName] || { enabled: false };
    if (!config.enabled) continue;

    try {
      const result = engine.check(content, context, config, sessionState);
      results.push(result);

      if (result.triggered) {
        anyTriggered = true;
      }
      if (result.blocked) {
        anyBlocked = true;
      }
      if (SEVERITY_LEVELS[result.severity] > SEVERITY_LEVELS[highestSeverity]) {
        highestSeverity = result.severity;
      }
    } catch (error) {
      // Fail open - log error but don't block
      results.push({
        engine: engineName,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error',
        },
      });
    }
  }

  // Build summary
  const triggeredEngines = results.filter((r) => r.triggered).map((r) => r.engine);
  const blockedEngines = results.filter((r) => r.blocked).map((r) => r.engine);

  let summary = '';
  if (anyBlocked) {
    summary = `Blocked by ${blockedEngines.length} engine(s): ${blockedEngines.join(', ')}`;
  } else if (anyTriggered) {
    summary = `Alerts from ${triggeredEngines.length} engine(s): ${triggeredEngines.join(', ')}`;
  } else {
    summary = 'All checks passed';
  }

  return {
    results,
    anyTriggered,
    anyBlocked,
    highestSeverity,
    summary,
  };
}

/**
 * Run only pattern detection engines (for content scanning)
 */
export function runPatternDetections(
  content: string,
  context: DetectionContext,
  configs: Record<string, DetectionConfig>,
): DetectionResultSet {
  const results: DetectionResult[] = [];
  let anyTriggered = false;
  let anyBlocked = false;
  let highestSeverity: Severity = 'info';

  for (const [engineName, engine] of Object.entries(patternEngines)) {
    const config = configs[engineName] || { enabled: false };
    if (!config.enabled) continue;

    try {
      const result = engine.check(content, context, config);
      results.push(result);

      if (result.triggered) anyTriggered = true;
      if (result.blocked) anyBlocked = true;
      if (SEVERITY_LEVELS[result.severity] > SEVERITY_LEVELS[highestSeverity]) {
        highestSeverity = result.severity;
      }
    } catch (error) {
      results.push({
        engine: engineName,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
      });
    }
  }

  const triggeredEngines = results.filter((r) => r.triggered).map((r) => r.engine);
  const blockedEngines = results.filter((r) => r.blocked).map((r) => r.engine);

  return {
    results,
    anyTriggered,
    anyBlocked,
    highestSeverity,
    summary: anyBlocked
      ? `Blocked by ${blockedEngines.join(', ')}`
      : anyTriggered
      ? `Alerts from ${triggeredEngines.join(', ')}`
      : 'All pattern checks passed',
  };
}

/**
 * Run only statistical detection engines (for behavioral analysis)
 */
export function runStatisticalDetections(
  content: string,
  context: DetectionContext,
  configs: Record<string, DetectionConfig>,
  sessionState: SessionState,
): DetectionResultSet {
  const results: DetectionResult[] = [];
  let anyTriggered = false;
  let anyBlocked = false;
  let highestSeverity: Severity = 'info';

  for (const [engineName, engine] of Object.entries(statisticalEngines)) {
    const config = configs[engineName] || { enabled: false };
    if (!config.enabled) continue;

    try {
      const result = engine.check(content, context, config, sessionState);
      results.push(result);

      if (result.triggered) anyTriggered = true;
      if (result.blocked) anyBlocked = true;
      if (SEVERITY_LEVELS[result.severity] > SEVERITY_LEVELS[highestSeverity]) {
        highestSeverity = result.severity;
      }
    } catch (error) {
      results.push({
        engine: engineName,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
      });
    }
  }

  const triggeredEngines = results.filter((r) => r.triggered).map((r) => r.engine);
  const blockedEngines = results.filter((r) => r.blocked).map((r) => r.engine);

  return {
    results,
    anyTriggered,
    anyBlocked,
    highestSeverity,
    summary: anyBlocked
      ? `Blocked by ${blockedEngines.join(', ')}`
      : anyTriggered
      ? `Alerts from ${triggeredEngines.join(', ')}`
      : 'All statistical checks passed',
  };
}
