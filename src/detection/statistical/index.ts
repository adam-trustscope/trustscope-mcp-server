/**
 * Statistical Detection Engines Index
 *
 * 10 statistical engines for behavioral analysis
 */

export { LoopKillerDetector, loopKillerDetector } from './loop-killer.js';
export { VelocityLimitDetector, velocityLimitDetector } from './velocity-limit.js';
export { CostVelocityDetector, costVelocityDetector } from './cost-velocity.js';
export { BudgetCapsDetector, budgetCapsDetector } from './budget-caps.js';
export { TokenGrowthDetector, tokenGrowthDetector } from './token-growth.js';
export { ContextExpansionDetector, contextExpansionDetector } from './context-expansion.js';
export { OscillationDetector, oscillationDetector } from './oscillation.js';
export { ErrorRateDetector, errorRateDetector } from './error-rate.js';
export { SessionDurationDetector, sessionDurationDetector } from './session-duration.js';
export { SessionActionLimitDetector, sessionActionLimitDetector } from './session-action-limit.js';

import { loopKillerDetector } from './loop-killer.js';
import { velocityLimitDetector } from './velocity-limit.js';
import { costVelocityDetector } from './cost-velocity.js';
import { budgetCapsDetector } from './budget-caps.js';
import { tokenGrowthDetector } from './token-growth.js';
import { contextExpansionDetector } from './context-expansion.js';
import { oscillationDetector } from './oscillation.js';
import { errorRateDetector } from './error-rate.js';
import { sessionDurationDetector } from './session-duration.js';
import { sessionActionLimitDetector } from './session-action-limit.js';
import type { DetectionEngine } from '../types.js';

/**
 * All statistical detection engines
 */
export const statisticalEngines: Record<string, DetectionEngine> = {
  loop_killer: loopKillerDetector,
  velocity_limit: velocityLimitDetector,
  cost_velocity: costVelocityDetector,
  budget_caps: budgetCapsDetector,
  token_growth: tokenGrowthDetector,
  context_expansion: contextExpansionDetector,
  oscillation: oscillationDetector,
  error_rate: errorRateDetector,
  session_duration: sessionDurationDetector,
  session_action_limit: sessionActionLimitDetector,
};
