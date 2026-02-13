/**
 * Pattern Detection Engines Index
 *
 * 8 pattern-based detection engines for content analysis
 */

export { PIIScanner, piiScanner } from './pii-scanner.js';
export { SecretsScanner, secretsScanner } from './secrets-scanner.js';
export { CommandFirewall, commandFirewall } from './command-firewall.js';
export { BlockedPhrasesDetector, blockedPhrasesDetector } from './blocked-phrases.js';
export { DataExfiltrationDetector, dataExfiltrationDetector } from './data-exfiltration.js';
export { PromptInjectionDetector, promptInjectionDetector } from './prompt-injection.js';
export { JailbreakDetector, jailbreakDetector } from './jailbreak.js';
export { ActionLabelMismatchDetector, actionLabelMismatchDetector } from './action-label-mismatch.js';

import { piiScanner } from './pii-scanner.js';
import { secretsScanner } from './secrets-scanner.js';
import { commandFirewall } from './command-firewall.js';
import { blockedPhrasesDetector } from './blocked-phrases.js';
import { dataExfiltrationDetector } from './data-exfiltration.js';
import { promptInjectionDetector } from './prompt-injection.js';
import { jailbreakDetector } from './jailbreak.js';
import { actionLabelMismatchDetector } from './action-label-mismatch.js';
import type { DetectionEngine } from '../types.js';

/**
 * All pattern detection engines
 */
export const patternEngines: Record<string, DetectionEngine> = {
  pii_scanner: piiScanner,
  secrets_scanner: secretsScanner,
  command_firewall: commandFirewall,
  blocked_phrases: blockedPhrasesDetector,
  data_exfiltration: dataExfiltrationDetector,
  prompt_injection: promptInjectionDetector,
  jailbreak: jailbreakDetector,
  action_label_mismatch: actionLabelMismatchDetector,
};
