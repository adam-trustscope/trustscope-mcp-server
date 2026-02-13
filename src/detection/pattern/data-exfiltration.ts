/**
 * Data Exfiltration Detector - Detect bulk data transfer, suspicious URLs, base64 encoding
 */

import type {
  DetectionEngine,
  DetectionResult,
  DetectionContext,
  DetectionConfig,
} from '../types.js';

const SUSPICIOUS_DOMAINS = [
  'pastebin.com',
  'hastebin.com',
  'requestbin.com',
  'ngrok.io',
  'ngrok.app',
  'webhook.site',
  'pipedream.net',
  'hookbin.com',
  'beeceptor.com',
];

const BASE64_PATTERN = /[A-Za-z0-9+/]{50,}={0,2}/g;
const URL_PATTERN = /https?:\/\/[^\s"'<>]+/gi;
const DATA_URL_PATTERN = /data:[a-z]+\/[a-z]+;base64,[A-Za-z0-9+/]+=*/gi;

export class DataExfiltrationDetector implements DetectionEngine {
  name = 'data_exfiltration';

  check(
    content: string,
    _context: DetectionContext,
    config: DetectionConfig,
  ): DetectionResult {
    if (!config.enabled || !content) {
      return {
        engine: this.name,
        triggered: false,
        blocked: false,
        severity: 'info',
        details: {},
      };
    }

    const allowedDomains = (config.allowedDomains as string[] | undefined) || [];
    const blockedDomains = (config.blockedDomains as string[] | undefined) || SUSPICIOUS_DOMAINS;
    const maxPayloadBytes = (config.maxPayloadBytes as number | undefined) || 100000;

    const issues: Array<{ type: string; detail: string; severity: string }> = [];

    // Check for blocked domains
    URL_PATTERN.lastIndex = 0;
    let urlMatch: RegExpExecArray | null;
    while ((urlMatch = URL_PATTERN.exec(content)) !== null) {
      const url = urlMatch[0];
      try {
        const hostname = new URL(url).hostname.toLowerCase();

        // Check if blocked
        const isBlocked = blockedDomains.some((d) => hostname.includes(d.toLowerCase()));
        if (isBlocked) {
          issues.push({
            type: 'blocked_domain',
            detail: `URL to blocked domain: ${hostname}`,
            severity: 'high',
          });
        }

        // Check if not in allowed domains (if allowlist specified)
        if (allowedDomains.length > 0) {
          const isAllowed = allowedDomains.some((d) => hostname.includes(d.toLowerCase()));
          if (!isAllowed) {
            issues.push({
              type: 'unapproved_domain',
              detail: `URL to unapproved domain: ${hostname}`,
              severity: 'warning',
            });
          }
        }
      } catch {
        // Invalid URL, skip
      }
    }

    // Check for large base64 payloads
    BASE64_PATTERN.lastIndex = 0;
    let base64Match: RegExpExecArray | null;
    while ((base64Match = BASE64_PATTERN.exec(content)) !== null) {
      const base64 = base64Match[0];
      // Approximate decoded size (base64 is ~4/3 of decoded)
      const estimatedSize = Math.floor(base64.length * 0.75);

      if (estimatedSize > maxPayloadBytes) {
        issues.push({
          type: 'large_base64',
          detail: `Large base64 payload (~${Math.round(estimatedSize / 1024)}KB)`,
          severity: 'high',
        });
      } else if (base64.length > 200) {
        issues.push({
          type: 'base64_data',
          detail: `Base64 encoded data (${base64.length} chars)`,
          severity: 'warning',
        });
      }
    }

    // Check for data URLs
    DATA_URL_PATTERN.lastIndex = 0;
    let dataUrlMatch: RegExpExecArray | null;
    while ((dataUrlMatch = DATA_URL_PATTERN.exec(content)) !== null) {
      const dataUrl = dataUrlMatch[0];
      if (dataUrl.length > 1000) {
        issues.push({
          type: 'data_url',
          detail: `Large data URL (${dataUrl.length} chars)`,
          severity: 'warning',
        });
      }
    }

    // Check for bulk data indicators
    const newlineCount = (content.match(/\n/g) || []).length;
    const commaCount = (content.match(/,/g) || []).length;

    if (newlineCount > 100 && content.length > 10000) {
      issues.push({
        type: 'bulk_data',
        detail: `Bulk text data (${newlineCount} lines, ${Math.round(content.length / 1024)}KB)`,
        severity: 'warning',
      });
    }

    if (commaCount > 500 && content.includes('\n')) {
      issues.push({
        type: 'csv_data',
        detail: `Possible CSV data (${commaCount} commas)`,
        severity: 'warning',
      });
    }

    const triggered = issues.length > 0;
    const hasHighSeverity = issues.some((i) => i.severity === 'high');

    return {
      engine: this.name,
      triggered,
      blocked: hasHighSeverity,
      severity: hasHighSeverity ? 'high' : triggered ? 'warning' : 'info',
      confidence: triggered ? 0.8 : 0,
      details: {
        issues,
        issueCount: issues.length,
        issueTypes: [...new Set(issues.map((i) => i.type))],
      },
      message: triggered
        ? `Detected ${issues.length} potential data exfiltration indicator(s)`
        : undefined,
    };
  }
}

export const dataExfiltrationDetector = new DataExfiltrationDetector();
