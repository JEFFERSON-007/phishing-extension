/**
 * Enterprise Policy Engine Module
 * Evaluates whitelists, blacklists, enterprise rules, user domain overrides, and feature flags.
 * @module EnterprisePolicyEngine
 */

export class EnterprisePolicyEngine {
  constructor() {
    /** @type {Set<string>} Permanent global domain whitelist */
    this.whitelist = new Set([
      'google.com', 'accounts.google.com', 'microsoft.com', 'login.microsoftonline.com',
      'github.com', 'paypal.com', 'apple.com', 'amazon.com', 'chase.com'
    ]);

    /** @type {Set<string>} Permanent domain blacklist */
    this.blacklist = new Set();

    /** @type {Set<string>} Session temporary allow overrides */
    this.sessionAllowedDomains = new Set();
  }

  /**
   * Add temporary session allow approval (e.g. user clicks "Proceed Anyway").
   * @param {string} hostname 
   */
  allowSessionDomain(hostname) {
    if (hostname) {
      this.sessionAllowedDomains.add(hostname.toLowerCase());
    }
  }

  /**
   * Evaluate context against rules before running heavy detectors.
   * @param {Record<string, *>} context 
   * @returns {{ isOverridden: boolean, riskScore?: number, classification?: string, reason?: string, recommendation?: string }}
   */
  evaluate(context) {
    if (!context || !context.url) {
      return { isOverridden: false };
    }

    let hostname = '';
    try {
      hostname = new URL(context.url).hostname.toLowerCase();
    } catch {
      return { isOverridden: false };
    }

    // 1. Session Temporary Allow Override
    if (this.sessionAllowedDomains.has(hostname)) {
      return {
        isOverridden: true,
        riskScore: 0,
        classification: 'SAFE',
        reason: `Domain '${hostname}' is explicitly allowed for this session by user override.`,
        recommendation: 'User temporary override active.'
      };
    }

    // 2. Enterprise Whitelist Match
    for (const domain of this.whitelist) {
      if (hostname === domain || hostname.endsWith('.' + domain)) {
        return {
          isOverridden: true,
          riskScore: 0,
          classification: 'SAFE',
          reason: `Domain '${hostname}' matches verified enterprise whitelist (${domain}).`,
          recommendation: 'Verified safe enterprise domain.'
        };
      }
    }

    // 3. Enterprise Blacklist Match
    for (const domain of this.blacklist) {
      if (hostname === domain || hostname.endsWith('.' + domain)) {
        return {
          isOverridden: true,
          riskScore: 100,
          classification: 'CRITICAL',
          reason: `Domain '${hostname}' is explicitly blocked by enterprise policy (${domain}).`,
          recommendation: 'Enterprise policy blocked domain.'
        };
      }
    }

    return { isOverridden: false };
  }
}
