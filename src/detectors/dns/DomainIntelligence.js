/**
 * Domain Intelligence Module
 * Offline-first domain metadata engine providing interface contracts for WHOIS, DNS records, ASN, and domain age providers.
 * @module DomainIntelligence
 */

import { DetectorInterface } from '../../plugins/DetectorInterface.js';
import { MultiLayerCache } from '../../cache/MultiLayerCache.js';

export class DomainIntelligence extends DetectorInterface {
  constructor() {
    super();
    /** @type {MultiLayerCache} */
    this.cache = new MultiLayerCache(500, 24 * 60 * 60 * 1000); // 24hr TTL
  }

  name() { return 'DomainIntelligence'; }
  version() { return '2.0.0'; }
  priority() { return 600; }
  enabled() { return true; }

  supports(context) {
    return Boolean(context && context.url);
  }

  /**
   * Analyze domain intelligence metadata (offline fallback).
   * @param {Record<string, *>} context 
   * @returns {Promise<import('../../plugins/DetectorInterface.js').DetectorResult>}
   */
  async analyze(context) {
    const startTime = performance.now();
    const findings = [];
    let totalScore = 0;

    let hostname = '';
    try {
      hostname = new URL(context.url).hostname;
    } catch {
      return this._buildResult(0, 1.0, 'LOW', [], performance.now() - startTime);
    }

    // Check cached domain intelligence record
    const cachedIntel = this.cache.get(hostname);
    if (cachedIntel) {
      if (cachedIntel.isNewlyRegistered) {
        findings.push({
          id: 'DNS_NEWLY_REGISTERED',
          type: 'NEWLY_REGISTERED_DOMAIN',
          description: `Domain '${hostname}' was registered within the last 30 days.`,
          score: 25,
          severity: 'HIGH'
        });
        totalScore += 25;
      }
    }

    const executionTime = parseFloat((performance.now() - startTime).toFixed(2));
    return this._buildResult(totalScore, 0.7, totalScore >= 40 ? 'MEDIUM' : 'LOW', findings, executionTime);
  }

  /**
   * Helper contract method for populating offline domain intelligence cache.
   * @param {string} domain 
   * @param {Record<string, *>} data - Domain metadata (age, registrar, ASN, DNS records).
   */
  registerDomainData(domain, data) {
    if (domain && data) {
      this.cache.set(domain.toLowerCase(), data);
    }
  }

  /**
   * @private
   */
  _buildResult(score, confidence, severity, findings, executionTime) {
    return {
      score,
      confidence,
      severity,
      findings,
      metadata: { detector: this.name() },
      executionTime
    };
  }
}
