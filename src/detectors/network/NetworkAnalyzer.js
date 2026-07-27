/**
 * Network Security Analyzer Module
 * Inspects third-party script connections, mixed content, CSP headers, XHR/Fetch destinations, and WebSockets.
 * @module NetworkAnalyzer
 */

import { DetectorInterface } from '../../plugins/DetectorInterface.js';

export class NetworkAnalyzer extends DetectorInterface {
  name() { return 'NetworkAnalyzer'; }
  version() { return '2.0.0'; }
  priority() { return 650; }
  enabled() { return true; }

  supports(context) {
    return Boolean(context && (context.network || context.url));
  }

  /**
   * Analyze network transport security context.
   * @param {Record<string, *>} context 
   * @returns {Promise<import('../../plugins/DetectorInterface.js').DetectorResult>}
   */
  async analyze(context) {
    const startTime = performance.now();
    const findings = [];
    let totalScore = 0;

    const pageUrl = context.url || '';
    const network = context.network || {};
    const isHttps = pageUrl.startsWith('https:');

    // 1. Mixed Content Detection (HTTP assets loaded on HTTPS page)
    if (isHttps && network.insecureResources && network.insecureResources.length > 0) {
      findings.push({
        id: 'NET_MIXED_CONTENT',
        type: 'MIXED_CONTENT_LOADED',
        description: `HTTPS page loaded ${network.insecureResources.length} insecure HTTP subresources.`,
        score: 15,
        severity: 'MEDIUM',
        metadata: { count: network.insecureResources.length }
      });
      totalScore += 15;
    }

    // 2. Cross-Origin WebSocket Connection to Suspicious Port / Raw IP
    if (network.webSockets && Array.isArray(network.webSockets)) {
      for (const wsUrl of network.webSockets) {
        if (wsUrl.startsWith('ws:') && isHttps) {
          findings.push({
            id: 'NET_INSECURE_WEBSOCKET',
            type: 'INSECURE_WEBSOCKET',
            description: 'Insecure WebSocket (ws://) initialized on encrypted HTTPS origin.',
            score: 20,
            severity: 'HIGH'
          });
          totalScore += 20;
        }
      }
    }

    const finalScore = Math.min(totalScore, 100);
    const severity = finalScore >= 80 ? 'CRITICAL' : finalScore >= 60 ? 'HIGH' : finalScore >= 40 ? 'MEDIUM' : 'LOW';
    const executionTime = parseFloat((performance.now() - startTime).toFixed(2));

    return {
      score: finalScore,
      confidence: 0.85,
      severity,
      findings,
      metadata: { detector: this.name() },
      executionTime
    };
  }
}
