/**
 * Certificate Analyzer Module
 * Analyzes SSL/TLS transport state, certificate attributes, and protocol scheme security offline.
 * @module CertificateAnalyzer
 */

import { DetectorInterface } from '../../plugins/DetectorInterface.js';

export class CertificateAnalyzer extends DetectorInterface {
  name() { return 'CertificateAnalyzer'; }
  version() { return '2.0.0'; }
  priority() { return 850; }
  enabled() { return true; }

  supports(context) {
    return Boolean(context && context.url);
  }

  /**
   * Analyze transport security state.
   * @param {Record<string, *>} context 
   * @returns {Promise<import('../../plugins/DetectorInterface.js').DetectorResult>}
   */
  async analyze(context) {
    const startTime = performance.now();
    const findings = [];
    let totalScore = 0;
    const url = context.url || '';

    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';

      // 1. Missing HTTPS Transport Layer
      if (!isHttps) {
        // High score if page carries authentication or financial keywords
        const isSensitivePath = url.includes('/login') || url.includes('/bank') || url.includes('/account') || url.includes('/pay');
        const score = isSensitivePath ? 35 : 15;
        findings.push({
          id: 'CERT_NO_HTTPS',
          type: 'MISSING_HTTPS_ENCRYPTION',
          description: isSensitivePath 
            ? 'Insecure HTTP protocol used on sensitive authentication/financial page.'
            : 'Page operates over unencrypted HTTP transport.',
          score,
          severity: isSensitivePath ? 'HIGH' : 'MEDIUM'
        });
        totalScore += score;
      }

      // 2. Transport Security Metadata (Offline Browser Security State)
      if (context.securityState) {
        const sec = context.securityState;
        if (sec.isSelfSigned) {
          findings.push({
            id: 'CERT_SELF_SIGNED',
            type: 'SELF_SIGNED_CERTIFICATE',
            description: 'Untrusted self-signed certificate detected.',
            score: 30,
            severity: 'HIGH'
          });
          totalScore += 30;
        }

        if (sec.isExpired) {
          findings.push({
            id: 'CERT_EXPIRED',
            type: 'EXPIRED_CERTIFICATE',
            description: 'SSL/TLS certificate has expired.',
            score: 35,
            severity: 'HIGH'
          });
          totalScore += 35;
        }
      }
    } catch {}

    const finalScore = Math.min(totalScore, 100);
    const severity = finalScore >= 80 ? 'CRITICAL' : finalScore >= 60 ? 'HIGH' : finalScore >= 40 ? 'MEDIUM' : 'LOW';
    const executionTime = parseFloat((performance.now() - startTime).toFixed(2));

    return {
      score: finalScore,
      confidence: 0.95,
      severity,
      findings,
      metadata: { detector: this.name() },
      executionTime
    };
  }
}
