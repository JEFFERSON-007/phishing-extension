/**
 * Explainable AI Engine Module
 * Generates transparent, evidence-backed security explanations directly mapped to detector findings.
 * @module ExplainableAIEngine
 */

export class ExplainableAIEngine {
  /**
   * Generate human-readable explanation and recommendations.
   * @param {Array<{ name: string, result: import('../../plugins/DetectorInterface.js').DetectorResult }>} detectorOutputs 
   * @param {{ riskScore: number, classification: string }} fusedResult 
   * @returns {{ reasons: string[], recommendation: string, findingsSummary: Array<{ category: string, description: string, severity: string }> }}
   */
  generateExplanation(detectorOutputs, fusedResult) {
    const reasons = [];
    const findingsSummary = [];

    if (!detectorOutputs || detectorOutputs.length === 0 || fusedResult.riskScore === 0) {
      return {
        reasons: ['No suspicious phishing or security threats detected on this page.'],
        recommendation: 'This site appears safe. Continue normal browsing.',
        findingsSummary: []
      };
    }

    // Extract findings across all detectors
    for (const { name, result } of detectorOutputs) {
      if (!result || !result.findings || result.findings.length === 0) continue;

      for (const finding of result.findings) {
        reasons.push(`[${finding.severity}] ${finding.description}`);
        findingsSummary.push({
          category: name.replace('Detector', '').replace('Analyzer', ''),
          description: finding.description,
          severity: finding.severity
        });
      }
    }

    const recommendation = this._generateRecommendation(fusedResult.classification);

    return {
      reasons: reasons.length > 0 ? reasons : ['Minor unusual security indicators observed.'],
      recommendation,
      findingsSummary
    };
  }

  /**
   * @private
   */
  _generateRecommendation(classification) {
    switch (classification) {
      case 'CRITICAL':
        return 'DO NOT enter passwords, credit cards, or personal information on this site. Leave immediately.';
      case 'HIGH':
        return 'Warning: Strong phishing indicators detected. Verify domain authenticity before interacting.';
      case 'MEDIUM':
        return 'Caution: Multiple suspicious indicators found. Exercise care when entering sensitive data.';
      case 'LOW':
        return 'Proceed with caution. Minor risk factors identified.';
      default:
        return 'Site appears safe.';
    }
  }
}
