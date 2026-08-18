/**
 * Risk Fusion Engine Module
 * Fuses scores from multiple security detectors using confidence weighting, priority multipliers, and severity caps.
 * @module RiskFusionEngine
 */

export class RiskFusionEngine {
  constructor() {
    /** @type {Record<string, number>} Base detector priority weights */
    this.detectorWeights = {
      'ReputationEngine': 1.8,
      'URLDetector': 1.4,
      'FormDetector': 1.3,
      'CertificateAnalyzer': 1.2,
      'DOMDetector': 1.0,
      'BrandImpersonationDetector': 1.1,
      'BehaviorDetector': 1.0,
      'NetworkAnalyzer': 0.9,
      'DomainIntelligence': 0.8
    };
  }

  /**
   * Fuse detector outputs into an overall risk score and classification.
   * @param {Array<{ name: string, result: import('../../plugins/DetectorInterface.js').DetectorResult }>} detectorOutputs 
   * @param {import('../../adapters/ml/MLAdapter.js').MLPrediction} [mlPrediction] 
   * @returns {{ riskScore: number, confidence: number, classification: string, detectorsTriggered: string[] }}
   */
  fuse(detectorOutputs, mlPrediction = null) {
    if (!detectorOutputs || detectorOutputs.length === 0) {
      return {
        riskScore: 0,
        confidence: 1.0,
        classification: 'SAFE',
        detectorsTriggered: []
      };
    }

    let weightedSum = 0;
    let totalWeight = 0;
    let confidenceSum = 0;
    let maxSingleScore = 0;
    const detectorsTriggered = [];

    for (const { name, result } of detectorOutputs) {
      if (!result) continue;

      const baseWeight = this.detectorWeights[name] || 1.0;
      const confidence = result.confidence || 0.8;
      const score = result.score || 0;

      if (score > 0) {
        detectorsTriggered.push(name);
      }

      const effectiveWeight = baseWeight * confidence;
      weightedSum += score * effectiveWeight;
      totalWeight += effectiveWeight;
      confidenceSum += confidence;

      if (score > maxSingleScore) {
        maxSingleScore = score;
      }
    }

    // Extensible ML Slot Weight Integration
    if (mlPrediction && mlPrediction.confidence > 0.5 && mlPrediction.score > 0) {
      const mlWeight = 1.5 * mlPrediction.confidence;
      const mlScore = mlPrediction.score * 100;
      weightedSum += mlScore * mlWeight;
      totalWeight += mlWeight;
      detectorsTriggered.push('MLAdapter');
    }

    let rawScore = totalWeight > 0 ? (weightedSum / totalWeight) : 0;

    // Apply severe finding boost to prevent false negative score dilution
    if (maxSingleScore >= 80) {
      rawScore = Math.max(rawScore, maxSingleScore * 0.85);
    } else if (maxSingleScore >= 40 && rawScore < maxSingleScore * 0.75) {
      rawScore = maxSingleScore * 0.75;
    }

    const finalScore = Math.min(Math.round(rawScore), 100);
    const avgConfidence = parseFloat((confidenceSum / Math.max(detectorOutputs.length, 1)).toFixed(2));
    const classification = this._classifyScore(finalScore);

    return {
      riskScore: finalScore,
      confidence: avgConfidence,
      classification,
      detectorsTriggered
    };
  }

  /**
   * @private
   */
  _classifyScore(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'SAFE';
  }
}
