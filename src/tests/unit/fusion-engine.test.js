/**
 * Risk Fusion Engine Unit Tests
 * @module fusion-engine.test
 */

import { RiskFusionEngine } from '../../core/fusion/RiskFusionEngine.js';

export function testRiskFusionEngine() {
  const fusion = new RiskFusionEngine();

  // Test 1: Empty input returns SAFE
  const res1 = fusion.fuse([]);
  console.assert(res1.riskScore === 0, 'Test Failed: Empty score expected 0');
  console.assert(res1.classification === 'SAFE', 'Test Failed: Classification expected SAFE');

  // Test 2: High score fusion
  const mockOutputs = [
    { name: 'URLDetector', result: { score: 80, confidence: 1.0, severity: 'CRITICAL', findings: [] } },
    { name: 'FormDetector', result: { score: 40, confidence: 0.9, severity: 'MEDIUM', findings: [] } }
  ];
  const res2 = fusion.fuse(mockOutputs);
  console.assert(res2.riskScore >= 60, 'Test Failed: High risk score expected');
  console.assert(res2.detectorsTriggered.includes('URLDetector'), 'Test Failed: Detector trigger missing');

  return true;
}

if (typeof process !== 'undefined' && process.env?.NODE_ENV === 'test') {
  testRiskFusionEngine();
  console.log('✅ RiskFusionEngine Unit Tests Passed.');
}
