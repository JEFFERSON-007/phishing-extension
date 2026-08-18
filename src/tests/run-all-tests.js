/**
 * Comprehensive Test Runner Suite
 * Runs unit tests, integration tests, and edge case regression verifications.
 * @module run-all-tests
 */

import { testURLDetector } from './unit/url-detector.test.js';
import { testRiskFusionEngine } from './unit/fusion-engine.test.js';
import { testDetectionPipeline } from './integration/detection-pipeline.test.js';

import { URLDetector } from '../detectors/url/URLDetector.js';
import { DOMDetector } from '../detectors/dom/DOMDetector.js';
import { MultiLayerCache } from '../cache/MultiLayerCache.js';
import { RiskFusionEngine } from '../core/fusion/RiskFusionEngine.js';

export async function runAllTests() {
  console.log('🧪 Starting Phishing Extension Test Suite...\n');

  let passed = 0;
  let failed = 0;

  async function assertAsync(testName, fn) {
    try {
      await fn();
      console.log(`  ✅ PASSED: ${testName}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ FAILED: ${testName}`);
      console.error(`     ${err.message}`);
      failed++;
    }
  }

  console.log('--- 1. Unit Tests ---');
  await assertAsync('URLDetector Unit Tests', async () => {
    const res = await testURLDetector();
    if (!res) throw new Error('testURLDetector returned false');
  });

  await assertAsync('RiskFusionEngine Unit Tests', async () => {
    const res = testRiskFusionEngine();
    if (!res) throw new Error('testRiskFusionEngine returned false');
  });

  console.log('\n--- 2. Integration Tests ---');
  await assertAsync('Detection Pipeline Integration Test', async () => {
    const res = await testDetectionPipeline();
    if (!res) throw new Error('testDetectionPipeline returned false');
  });

  console.log('\n--- 3. Edge Case Regression Tests ---');
  
  await assertAsync('URLDetector: Typosquatting (g00gle.com)', async () => {
    const detector = new URLDetector();
    const result = await detector.analyze({ url: 'http://g00gle.com/login' });
    if (result.score < 35) throw new Error(`Expected score >= 35, got ${result.score}`);
    if (!result.findings.some(f => f.type === 'TYPOSQUATTING_ATTACK')) {
      throw new Error('Expected TYPOSQUATTING_ATTACK finding missing');
    }
  });

  await assertAsync('URLDetector: Typosquatting (paypa1.com)', async () => {
    const detector = new URLDetector();
    const result = await detector.analyze({ url: 'https://paypa1.com/verify' });
    if (result.score < 35) throw new Error(`Expected score >= 35, got ${result.score}`);
    if (!result.findings.some(f => f.type === 'TYPOSQUATTING_ATTACK')) {
      throw new Error('Expected TYPOSQUATTING_ATTACK finding missing');
    }
  });

  await assertAsync('DOMDetector: Serialized domData Processing', async () => {
    const detector = new DOMDetector();
    const context = {
      domData: {
        iframes: [{ src: 'http://malicious-iframe.com/login', width: 0, height: 0, isHidden: true }],
        scripts: [],
        overlays: [],
        anchors: []
      }
    };
    const result = await detector.analyze(context);
    if (result.score < 25) throw new Error(`Expected score >= 25, got ${result.score}`);
    if (!result.findings.some(f => f.type === 'HIDDEN_IFRAME')) {
      throw new Error('Expected HIDDEN_IFRAME finding missing');
    }
  });

  await assertAsync('MultiLayerCache: has() Non-Mutating Hit Counter', () => {
    const cache = new MultiLayerCache(10, 60000);
    cache.set('key1', 'val1');
    const initialStats = cache.getStats();
    if (initialStats.hits !== 0) throw new Error('Hits should start at 0');

    const exists = cache.has('key1');
    if (!exists) throw new Error('Key should exist in cache');

    const afterHasStats = cache.getStats();
    if (afterHasStats.hits !== 0) throw new Error(`has() inflated hits to ${afterHasStats.hits}`);
  });

  await assertAsync('RiskFusionEngine: Critical Score Dilution Prevention', () => {
    const fusion = new RiskFusionEngine();
    const mockOutputs = [
      { name: 'URLDetector', result: { score: 90, confidence: 1.0, severity: 'CRITICAL', findings: [] } },
      { name: 'FormDetector', result: { score: 0, confidence: 1.0, severity: 'LOW', findings: [] } },
      { name: 'DOMDetector', result: { score: 0, confidence: 1.0, severity: 'LOW', findings: [] } },
      { name: 'BehaviorDetector', result: { score: 0, confidence: 1.0, severity: 'LOW', findings: [] } }
    ];
    const fused = fusion.fuse(mockOutputs);
    if (fused.riskScore < 75) {
      throw new Error(`Fused riskScore diluted too low: ${fused.riskScore}`);
    }
    if (fused.classification !== 'CRITICAL' && fused.classification !== 'HIGH') {
      throw new Error(`Expected CRITICAL or HIGH classification, got ${fused.classification}`);
    }
  });

  await assertAsync('BrandImpersonationDetector: Domain Keyword Spoofing', async () => {
    const BrandImpersonationDetectorModule = await import('../detectors/brand/BrandImpersonationDetector.js');
    const detector = new BrandImpersonationDetectorModule.BrandImpersonationDetector();
    const result = await detector.analyze({ url: 'http://paypal-security-update.com/login', title: 'Security Alert' });
    if (result.score < 30) throw new Error(`Expected score >= 30, got ${result.score}`);
    if (!result.findings.some(f => f.type === 'BRAND_DOMAIN_SPOOFING')) {
      throw new Error('Expected BRAND_DOMAIN_SPOOFING finding missing');
    }
  });

  console.log(`\n========================================`);
  console.log(`📊 Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  return failed === 0;
}

if (typeof process !== 'undefined' && process.env?.NODE_ENV === 'test') {
  runAllTests();
}
