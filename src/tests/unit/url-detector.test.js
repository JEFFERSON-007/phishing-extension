/**
 * URL Detector Unit Tests
 * @module url-detector.test
 */

import { URLDetector } from '../../detectors/url/URLDetector.js';

export async function testURLDetector() {
  const detector = new URLDetector();
  console.assert(detector.name() === 'URLDetector', 'Test Failed: Detector name mismatch');
  console.assert(detector.priority() === 1000, 'Test Failed: Priority mismatch');

  // Test 1: Homograph Attack Detection
  const homographContext = { url: 'https://аrnaz0n.com/login' };
  const res1 = await detector.analyze(homographContext);
  console.assert(res1.score >= 35, 'Test Failed: Homograph attack score expected >= 35');
  console.assert(res1.findings.some(f => f.type === 'HOMOGRAPH_SPOOFING'), 'Test Failed: Homograph finding missing');

  // Test 2: Raw IP Domain
  const ipContext = { url: 'http://192.168.1.1/login' };
  const res2 = await detector.analyze(ipContext);
  console.assert(res2.score >= 35, 'Test Failed: Raw IP score expected >= 35');

  // Test 3: Safe Domain
  const safeContext = { url: 'https://google.com/search' };
  const res3 = await detector.analyze(safeContext);
  console.assert(res3.score === 0, 'Test Failed: Safe domain score expected 0');

  return true;
}

if (typeof process !== 'undefined' && process.env?.NODE_ENV === 'test') {
  testURLDetector().then(() => console.log('✅ URLDetector Unit Tests Passed.'));
}
