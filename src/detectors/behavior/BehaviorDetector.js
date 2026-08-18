/**
 * Behavioral Security Detector Module
 * Monitors runtime API usage, clipboard manipulation, popup spam, notification abuse, auto-submits, and device permission requests.
 * @module BehaviorDetector
 */

import { DetectorInterface } from '../../plugins/DetectorInterface.js';

export class BehaviorDetector extends DetectorInterface {
  name() { return 'BehaviorDetector'; }
  version() { return '2.0.0'; }
  priority() { return 700; }
  enabled() { return true; }

  supports(context) {
    return Boolean(context && (context.behavior || context.dom || typeof window !== 'undefined'));
  }

  /**
   * Analyze runtime behavioral flags.
   * @param {Record<string, *>} context 
   * @returns {Promise<import('../../plugins/DetectorInterface.js').DetectorResult>}
   */
  async analyze(context) {
    const startTime = performance.now();
    const findings = [];
    let totalScore = 0;
    const behavior = context.behavior || {};

    // 1. Clipboard Hijacking & Unauthorized Access
    if (behavior.clipboardAccess || behavior.clipboardWriteOnCopy) {
      findings.push({
        id: 'BEHAVIOR_CLIPBOARD_HIJACK',
        type: 'CLIPBOARD_HIJACKING',
        description: 'Page overrides clipboard events or requests background clipboard access.',
        score: 15,
        severity: 'MEDIUM'
      });
      totalScore += 15;
    }

    // 2. Disabled Right-Click / Context Menu Restriction
    if (behavior.rightClickDisabled) {
      findings.push({
        id: 'BEHAVIOR_RIGHT_CLICK_DISABLED',
        type: 'CONTEXT_MENU_RESTRICTED',
        description: 'Page restricts right-click context menu (technique used to impede developer tools inspection).',
        score: 10,
        severity: 'LOW'
      });
      totalScore += 10;
    }

    // 3. Popup Spam & Auto Window Openers
    if (behavior.popupCount && behavior.popupCount > 2) {
      findings.push({
        id: 'BEHAVIOR_POPUP_SPAM',
        type: 'POPUP_SPAM',
        description: `Multiple automated popup windows triggered (${behavior.popupCount}).`,
        score: 20,
        severity: 'HIGH'
      });
      totalScore += 20;
    }

    // 4. Auto Submit Form / Immediate Script Redirect
    if (behavior.autoSubmitForm) {
      findings.push({
        id: 'BEHAVIOR_AUTO_SUBMIT',
        type: 'AUTO_SUBMIT_FORM',
        description: 'Form automatically submitted via JavaScript immediately upon page load.',
        score: 25,
        severity: 'HIGH'
      });
      totalScore += 25;
    }

    // 5. Hardware / Sensor Device API Request (WebUSB, Bluetooth, WebRTC)
    if (behavior.requestedSensitiveAPIs && Array.isArray(behavior.requestedSensitiveAPIs)) {
      for (const api of behavior.requestedSensitiveAPIs) {
        if (typeof api !== 'string') continue;
        findings.push({
          id: `BEHAVIOR_SENSITIVE_API_${api.toUpperCase()}`,
          type: 'SENSITIVE_API_REQUEST',
          description: `Page requested access to sensitive browser API: ${api}.`,
          score: 15,
          severity: 'MEDIUM'
        });
        totalScore += 15;
      }
    }

    const finalScore = Math.min(totalScore, 100);
    const severity = finalScore >= 80 ? 'CRITICAL' : finalScore >= 60 ? 'HIGH' : finalScore >= 40 ? 'MEDIUM' : 'LOW';
    const executionTime = parseFloat((performance.now() - startTime).toFixed(2));

    return {
      score: finalScore,
      confidence: 0.8,
      severity,
      findings,
      metadata: { detector: this.name() },
      executionTime
    };
  }
}
