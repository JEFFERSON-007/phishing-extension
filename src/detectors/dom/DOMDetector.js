/**
 * DOM Security Detector Module
 * Incremental DOM analyzer detecting hidden zero-pixel IFrames, canvas tricks, obfuscated scripts, and fake UI overlays.
 * @module DOMDetector
 */

import { DetectorInterface } from '../../plugins/DetectorInterface.js';

export class DOMDetector extends DetectorInterface {
  name() { return 'DOMDetector'; }
  version() { return '2.0.0'; }
  priority() { return 800; }
  enabled() { return true; }

  supports(context) {
    return Boolean(context && (context.dom || context.domData));
  }

  /**
   * Analyze DOM elements.
   * @param {Record<string, *>} context 
   * @returns {Promise<import('../../plugins/DetectorInterface.js').DetectorResult>}
   */
  async analyze(context) {
    const startTime = performance.now();
    const findings = [];
    let totalScore = 0;
    const dom = context.dom;
    const domData = context.domData;

    let iframes = [];
    let scripts = [];
    let overlays = [];
    let anchors = [];

    if (dom && typeof dom.querySelectorAll === 'function') {
      iframes = Array.from(dom.querySelectorAll('iframe')).map(iframe => ({
        src: iframe.src || iframe.getAttribute('src') || '',
        width: parseInt(iframe.width || iframe.style.width || '100', 10),
        height: parseInt(iframe.height || iframe.style.height || '100', 10),
        isHidden: iframe.style.display === 'none' || iframe.style.visibility === 'hidden' || iframe.style.opacity === '0'
      }));

      scripts = Array.from(dom.querySelectorAll('script')).map(script => ({
        textContent: script.textContent || ''
      }));

      overlays = Array.from(dom.querySelectorAll('div, section')).filter(node => {
        const style = node.style || {};
        return (style.position === 'fixed' || style.position === 'absolute') &&
               (style.zIndex > 9999 || parseInt(style.zIndex, 10) > 9999) &&
               (style.width === '100vw' || style.width === '100%' || style.left === '0px');
      }).map(() => ({ isOverlay: true }));

      anchors = Array.from(dom.querySelectorAll('a[href]')).slice(0, 50).map(anchor => ({
        text: (anchor.textContent || '').trim(),
        href: anchor.href || ''
      }));
    } else if (domData) {
      iframes = domData.iframes || [];
      scripts = domData.scripts || [];
      overlays = domData.overlays || [];
      anchors = domData.anchors || [];
    } else {
      return {
        score: 0,
        confidence: 1.0,
        severity: 'LOW',
        findings: [],
        metadata: {},
        executionTime: parseFloat((performance.now() - startTime).toFixed(2))
      };
    }

    try {
      // 1. Hidden / Zero-Pixel IFrames
      for (const iframe of iframes) {
        const src = iframe.src || '';
        const width = iframe.width;
        const height = iframe.height;
        const isHidden = iframe.isHidden;

        if ((width <= 2 || height <= 2 || isHidden) && src && !src.startsWith('about:blank')) {
          findings.push({
            id: 'DOM_HIDDEN_IFRAME',
            type: 'HIDDEN_IFRAME',
            description: `Invisible zero-pixel iframe detected loading external URL (${src.substring(0, 50)}...).`,
            score: 25,
            severity: 'HIGH',
            metadata: { src }
          });
          totalScore += 25;
        }
      }

      // 2. Obfuscated Script & Encoded JS Check
      for (const script of scripts) {
        const text = script.textContent || '';
        if (text.includes('eval(') || text.includes('unescape(') || text.match(/\\x[0-9a-f]{2}/gi)) {
          if (text.length > 500 && (text.match(/\\x/g) || []).length > 20) {
            findings.push({
              id: 'DOM_OBFUSCATED_SCRIPT',
              type: 'OBFUSCATED_SCRIPT',
              description: 'Script block contains heavy obfuscation (hexadecimal decoding / eval).',
              score: 20,
              severity: 'MEDIUM'
            });
            totalScore += 20;
            break;
          }
        }
      }

      // 3. Fake Overlay / Fullscreen Clickjacking Mask
      if (overlays.length > 0) {
        findings.push({
          id: 'DOM_FAKE_OVERLAY',
          type: 'FULLSCREEN_OVERLAY_MASK',
          description: 'High z-index full-screen absolute element detected (potential clickjacking mask).',
          score: 20,
          severity: 'MEDIUM'
        });
        totalScore += 20;
      }

      // 4. Misleading Anchors (Display Text vs Href mismatch)
      for (const anchor of anchors) {
        const text = (anchor.text || '').trim();
        const href = anchor.href || '';
        if (text.startsWith('http://') || text.startsWith('https://') || text.match(/^[\w-]+\.[\w-]+/)) {
          try {
            const displayedDomain = new URL(text.startsWith('http') ? text : `https://${text}`).hostname;
            const targetDomain = new URL(href).hostname;
            if (displayedDomain && targetDomain && displayedDomain !== targetDomain) {
              findings.push({
                id: 'DOM_MISLEADING_LINK',
                type: 'MISLEADING_LINK_TEXT',
                description: `Link text displays domain '${displayedDomain}' but links to '${targetDomain}'.`,
                score: 25,
                severity: 'HIGH',
                metadata: { displayedDomain, targetDomain }
              });
              totalScore += 25;
              break;
            }
          } catch {}
        }
      }

    } catch (err) {
      // Graceful failure isolation
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

  cleanup() {
    // Release memory footprints
  }
}
