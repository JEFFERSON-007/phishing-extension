/**
 * Content Script (DOM Observer & Shadow DOM Isolator)
 * Incremental TreeWalker DOM scanner, behavioral event tracker, and anti-tamper Shadow DOM overlay manager.
 * @module content-script
 */

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__PHISHING_DETECTOR_INJECTED__) return;
  window.__PHISHING_DETECTOR_INJECTED__ = true;

  const behavioralFlags = {
    clipboardAccess: false,
    rightClickDisabled: false,
    autoSubmitForm: false,
    popupCount: 0,
    requestedSensitiveAPIs: []
  };

  // Listen for context menu restrictions
  document.addEventListener('contextmenu', () => {
    behavioralFlags.rightClickDisabled = true;
  }, true);

  // Listen for clipboard events
  document.addEventListener('copy', () => {
    behavioralFlags.clipboardAccess = true;
  }, true);

  /**
   * Extract DOM context payload for detection engine.
   * @returns {Record<string, *>}
   */
  function extractDOMContext() {
    const forms = Array.from(document.forms || []).map(form => ({
      action: form.action || '',
      method: form.method || 'get',
      inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(input => ({
        type: input.type || 'text',
        name: input.name || '',
        id: input.id || '',
        placeholder: input.placeholder || '',
        isHidden: input.type === 'hidden' || input.style.display === 'none' || input.style.visibility === 'hidden',
        isOffScreen: input.offsetWidth === 0 && input.offsetHeight === 0
      }))
    }));

    return {
      url: location.href,
      title: document.title,
      dom: document.documentElement,
      forms,
      behavior: { ...behavioralFlags }
    };
  }

  /**
   * Request page analysis from background service worker.
   */
  function triggerPageAnalysis() {
    const context = extractDOMContext();
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({ action: 'ANALYZE_PAGE', context }, (response) => {
        if (chrome.runtime.lastError) {
          return; // Ignore disconnect error silently
        }
        if (response && response.success && response.result) {
          const result = response.result;
          if (result.riskScore >= 60) {
            renderShadowDOMWarningOverlay(result);
          }
        }
      });
    }
  }

  // Listen for rescan trigger messages from popup or background
  if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'TRIGGER_DOM_SCAN') {
        triggerPageAnalysis();
        sendResponse({ success: true });
        return true;
      }
    });
  }

  /**
   * Render isolated Shadow DOM warning overlay on top of dangerous page.
   * @param {Record<string, *>} result 
   */
  function renderShadowDOMWarningOverlay(result) {
    if (document.getElementById('phishing-detector-root')) return;

    const host = document.createElement('div');
    host.id = 'phishing-detector-root';
    host.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:2147483647;pointer-events:all;';

    const shadow = host.attachShadow({ mode: 'closed' });

    shadow.innerHTML = `
      <style>
        .overlay-container {
          width: 100%;
          height: 100%;
          background: rgba(15, 23, 42, 0.95);
          backdrop-filter: blur(12px);
          display: flex;
          align-items: center;
          justify-content: center;
          color: #f8fafc;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          box-sizing: border-box;
          padding: 2rem;
        }
        .card {
          background: #1e293b;
          border: 1px solid #334155;
          border-radius: 16px;
          max-width: 600px;
          width: 100%;
          padding: 2rem;
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
          text-align: center;
        }
        .icon { font-size: 3.5rem; margin-bottom: 1rem; }
        .title { font-size: 1.75rem; font-weight: 700; color: #ef4444; margin-bottom: 0.5rem; }
        .score { font-size: 1.1rem; color: #94a3b8; margin-bottom: 1.5rem; }
        .reasons { text-align: left; background: #0f172a; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; font-size: 0.9rem; max-height: 150px; overflow-y: auto; }
        .reason-item { color: #f8fafc; margin-bottom: 0.5rem; }
        .btn-group { display: flex; gap: 1rem; justify-content: center; }
        .btn-back { background: #3b82f6; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; cursor: pointer; }
        .btn-proceed { background: transparent; color: #94a3b8; border: 1px solid #475569; padding: 0.75rem 1.5rem; border-radius: 8px; cursor: pointer; }
      </style>
      <div class="overlay-container">
        <div class="card">
          <div class="icon">🛡️</div>
          <div class="title">Security Warning: High Risk Site</div>
          <div class="score">Threat Risk Score: <strong>${result.riskScore}/100</strong> (${result.classification})</div>
          <div class="reasons">
            ${(result.reasons || []).map(r => `<div class="reason-item">• ${r}</div>`).join('')}
          </div>
          <div class="btn-group">
            <button class="btn-back" id="btn-back">Go Back to Safety</button>
            <button class="btn-proceed" id="btn-proceed">Proceed (Unsafe)</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(host);

    shadow.getElementById('btn-back').addEventListener('click', () => {
      window.history.back();
    });

    shadow.getElementById('btn-proceed').addEventListener('click', () => {
      if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ action: 'ALLOW_SESSION_DOMAIN', domain: location.hostname }, () => {
          host.remove();
        });
      } else {
        host.remove();
      }
    });
  }

  // Initial Scan at document_end
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', triggerPageAnalysis);
  } else {
    triggerPageAnalysis();
  }
})();
