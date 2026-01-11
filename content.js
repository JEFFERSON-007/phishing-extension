/**
 * Content Script - Refactored
 * Monitors pages for phishing attempts with proper cleanup
 * @module content
 */

// Lazy-loaded detector instance
let detector = null;
let currentAnalysis = null;
let isWarningDisplayed = false;
let mutationObserver = null;
let debouncedAnalyze = null;

// Dismissed warnings for this session
const dismissedWarnings = new Set();

// Configuration (will be available globally from injected script)
const CONFIG = typeof window.CONFIG !== 'undefined' ? window.CONFIG : null;
const Logger = typeof window.Logger !== 'undefined' ? window.Logger : console;

/**
 * Initialize detector (lazy loading)
 * @returns {PhishingDetector} Detector instance
 */
function getDetector() {
    if (!detector && typeof PhishingDetector !== 'undefined' && CONFIG) {
        detector = new PhishingDetector(CONFIG);
        Logger.debug('Detector instance created');
    }
    return detector;
}

/**
 * Analyze the current page
 * @returns {Object|null} Analysis result
 */
function analyzePage() {
    console.log('🔎 Starting page analysis...');

    try {
        const det = getDetector();
        if (!det) {
            console.warn('⚠️ Detector not available');
            Logger.warn('Detector not available');
            return null;
        }

        const url = window.location.href;
        console.log('  - Analyzing URL:', url);

        currentAnalysis = det.analyze(url, document);

        console.log('  - Analysis complete:', {
            level: currentAnalysis.level,
            score: currentAnalysis.score,
            threats: currentAnalysis.threats.length
        });

        // Send results to background script
        chrome.runtime.sendMessage({
            type: 'ANALYSIS_COMPLETE',
            data: currentAnalysis,
            url: url
        }).catch(err => {
            console.warn('Failed to send analysis to background:', err);
            Logger.warn('Failed to send analysis:', err);
        });

        // Show warning if significant risk
        if (currentAnalysis.level !== 'safe' && currentAnalysis.level !== 'low') {
            console.log('⚠️ Showing warning for risk level:', currentAnalysis.level);
            showWarning(currentAnalysis);
        } else {
            console.log('✅ Site appears safe');
        }

        return currentAnalysis;

    } catch (error) {
        console.error('❌ Page analysis error:', error);
        Logger.error('Page analysis error:', error);
        return null;
    }
}

/**
 * Show warning overlay
 * @param {Object} analysis - Analysis result
 */
function showWarning(analysis) {
    if (!CONFIG?.FEATURES.ENABLE_SHADOW_DOM_PROTECTION) return;
    if (isWarningDisplayed) return;

    // Check if already dismissed
    const urlKey = window.location.href;
    if (dismissedWarnings.has(urlKey)) return;

    try {
        // Create overlay
        const overlay = createWarningOverlay(analysis);

        // Use Shadow DOM for protection
        const host = document.createElement('div');
        host.id = 'phishing-detector-host';
        host.setAttribute('style', 'all: initial; position: fixed; inset: 0; z-index: 2147483647;');

        const shadow = host.attachShadow({ mode: 'closed' });

        // Add styles
        const style = document.createElement('style');
        style.textContent = getWarningStyles();
        shadow.appendChild(style);

        shadow.appendChild(overlay);
        document.body.appendChild(host);

        isWarningDisplayed = true;
        Logger.info('Warning overlay displayed');

    } catch (error) {
        Logger.error('Failed to show warning:', error);
    }
}

/**
 * Create warning overlay element
 * @param {Object} analysis - Analysis result
 * @returns {HTMLElement} Overlay element
 */
function createWarningOverlay(analysis) {
    // Get warning info
    const warningInfo = getWarningInfo(analysis.level);

    const overlay = document.createElement('div');
    overlay.id = 'phishing-detector-overlay';
    overlay.className = `phishing-warning phishing-warning-${analysis.level}`;

    overlay.innerHTML = `
    <div class="phishing-warning-backdrop"></div>
    <div class="phishing-warning-content">
      <div class="phishing-warning-header">
        <div class="phishing-warning-icon" style="color: ${warningInfo.iconColor}">
          <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
            <path d="M12 8v4M12 16h.01"/>
          </svg>
        </div>
        <h2 class="phishing-warning-title">${warningInfo.title}</h2>
      </div>
      
      <p class="phishing-warning-message">${warningInfo.message}</p>
      
      <div class="phishing-warning-details">
        <div class="phishing-warning-score">
          <span class="phishing-warning-score-label">Risk Score:</span>
          <span class="phishing-warning-score-value">${analysis.score}/100</span>
        </div>
        
        ${analysis.threats.length > 0 ? createThreatsHTML(analysis.threats) : ''}
      </div>
      
      <div class="phishing-warning-actions">
        <button id="phishing-warning-goback" class="phishing-btn phishing-btn-primary">
          ← Go Back to Safety
        </button>
        <button id="phishing-warning-proceed" class="phishing-btn phishing-btn-secondary">
          I Understand the Risks, Proceed Anyway
        </button>
      </div>
      
      <div class="phishing-warning-footer">
        <small>Protected by Phishing Detector Extension</small>
      </div>
    </div>
  `;

    // Attach event listeners
    attachWarningListeners(overlay);

    return overlay;
}

/**
 * Get warning info based on risk level
 * @param {string} level - Risk level
 * @returns {Object} Warning info
 */
function getWarningInfo(level) {
    const warnings = {
        critical: {
            title: '🛑 Critical Security Warning',
            message: 'This website shows serious signs of being a phishing or scam site. We strongly recommend leaving immediately.',
            iconColor: '#dc2626'
        },
        high: {
            title: '⚠️ High Risk Warning',
            message: 'This website has multiple suspicious characteristics. Exercise extreme caution.',
            iconColor: '#ea580c'
        },
        medium: {
            title: '⚡ Security Alert',
            message: 'This website has some suspicious characteristics. Please verify before entering any personal information.',
            iconColor: '#f59e0b'
        }
    };

    return warnings[level] || {
        title: 'ℹ️ Security Notice',
        message: 'Some potentially suspicious activity detected on this page.',
        iconColor: '#3b82f6'
    };
}

/**
 * Create threats HTML
 * @param {Array} threats - List of threats
 * @returns {string} HTML string
 */
function createThreatsHTML(threats) {
    const maxDisplay = CONFIG?.PERFORMANCE.MAX_THREATS_DISPLAY || 5;
    const displayThreats = threats.slice(0, maxDisplay);
    const remaining = threats.length - maxDisplay;

    return `
    <div class="phishing-warning-threats">
      <strong>Detected Threats:</strong>
      <ul>
        ${displayThreats.map((threat, idx) =>
        `<li><span class="threat-badge">${idx + 1}</span> ${threat}</li>`
    ).join('')}
        ${remaining > 0 ? `<li style="margin-top: 8px; opacity: 0.7;">...and ${remaining} more threat(s)</li>` : ''}
      </ul>
      <div class="phishing-warning-tip">
        <strong>💡 Tip:</strong> Legitimate companies never ask for passwords via email or unfamiliar websites.
      </div>
    </div>
  `;
}

/**
 * Attach event listeners to warning overlay
 * @param {HTMLElement} overlay - Overlay element
 */
function attachWarningListeners(overlay) {
    // Use RAF to ensure DOM is ready
    requestAnimationFrame(() => {
        const goBackBtn = overlay.querySelector('#phishing-warning-goback');
        const proceedBtn = overlay.querySelector('#phishing-warning-proceed');

        goBackBtn?.addEventListener('click', () => {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.close();
            }
        });

        proceedBtn?.addEventListener('click', () => {
            dismissedWarnings.add(window.location.href);
            removeWarningOverlay();
        });
    });
}

/**
 * Remove warning overlay
 */
function removeWarningOverlay() {
    const host = document.getElementById('phishing-detector-host');
    if (host) {
        host.remove();
    }
    isWarningDisplayed = false;
}

/**
 * Get warning styles (inline for Shadow DOM)
 * @returns {string} CSS styles
 */
function getWarningStyles() {
    // Return inline CSS for Shadow DOM
    return ` 
    #phishing-detector-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      animation: fade-in 0.3s ease-out;
    }
    @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
    .phishing-warning-backdrop {
      position: absolute;
      inset: 0;
      background: rgba(0, 0, 0, 0.85);
      backdrop-filter: blur(8px);
    }
    .phishing-warning-content {
      position: relative;
      max-width: 600px;
      margin: 100px auto;
      background: white;
      border-radius: 16px;
      padding: 40px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      animation: slide-up 0.4s ease-out;
    }
    @keyframes slide-up { from { transform: translateY(50px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    .phishing-warning-header { text-align: center; margin-bottom: 24px; }
    .phishing-warning-icon { width: 64px; height: 64px; margin: 0 auto 16px; animation: pulse 2s ease-in-out infinite; }
    @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.1); } }
    .phishing-warning-title { font-size: 28px; font-weight: 700; margin: 0; color: #1f2937; }
    .phishing-warning-message { font-size: 16px; line-height: 1.6; color: #4b5563; text-align: center; margin-bottom: 24px; }
    .phishing-warning-details { background: #f9fafb; border-radius: 12px; padding: 20px; margin-bottom: 24px; }
    .phishing-warning-score { display: flex; justify-content: space-between; align-items: center; padding-bottom: 16px; margin-bottom: 16px; border-bottom: 2px solid #e5e7eb; }
    .phishing-warning-score-label { font-weight: 600; color: #374151; font-size: 16px; }
    .phishing-warning-score-value { font-size: 24px; font-weight: 700; color: #dc2626; }
    .phishing-warning-threats { color: #374151; }
    .phishing-warning-threats strong { display: block; margin-bottom: 8px; color: #1f2937; }
    .phishing-warning-threats ul { margin: 0; padding-left: 0; list-style: none; }
    .phishing-warning-threats li { margin: 6px 0; font-size: 14px; color: #6b7280; display: flex; align-items: center; }
    .threat-badge { display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; background: rgba(255, 255, 255, 0.2); border-radius: 50%; font-size: 11px; font-weight: bold; margin-right: 8px; background: #fee2e2; color: #dc2626; }
    .phishing-warning-tip { margin-top: 12px; padding: 10px; background: rgba(59, 130, 246, 0.1); border-left: 3px solid #3b82f6; border-radius: 4px; font-size: 13px; color: #1f2937; }
    .phishing-warning-actions { display: flex; gap: 12px; margin-bottom: 20px; }
    .phishing-btn { flex: 1; padding: 14px 24px; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s ease; }
    .phishing-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15); }
    .phishing-btn:active { transform: translateY(0); }
    .phishing-btn-primary { background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); color: white; }
    .phishing-btn-primary:hover { background: linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%); }
    .phishing-btn-secondary { background: white; color: #6b7280; border: 2px solid #e5e7eb; }
    .phishing-btn-secondary:hover { border-color: #d1d5db; color: #4b5563; }
    .phishing-warning-footer { text-align: center; color: #9ca3af; font-size: 12px; }
    .phishing-warning-critical .phishing-warning-content { border: 3px solid #dc2626; }
    .phishing-warning-high .phishing-warning-content { border: 3px solid #ea580c; }
    .phishing-warning-medium .phishing-warning-content { border: 3px solid #f59e0b; }
    @media (max-width: 640px) {
      .phishing-warning-content { margin: 20px; padding: 24px; max-width: none; }
      .phishing-warning-title { font-size: 22px; }
      .phishing-warning-actions { flex-direction: column; }
    }
  `;
}

/**
 * Start monitoring page for changes
 */
function startMonitoring() {
    // Initial analysis
    analyzePage();

    if (!CONFIG?.FEATURES.ENABLE_MUTATION_OBSERVER) return;

    // Create debounced analyze function
    if (typeof debounce !== 'undefined' && CONFIG) {
        debouncedAnalyze = debounce(analyzePage, CONFIG.PERFORMANCE.REANALYSIS_DEBOUNCE_MS);
    }

    // Monitor significant DOM changes
    mutationObserver = new MutationObserver((mutations) => {
        if (!shouldReanalyze(mutations)) return;

        if (debouncedAnalyze) {
            debouncedAnalyze();
        } else {
            analyzePage();
        }
    });

    // Start observing
    mutationObserver.observe(document.body, {
        childList: true,
        subtree: true
    });
}

/**
 * Check if mutations warrant re-analysis
 * @param {Array} mutations - Mutation records
 * @returns {boolean} True if should reanalyze
 */
function shouldReanalyze(mutations) {
    for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
            if (node.nodeType !== 1) continue; // Only element nodes

            // Check for forms, iframes, or scripts
            if (node.tagName === 'FORM' ||
                node.tagName === 'IFRAME' ||
                node.tagName === 'SCRIPT' ||
                node.querySelector?.('form, iframe, script')) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Monitor form submissions
 */
function monitorForms() {
    if (!CONFIG?.FEATURES.ENABLE_FORM_MONITORING) return;

    document.addEventListener('submit', (e) => {
        const form = e.target;
        if (form.tagName !== 'FORM') return;

        // Check if submitting on risky site
        if (currentAnalysis && currentAnalysis.level !== 'safe' && currentAnalysis.level !== 'low') {
            const inputs = form.querySelectorAll('input');
            let hasSensitiveData = false;

            for (const input of inputs) {
                if (input.type === 'password' || input.type === 'email') {
                    hasSensitiveData = true;
                    break;
                }
            }

            if (hasSensitiveData) {
                const confirmed = confirm(
                    '⚠️ Phishing Detector Warning!\n\n' +
                    'You are about to submit sensitive information to a potentially dangerous website.\n\n' +
                    `Risk Level: ${currentAnalysis.level.toUpperCase()}\n` +
                    `Risk Score: ${currentAnalysis.score}/100\n\n` +
                    'Are you sure you want to continue?'
                );

                if (!confirmed) {
                    e.preventDefault();
                    e.stopPropagation();
                    return false;
                }
            }
        }
    }, true);
}

/**
 * Listen for messages from background script
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    try {
        if (message.type === 'ANALYZE_PAGE') {
            const result = analyzePage();
            sendResponse(result);

        } else if (message.type === 'GET_ANALYSIS') {
            sendResponse(currentAnalysis);
        }

    } catch (error) {
        Logger.error('Message handler error:', error);
        sendResponse({ error: error.message });
    }

    return true;
});

/**
 * Cleanup function
 */
function cleanup() {
    if (mutationObserver) {
        mutationObserver.disconnect();
        mutationObserver = null;
    }

    removeWarningOverlay();
    Logger.debug('Content script cleaned up');
}

/**
 * Initialize when page loads
 */
function init() {
    console.log('🔍 Phishing Detector Content Script Loading...');
    console.log('  - URL:', window.location.href);
    console.log('  - CONFIG available:', typeof CONFIG !== 'undefined');
    console.log('  - PhishingDetector available:', typeof PhishingDetector !== 'undefined');
    console.log('  - Logger available:', typeof Logger !== 'undefined');

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            console.log('📄 DOM loaded, starting monitoring');
            startMonitoring();
            monitorForms();
        });
    } else {
        console.log('📄 DOM already loaded, starting monitoring');
        startMonitoring();
        monitorForms();
    }

    // Cleanup on unload
    window.addEventListener('beforeunload', cleanup);

    console.log('✅ Content script initialized');
}

// Start initialization
init();

Logger.debug('Content script loaded');
