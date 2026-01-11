/**
 * Warning Page Script - Refactored
 * Displays full-page warning with better UX
 * @module warning
 */

let blockedUrl = '';
let analysisData = null;

// Get URL from query parameters
const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url');

/**
 * Initialize warning page
 */
document.addEventListener('DOMContentLoaded', () => {
    if (targetUrl) {
        blockedUrl = decodeURIComponent(targetUrl);

        // Display URL
        const urlEl = document.getElementById('urlText');
        if (urlEl) {
            urlEl.textContent = blockedUrl;
        }

        // Analyze the blocked URL
        analyzeBlockedUrl();
    } else {
        showError();
    }

    // Setup event listeners
    const goBackBtn = document.getElementById('goBackBtn');
    const proceedBtn = document.getElementById('proceedBtn');

    if (goBackBtn) {
        goBackBtn.addEventListener('click', goBack);
    }

    if (proceedBtn) {
        proceedBtn.addEventListener('click', proceedAnyway);
    }
});

/**
 * Analyze the blocked URL
 */
async function analyzeBlockedUrl() {
    try {
        // Create detector instance if available
        if (typeof PhishingDetector === 'undefined' || typeof CONFIG === 'undefined') {
            console.error('Dependencies not loaded');
            showFallbackWarning();
            return;
        }

        const detector = new PhishingDetector(CONFIG);
        const urlAnalysis = detector._analyzeURL(blockedUrl);

        // Create full analysis structure
        analysisData = {
            score: urlAnalysis.score,
            level: detector._getRiskLevel(urlAnalysis.score),
            threats: urlAnalysis.threats,
            details: { url: urlAnalysis }
        };

        // Display results
        displayAnalysis(analysisData);

    } catch (error) {
        console.error('Analysis error:', error);
        showFallbackWarning();
    }
}

/**
 * Display analysis results
 * @param {Object} analysis - Analysis data
 */
function displayAnalysis(analysis) {
    const { score, level, threats } = analysis;

    // Update header
    updateHeader(level);

    // Animate risk score
    animateRiskScore(score, level);

    // Display threats
    displayThreats(threats);

    // Update security tip
    updateSecurityTip(threats);
}

/**
 * Update header based on risk level
 * @param {string} level - Risk level
 */
function updateHeader(level) {
    const header = document.getElementById('warningHeader');
    const icon = document.getElementById('warningIcon');
    const title = document.getElementById('warningTitle');
    const subtitle = document.getElementById('warningSubtitle');

    if (!header || !icon || !title || !subtitle) return;

    const configs = {
        critical: {
            className: 'warning-header',
            icon: '🛑',
            title: 'Danger: Highly Suspicious Website',
            subtitle: 'This website shows multiple signs of being a phishing or scam site'
        },
        high: {
            className: 'warning-header high',
            icon: '⚠️',
            title: 'Warning: High Risk Website',
            subtitle: 'This website has several suspicious characteristics'
        },
        medium: {
            className: 'warning-header medium',
            icon: '⚡',
            title: 'Caution: Potentially Risky Website',
            subtitle: 'This website has some concerning features'
        }
    };

    const config = configs[level] || configs.medium;

    header.className = config.className;
    icon.textContent = config.icon;
    title.textContent = config.title;
    subtitle.textContent = config.subtitle;
}

/**
 * Animate risk score
 * @param {number} score - Risk score
 * @param {string} level - Risk level
 */
function animateRiskScore(score, level) {
    const scoreValue = document.getElementById('scoreValue');
    const scoreProgress = document.getElementById('scoreProgress');

    if (!scoreValue || !scoreProgress) return;

    // Color based on level
    const colors = {
        safe: '#22c55e',
        low: '#3b82f6',
        medium: '#f59e0b',
        high: '#ea580c',
        critical: '#dc2626'
    };

    const color = colors[level] || '#dc2626';
    scoreProgress.style.stroke = color;

    // Animate number
    let current = 0;
    const increment = score / 50;
    const interval = setInterval(() => {
        current += increment;
        if (current >= score) {
            current = score;
            clearInterval(interval);
        }
        scoreValue.textContent = Math.round(current);
    }, 20);

    // Animate circle
    const circumference = 283;
    const offset = circumference - (score / 100) * circumference;
    setTimeout(() => {
        scoreProgress.style.strokeDashoffset = offset;
        scoreProgress.style.transition = 'stroke-dashoffset 1s ease-out';
    }, 100);
}

/**
 * Display threat list
 * @param {Array} threats - Threats array
 */
function displayThreats(threats) {
    const threatsList = document.getElementById('threatsList');
    if (!threatsList) return;

    threatsList.innerHTML = '';

    if (!threats || threats.length === 0) {
        const li = createElement('li', 'threat-item', `
      <div class="threat-badge">!</div>
      <span>No specific threats detected, but caution advised</span>
    `);
        threatsList.appendChild(li);
        return;
    }

    // Show up to 5 threats
    threats.slice(0, 5).forEach((threat, index) => {
        const li = createElement('li', 'threat-item', `
      <div class="threat-badge">${index + 1}</div>
      <span>${sanitizeHTML(threat)}</span>
    `);
        threatsList.appendChild(li);
    });

    // Add "more" indicator
    if (threats.length > 5) {
        const li = createElement('li', 'threat-item', `
      <div class="threat-badge">+</div>
      <span>...and ${threats.length - 5} more security concerns</span>
    `);
        li.style.opacity = '0.7';
        threatsList.appendChild(li);
    }
}

/**
 * Update security tip based on threats
 * @param {Array} threats - Threats array
 */
function updateSecurityTip(threats) {
    const tipText = document.getElementById('tipText');
    if (!tipText) return;

    const threatsLower = threats.join(' ').toLowerCase();

    if (threatsLower.includes('typo') || threatsLower.includes('homograph')) {
        tipText.textContent = 'This website\'s address closely resembles a legitimate site. Always check the URL carefully before entering any information.';
    } else if (threatsLower.includes('password') || threatsLower.includes('credit')) {
        tipText.textContent = 'This site is requesting sensitive information. Legitimate companies use secure, verified connections and never ask for passwords via email links.';
    } else if (threatsLower.includes('urgency') || threatsLower.includes('immediate')) {
        tipText.textContent = 'Scammers often create false urgency to pressure you into acting quickly. Take your time and verify independently.';
    } else {
        tipText.textContent = 'When in doubt, navigate to the website directly by typing the known address into your browser, rather than clicking links.';
    }
}

/**
 * Go back to safety
 */
function goBack() {
    if (window.history.length > 1) {
        window.history.back();
    } else {
        window.location.href = 'about:blank';
    }
}

/**
 * Proceed to blocked site with confirmation
 */
function proceedAnyway() {
    // Create custom modal dialog
    showConfirmDialog().then(confirmed => {
        if (confirmed && blockedUrl) {
            // Store bypass in chrome storage
            try {
                const bypassKey = CONFIG?.STORAGE_KEYS.BYPASS_PREFIX + blockedUrl;
                chrome.storage.local.set({ [bypassKey]: Date.now() });
            } catch (e) {
                console.error('Storage error:', e);
            }

            // Redirect to blocked URL
            window.location.href = blockedUrl;
        }
    });
}

/**
 * Show custom confirmation dialog
 * @returns {Promise<boolean>} User confirmation
 */
function showConfirmDialog() {
    return new Promise((resolve) => {
        // For now, use native confirm
        // TODO: Replace with custom modal for better UX
        const confirmed = confirm(
            '⚠️ FINAL WARNING\n\n' +
            'You are about to visit a website that was flagged as dangerous.\n\n' +
            'Risk Score: ' + (analysisData?.score || 'Unknown') + '/100\n\n' +
            'Do NOT enter passwords, credit card numbers, or personal information.\n\n' +
            'Are you absolutely sure you want to continue?'
        );

        resolve(confirmed);
    });
}

/**
 * Show fallback warning
 */
function showFallbackWarning() {
    analysisData = {
        score: 80,
        level: 'critical',
        threats: ['Unable to fully analyze - proceeding with caution recommended'],
        details: {}
    };

    displayAnalysis(analysisData);
}

/**
 * Show error state
 */
function showError() {
    const titleEl = document.getElementById('warningTitle');
    if (titleEl) {
        titleEl.textContent = 'Error Loading Warning';
    }

    const subtitleEl = document.getElementById('warningSubtitle');
    if (subtitleEl) {
        subtitleEl.textContent = 'Unable to display security warning';
    }
}

/**
 * Create element with className and innerHTML
 * @param {string} tag - HTML tag
 * @param {string} className - Class name
 * @param {string} innerHTML - Inner HTML
 * @returns {HTMLElement} Created element
 */
function createElement(tag, className, innerHTML) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (innerHTML) el.innerHTML = innerHTML;
    return el;
}

/**
 * Sanitize HTML to prevent XSS
 * @param {string} str - String to sanitize
 * @returns {string} Sanitized string
 */
function sanitizeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
