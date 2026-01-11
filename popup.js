/**
 * Popup Script - Refactored
 * Display analysis results with better state management
 * @module popup
 */

// Configuration templates for risk levels
const RISK_LEVEL_CONFIG = {
    critical: {
        title: '⚠️ Critical Threat Detected!',
        message: 'This website is extremely dangerous. Leave immediately.',
        icon: '🛑'
    },
    high: {
        title: '🛑 High Risk Warning',
        message: 'Multiple suspicious indicators found. Avoid entering any information.',
        icon: '⚠'
    },
    medium: {
        title: '⚡ Moderate Risk',
        message: 'Some suspicious characteristics detected. Proceed with caution.',
        icon: '⚠'
    },
    low: {
        title: 'ℹ️ Low Risk',
        message: 'Minor concerns detected. Be vigilant.',
        icon: 'ℹ'
    },
    safe: {
        title: '✅ Site Appears Safe',
        message: 'No significant threats detected',
        icon: '✓'
    }
};

// State
let currentTab = null;
let currentAnalysis = null;

/**
 * Initialize popup
 */
document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Show loading state
        showLoadingState();

        // Get current tab
        [currentTab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!currentTab) {
            showError('Unable to get current tab');
            return;
        }

        // Get analysis from content script
        await loadAnalysis();

        // Get and display stats
        await loadStats();

    } catch (error) {
        console.error('Popup initialization error:', error);
        showError('Failed to load phishing analysis');
    }
});

/**
 * Show loading state
 */
function showLoadingState() {
    const indicator = document.getElementById('status-indicator');
    const title = document.getElementById('status-title');
    const message = document.getElementById('status-message');

    if (indicator) indicator.className = 'status-indicator status-checking';
    if (title) title.textContent = 'Checking...';
    if (message) message.textContent = 'Analyzing page security';
}

/**
 * Load analysis from content script
 */
async function loadAnalysis() {
    try {
        currentAnalysis = await sendMessageToTab({ type: 'GET_ANALYSIS' });

        if (!currentAnalysis || currentAnalysis.error) {
            showStatus('safe', 'No Analysis Available', 'This page hasn\'t been analyzed yet.');
            return;
        }

        displayAnalysis(currentAnalysis);

    } catch (error) {
        console.error('Failed to load analysis:', error);
        showStatus('safe', 'Analysis Unavailable', 'Unable to analyze this page.');
    }
}

/**
 * Send message to current tab with timeout
 * @param {Object} message - Message to send
 * @returns {Promise} Response
 */
function sendMessageToTab(message) {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error('Message timeout'));
        }, 3000);

        chrome.tabs.sendMessage(currentTab.id, message, (response) => {
            clearTimeout(timeout);

            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
            } else {
                resolve(response);
            }
        });
    });
}

/**
 * Load stats from background
 */
async function loadStats() {
    try {
        const stats = await chrome.runtime.sendMessage({ type: 'GET_STATS' });

        if (stats) {
            const sitesEl = document.getElementById('sites-checked');
            const threatsEl = document.getElementById('threats-blocked');

            if (sitesEl) sitesEl.textContent = stats.sitesChecked || 0;
            if (threatsEl) threatsEl.textContent = stats.threatsBlocked || 0;
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

/**
 * Display analysis results
 * @param {Object} analysis - Analysis data
 */
function displayAnalysis(analysis) {
    const { level, score, threats, details } = analysis;

    // Get risk level config
    const config = RISK_LEVEL_CONFIG[level] || RISK_LEVEL_CONFIG.safe;

    // Update status
    showStatus(level, config.title, config.message);

    // Show risk score
    if (score && score > 0) {
        showRiskScore(score, level);
    } else {
        hideRiskScore();
    }

    // Show threats
    if (threats && threats.length > 0) {
        showThreats(threats, details);
    } else {
        hideThreats();
    }
}

/**
 * Update status display
 * @param {string} level - Risk level
 * @param {string} title - Status title
 * @param {string} message - Status message
 */
function showStatus(level, title, message) {
    const indicator = document.getElementById('status-indicator');
    const statusTitle = document.getElementById('status-title');
    const statusMessage = document.getElementById('status-message');
    const iconEl = document.querySelector('.status-icon');

    if (!indicator || !statusTitle || !statusMessage) return;

    // Remove checking class
    indicator.classList.remove('status-checking');

    // Set level class
    indicator.className = `status-indicator status-${level}`;

    // Update icon
    const config = RISK_LEVEL_CONFIG[level] || RISK_LEVEL_CONFIG.safe;
    if (iconEl) {
        iconEl.innerHTML = `<span class="status-icon-text">${config.icon}</span>`;
    }

    // Update text
    statusTitle.textContent = title;
    statusMessage.textContent = message;
}

/**
 * Show risk score with animation
 * @param {number} score - Risk score
 * @param {string} level - Risk level
 */
function showRiskScore(score, level) {
    const container = document.getElementById('risk-score-container');
    const scoreNumber = document.getElementById('risk-score-number');
    const progressCircle = document.getElementById('risk-score-progress');

    if (!container || !scoreNumber || !progressCircle) return;

    container.style.display = 'block';

    // Color map
    const colorMap = {
        safe: '#22c55e',
        low: '#3b82f6',
        medium: '#f59e0b',
        high: '#ea580c',
        critical: '#dc2626'
    };

    const color = colorMap[level] || '#6b7280';
    progressCircle.style.stroke = color;

    // Animate score number
    animateValue(scoreNumber, 0, score, 800);

    // Animate circle (circumference = 283)
    const offset = 283 - (score / 100) * 283;
    setTimeout(() => {
        progressCircle.style.strokeDashoffset = offset;
    }, 100);
}

/**
 * Animate number value
 * @param {HTMLElement} element - Element to animate
 * @param {number} start - Start value
 * @param {number} end - End value
 * @param {number} duration - Duration in ms
 */
function animateValue(element, start, end, duration) {
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const current = Math.floor(start + (end - start) * progress);

        element.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

/**
 * Hide risk score
 */
function hideRiskScore() {
    const container = document.getElementById('risk-score-container');
    if (container) {
        container.style.display = 'none';
    }
}

/**
 * Display threats list
 * @param {Array} threats - Threats array
 * @param {Object} details - Analysis details
 */
function showThreats(threats, details) {
    const container = document.getElementById('threats-container');
    const list = document.getElementById('threats-list');

    if (!container || !list) return;

    container.style.display = 'block';
    list.innerHTML = '';

    // Categorize threats
    const categorized = categorizeThreats(threats);

    // Display sorted threats (max 6)
    const displayThreats = categorized.slice(0, 6);

    displayThreats.forEach((threat, idx) => {
        const li = document.createElement('li');

        const badge = document.createElement('span');
        badge.className = 'threat-priority';
        badge.textContent = idx < 3 ? '⚠️' : '•';

        li.appendChild(badge);
        li.appendChild(document.createTextNode(' ' + threat));
        list.appendChild(li);
    });

    // Add "more" indicator
    if (categorized.length > 6) {
        const li = document.createElement('li');
        li.textContent = `...and ${categorized.length - 6} more issue(s)`;
        li.style.fontStyle = 'italic';
        li.style.color = '#9ca3af';
        li.style.marginTop = '8px';
        list.appendChild(li);
    }
}

/**
 * Categorize and sort threats by priority
 * @param {Array} threats - Threats array
 * @returns {Array} Sorted threats
 */
function categorizeThreats(threats) {
    const categories = {
        critical: [],
        high: [],
        medium: [],
        low: []
    };

    threats.forEach(threat => {
        const lower = threat.toLowerCase();

        // Critical threats
        if (lower.includes('typo') || lower.includes('homograph') ||
            lower.includes('ip address') || lower.includes('password')) {
            categories.critical.push(threat);
        }
        // High priority
        else if (lower.includes('non-https') || lower.includes('external') ||
            lower.includes('credit') || lower.includes('ssn')) {
            categories.high.push(threat);
        }
        // Medium priority
        else if (lower.includes('suspicious') || lower.includes('urgency') ||
            lower.includes('misleading')) {
            categories.medium.push(threat);
        }
        // Low priority
        else {
            categories.low.push(threat);
        }
    });

    return [
        ...categories.critical,
        ...categories.high,
        ...categories.medium,
        ...categories.low
    ];
}

/**
 * Hide threats
 */
function hideThreats() {
    const container = document.getElementById('threats-container');
    if (container) {
        container.style.display = 'none';
    }
}

/**
 * Show error message
 * @param {string} message - Error message
 */
function showError(message) {
    showStatus('safe', 'Error', message);
    hideRiskScore();
    hideThreats();
}
