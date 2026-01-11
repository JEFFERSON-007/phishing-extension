/**
 * Background Service Worker - Refactored
 * Manages extension state, communication, and lifecycle
 * @module background
 */

// Load dependencies using importScripts (works in service workers)
// These will be available as global variables (CONFIG, CacheManager, Logger, etc.)
try {
  self.importScripts('config.js', 'utils.js', 'cache-manager.js');
} catch (error) {
  console.error('Failed to load dependencies:', error);
}

// Access globals directly (no redeclaration needed)
// CONFIG, CacheManager, Logger, debounce, etc. are now available

// Initialize logger (globals from importScripts)
if (typeof Logger !== 'undefined' && typeof CONFIG !== 'undefined') {
  Logger.setLevel(CONFIG.LOGGING.LEVEL);
}

// Extension state
let stats = {
  sitesChecked: 0,
  threatsBlocked: 0,
  lastUpdate: Date.now()
};

// Request deduplication map
const pendingRequests = new Map();

// Debounced save function
let saveStatsDebounced;

/**
 * Initialize extension
 */
chrome.runtime.onInstalled.addListener(async () => {
  console.log('🔧 Phishing Detector Extension installed/updated');

  if (typeof Logger !== 'undefined') {
    Logger.info('Phishing Detector Extension installed/updated');
  }

  try {
    // Load saved stats
    const result = await chrome.storage.local.get([CONFIG.STORAGE_KEYS.STATS]);
    if (result[CONFIG.STORAGE_KEYS.STATS]) {
      stats = { ...stats, ...result[CONFIG.STORAGE_KEYS.STATS] };
      if (typeof Logger !== 'undefined') Logger.debug('Stats loaded from storage:', stats);
      console.log('📊 Stats loaded:', stats);
    }

    // Set default badge
    await chrome.action.setBadgeBackgroundColor({ color: CONFIG.UI.BADGE_COLORS.SAFE });
    await chrome.action.setBadgeText({ text: '' });

    console.log('✅ Extension initialized successfully');

    // Create debounced save function
    if (typeof debounce !== 'undefined' && CONFIG) {
      saveStatsDebounced = debounce(saveStats, CONFIG.PERFORMANCE.STORAGE_SAVE_DEBOUNCE_MS);
    }

  } catch (error) {
    console.error('❌ Initialization error:', error);
    if (typeof Logger !== 'undefined') Logger.error('Initialization error:', error);
  }
});

/**
 * Pre-analyze URL before page loads
 * @param {string} url - URL to check
 * @returns {boolean} True if should block
 */
function shouldBlockNavigation(url) {
  if (!CONFIG.FEATURES.ENABLE_PRE_NAVIGATION_BLOCKING) {
    return false;
  }

  try {
    // Don't analyze internal pages
    if (isInternalPage(url)) {
      return false;
    }

    const urlObj = new URL(url);
    let quickScore = 0;

    if (typeof Logger !== 'undefined') {
      Logger.debug('🔍 Analyzing URL for blocking:', url);
    }

    // IP address check
    if (CONFIG.PATTERNS.IP_ADDRESS_PATTERN.test(url)) {
      quickScore += CONFIG.SCORE_WEIGHTS.IP_ADDRESS_DOMAIN;
      if (typeof Logger !== 'undefined') {
        Logger.debug('  ⚠️ IP address detected: +' + CONFIG.SCORE_WEIGHTS.IP_ADDRESS_DOMAIN);
      }
    }

    // Suspicious TLD - CHECK THIS!
    const domain = urlObj.hostname.toLowerCase();
    const hasSuspiciousTLD = CONFIG.PATTERNS.SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld));
    if (hasSuspiciousTLD) {
      quickScore += CONFIG.SCORE_WEIGHTS.SUSPICIOUS_TLD;
      if (typeof Logger !== 'undefined') {
        Logger.debug('  ⚠️ Suspicious TLD detected: +' + CONFIG.SCORE_WEIGHTS.SUSPICIOUS_TLD);
      }
    }

    // Non-HTTPS on sensitive pages
    if (urlObj.protocol !== 'https:') {
      const path = urlObj.pathname.toLowerCase();
      if (path.includes('login') || path.includes('payment')) {
        quickScore += CONFIG.SCORE_WEIGHTS.NON_HTTPS_SENSITIVE;
        if (typeof Logger !== 'undefined') {
          Logger.debug('  ⚠️ Non-HTTPS sensitive: +' + CONFIG.SCORE_WEIGHTS.NON_HTTPS_SENSITIVE);
        }
      }
    }

    if (typeof Logger !== 'undefined') {
      Logger.debug('  📊 Quick score:', quickScore, '/ Threshold:', CONFIG.RISK_THRESHOLDS.HIGH);
    }

    // Block if HIGH threshold reached (was CRITICAL before)
    // This makes blocking more aggressive for testing
    const shouldBlock = quickScore >= CONFIG.RISK_THRESHOLDS.HIGH;

    if (shouldBlock && typeof Logger !== 'undefined') {
      Logger.info('  🛑 WILL BLOCK - Score exceeds threshold');
    }

    return shouldBlock;

  } catch (error) {
    if (typeof Logger !== 'undefined') Logger.error('Pre-navigation analysis error:', error);
    return false; // Don't block on errors
  }
}

/**
 * Check if page is internal (chrome://, extension pages, etc.)
 * @param {string} url - URL to check
 * @returns {boolean} True if internal
 */
function isInternalPage(url) {
  return url.startsWith('chrome://') ||
    url.startsWith('chrome-extension://') ||
    url.startsWith('about:') ||
    url.startsWith('edge://') ||
    url.startsWith('file://');
}

/**
 * Pre-navigation blocking using tabs.onUpdated (Manifest V3 compatible)
 * We intercept in the 'loading' phase and redirect to warning page
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  try {
    // EARLY INTERCEPTION - Check during loading phase
    if (changeInfo.status === 'loading' && changeInfo.url) {
      const url = changeInfo.url;

      // Don't block internal pages
      if (isInternalPage(url)) return;

      // Don't block our own warning page
      if (url.includes(chrome.runtime.getURL('warning.html'))) return;

      // Quick pre-navigation check
      if (shouldBlockNavigation(url)) {
        // Immediately redirect to warning page
        const warningUrl = chrome.runtime.getURL('warning.html') + '?url=' + encodeURIComponent(url);

        // Cancel current navigation and redirect
        await chrome.tabs.update(tabId, { url: warningUrl });

        // Update badge
        updateBadge(tabId, { level: 'critical' });

        // Update stats
        stats.threatsBlocked++;
        if (saveStatsDebounced) {
          saveStatsDebounced();
        } else {
          saveStats();
        }

        if (typeof Logger !== 'undefined') {
          Logger.info('🛑 BLOCKED navigation to:', url);
        }

        return; // Stop processing
      }
    }

    // Full analysis after page loads (for pages that weren't blocked)
    if (changeInfo.status === 'complete' && tab.url) {
      if (isInternalPage(tab.url)) return;

      // Skip if it's our warning page
      if (tab.url.includes(chrome.runtime.getURL('warning.html'))) return;

      // Check for pending request (deduplication)
      const requestKey = `${tabId}-${tab.url}`;
      if (pendingRequests.has(requestKey)) {
        if (typeof Logger !== 'undefined') Logger.debug('Skipping duplicate request for:', tab.url);
        return;
      }

      // Mark as pending
      pendingRequests.set(requestKey, Date.now());

      // Request analysis with timeout
      try {
        const response = await sendMessageWithTimeout(
          tabId,
          { type: 'ANALYZE_PAGE' },
          CONFIG.PERFORMANCE.MESSAGE_TIMEOUT_MS
        );

        if (response) {
          await updateBadge(tabId, response);
          updateStatsFromAnalysis(response);
        }

      } catch (error) {
        if (typeof Logger !== 'undefined') Logger.warn('Analysis request failed:', error.message);
      } finally {
        // Remove from pending after delay
        setTimeout(() => pendingRequests.delete(requestKey), 5000);
      }
    }

  } catch (error) {
    if (typeof Logger !== 'undefined') Logger.error('Tab update handler error:', error);
  }
});

/**
 * Send message with timeout
 * @param {number} tabId - Tab ID
 * @param {Object} message - Message to send
 * @param {number} timeout = Timeout in ms
 * @returns {Promise} Response promise
 */
function sendMessageWithTimeout(tabId, message, timeout) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('Message timeout'));
    }, timeout);

    chrome.tabs.sendMessage(tabId, message, (response) => {
      clearTimeout(timer);

      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

/**
 * Handle messages from content scripts and popup
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  try {
    if (message.type === 'ANALYSIS_COMPLETE') {
      handleAnalysisComplete(message, sender).then(sendResponse);
      return true; // Async response

    } else if (message.type === 'GET_STATS') {
      sendResponse(stats);

    } else {
      if (typeof Logger !== 'undefined') Logger.warn('Unknown message type:', message.type);
      sendResponse({ error: 'Unknown message type' });
    }

  } catch (error) {
    if (typeof Logger !== 'undefined') Logger.error('Message handler error:', error);
    sendResponse({ error: error.message });
  }

  return true;
});

/**
 * Handle analysis complete message
 * @param {Object} message - Message data
 * @param {Object} sender - Message sender
 */
async function handleAnalysisComplete(message, sender) {
  const tabId = sender.tab?.id;

  if (tabId) {
    await updateBadge(tabId, message.data);
    updateStatsFromAnalysis(message.data);
  }

  return { success: true };
}

/**
 * Update badge based on risk level
 * @param {number} tabId - Tab ID
 * @param {Object} analysis - Analysis result
 */
async function updateBadge(tabId, analysis) {
  try {
    const level = analysis.level || 'safe';
    const color = CONFIG.UI.BADGE_COLORS[level.toUpperCase()] || CONFIG.UI.BADGE_COLORS.SAFE;
    const text = CONFIG.UI.BADGE_TEXT[level.toUpperCase()] || '';

    await chrome.action.setBadgeBackgroundColor({ color, tabId });
    await chrome.action.setBadgeText({ text, tabId });

  } catch (error) {
    if (typeof Logger !== 'undefined') Logger.error('Badge update error:', error);
  }
}

/**
 * Update statistics from analysis
 * @param {Object} analysis - Analysis data
 */
function updateStatsFromAnalysis(analysis) {
  stats.sitesChecked++;

  if (analysis.level === 'high' || analysis.level === 'critical') {
    stats.threatsBlocked++;
  }

  stats.lastUpdate = Date.now();

  // Debounced save
  if (saveStatsDebounced) {
    saveStatsDebounced();
  } else {
    saveStats();
  }
}

/**
 * Save stats to storage
 */
async function saveStats() {
  try {
    await chrome.storage.local.set({ [CONFIG.STORAGE_KEYS.STATS]: stats });
    if (typeof Logger !== 'undefined') Logger.debug('Stats saved:', stats);
  } catch (error) {
    if (typeof Logger !== 'undefined') Logger.error('Stats save error:', error);
  }
}

/**
 * Service worker lifecycle - keep alive strategy
 */
let keepAliveInterval;

chrome.runtime.onStartup.addListener(() => {
  if (typeof Logger !== 'undefined') Logger.info('Service worker started');

  // Keep service worker alive with periodic messages
  keepAliveInterval = setInterval(() => {
    chrome.runtime.getPlatformInfo(() => {
      // Just to keep the service worker alive
    });
  }, 20000); // Every 20 seconds
});

/**
 * Cleanup on suspend
 */
chrome.runtime.onSuspend.addListener(async () => {
  if (typeof Logger !== 'undefined') Logger.info('Service worker suspending - saving state');

  if (keepAliveInterval) {
    clearInterval(keepAliveInterval);
  }

  // Save stats one last time
  await saveStats();
});

// Log that background script is loaded
if (typeof Logger !== 'undefined') Logger.info('Background service worker loaded');