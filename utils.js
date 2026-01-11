/**
 * Utility Functions Module
 * Shared utilities for the phishing detector extension
 * @module utils
 */

/**
 * Debounce function - delays execution until after wait time has elapsed
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func.apply(this, args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Throttle function - ensures function is called at most once per interval
 * @param {Function} func - Function to throttle
 * @param {number} limit - Time limit in milliseconds
 * @returns {Function} Throttled function
 */
function throttle(func, limit) {
    let inThrottle;
    return function executedFunction(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

/**
 * Safe URL validator
 * @param {string} url - URL to validate
 * @returns {boolean} True if valid URL
 */
function isValidURL(url) {
    if (!url || typeof url !== 'string') return false;

    try {
        const urlObj = new URL(url);
        // Only allow http and https protocols
        return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch (e) {
        return false;
    }
}

/**
 * Sanitize URL by removing potentially dangerous components
 * @param {string} url - URL to sanitize
 * @returns {string} Sanitized URL
 */
function sanitizeURL(url) {
    if (!url) return '';

    try {
        const urlObj = new URL(url);
        // Remove auth credentials if present
        urlObj.username = '';
        urlObj.password = '';
        return urlObj.toString();
    } catch (e) {
        return '';
    }
}

/**
 * Sanitize text input to prevent XSS
 * @param {string} text - Text to sanitize
 * @returns {string} Sanitized text
 */
function sanitizeText(text) {
    if (!text) return '';

    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Safe DOM element creation with sanitized content
 * @param {string} tag - HTML tag name
 * @param {Object} attributes - Element attributes
 * @param {string} textContent - Text content (will be sanitized)
 * @returns {HTMLElement} Created element
 */
function createSafeElement(tag, attributes = {}, textContent = '') {
    const element = document.createElement(tag);

    // Set attributes
    for (const [key, value] of Object.entries(attributes)) {
        if (key === 'style') {
            Object.assign(element.style, value);
        } else {
            element.setAttribute(key, value);
        }
    }

    // Set text content (safe from XSS)
    if (textContent) {
        element.textContent = textContent;
    }

    return element;
}

/**
 * Retry function with exponential backoff
 * @param {Function} fn - Async function to retry
 * @param {number} maxRetries - Maximum number of retries
 * @param {number} delay - Initial delay in ms
 * @returns {Promise} Result of function
 */
async function retryWithBackoff(fn, maxRetries = 3, delay = 1000) {
    try {
        return await fn();
    } catch (error) {
        if (maxRetries <= 0) {
            throw error;
        }

        await new Promise(resolve => setTimeout(resolve, delay));
        return retryWithBackoff(fn, maxRetries - 1, delay * 2);
    }
}

/**
 * Promise with timeout
 * @param {Promise} promise - Promise to wrap
 * @param {number} timeoutMs - Timeout in milliseconds
 * @param {string} timeoutMessage - Error message on timeout
 * @returns {Promise} Promise that rejects on timeout
 */
function promiseWithTimeout(promise, timeoutMs, timeoutMessage = 'Operation timed out') {
    return Promise.race([
        promise,
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs)
        )
    ]);
}

/**
 * Deep clone object (simple implementation)
 * @param {Object} obj - Object to clone
 * @returns {Object} Cloned object
 */
function deepClone(obj) {
    if (obj === null || typeof obj !== 'object') return obj;

    if (obj instanceof Date) return new Date(obj.getTime());
    if (obj instanceof Array) return obj.map(item => deepClone(item));
    if (obj instanceof Set) return new Set(Array.from(obj).map(item => deepClone(item)));
    if (obj instanceof Map) {
        return new Map(Array.from(obj.entries()).map(([k, v]) => [k, deepClone(v)]));
    }

    const clonedObj = {};
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            clonedObj[key] = deepClone(obj[key]);
        }
    }
    return clonedObj;
}

/**
 * Format time ago (e.g., "2 minutes ago")
 * @param {number} timestamp - Timestamp in milliseconds
 * @returns {string} Formatted time string
 */
function timeAgo(timestamp) {
    const seconds = Math.floor((Date.now() - timestamp) / 1000);

    const intervals = {
        year: 31536000,
        month: 2592000,
        week: 604800,
        day: 86400,
        hour: 3600,
        minute: 60,
        second: 1
    };

    for (const [name, secondsInInterval] of Object.entries(intervals)) {
        const interval = Math.floor(seconds / secondsInInterval);
        if (interval >= 1) {
            return interval === 1 ? `1 ${name} ago` : `${interval} ${name}s ago`;
        }
    }

    return 'just now';
}

/**
 * Check if element is visible in viewport
 * @param {HTMLElement} element - Element to check
 * @returns {boolean} True if visible
 */
function isElementVisible(element) {
    if (!element) return false;

    const style = window.getComputedStyle(element);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
        return false;
    }

    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

/**
 * Get domain from URL
 * @param {string} url - URL to extract domain from
 * @returns {string} Domain or empty string
 */
function getDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname.toLowerCase();
    } catch (e) {
        return '';
    }
}

/**
 * Calculate percentage with bounds
 * @param {number} value - Current value
 * @param {number} max - Maximum value
 * @returns {number} Percentage (0-100)
 */
function calculatePercentage(value, max) {
    if (max === 0) return 0;
    return Math.min(100, Math.max(0, (value / max) * 100));
}

/**
 * Simple logger with levels
 */
const Logger = {
    levels: {
        DEBUG: 0,
        INFO: 1,
        WARN: 2,
        ERROR: 3
    },

    currentLevel: 1, // INFO by default

    setLevel(level) {
        this.currentLevel = this.levels[level.toUpperCase()] || 1;
    },

    debug(...args) {
        if (this.currentLevel <= this.levels.DEBUG) {
            console.log('[DEBUG]', ...args);
        }
    },

    info(...args) {
        if (this.currentLevel <= this.levels.INFO) {
            console.log('[INFO]', ...args);
        }
    },

    warn(...args) {
        if (this.currentLevel <= this.levels.WARN) {
            console.warn('[WARN]', ...args);
        }
    },

    error(...args) {
        if (this.currentLevel <= this.levels.ERROR) {
            console.error('[ERROR]', ...args);
        }
    }
};

/**
 * Initialize logger from config
 * @param {Object} config - Configuration object
 */
function initLogger(config) {
    if (config?.LOGGING?.ENABLED) {
        Logger.setLevel(config.LOGGING.LEVEL || 'info');
    }
}

// Export all utilities
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        debounce,
        throttle,
        isValidURL,
        sanitizeURL,
        sanitizeText,
        createSafeElement,
        retryWithBackoff,
        promiseWithTimeout,
        deepClone,
        timeAgo,
        isElementVisible,
        getDomain,
        calculatePercentage,
        Logger,
        initLogger
    };
}
