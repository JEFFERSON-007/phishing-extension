/**
 * Configuration Module
 * Central configuration for all phishing detection parameters
 * @module config
 */

const CONFIG = {
  // Version information
  VERSION: '2.0.0',

  // Analysis Thresholds
  RISK_THRESHOLDS: {
    SAFE: 0,
    LOW: 20,
    MEDIUM: 40,
    HIGH: 60,
    CRITICAL: 80
  },

  // Performance Settings
  PERFORMANCE: {
    // Cache settings
    CACHE_TTL_MS: 30 * 60 * 1000, // 30 minutes
    CACHE_MAX_ENTRIES: 1000,

    // Debounce/throttle delays
    REANALYSIS_DEBOUNCE_MS: 1000,
    STORAGE_SAVE_DEBOUNCE_MS: 2000,

    // Timeouts
    MESSAGE_TIMEOUT_MS: 5000,
    ANALYSIS_TIMEOUT_MS: 10000,

    // Limits
    MAX_THREATS_DISPLAY: 6,
    MAX_THREATS_IN_POPUP: 6,
    MAX_METHOD_LINES: 25 // Code quality target
  },

  // Score Weights (out of 100 total)
  SCORE_WEIGHTS: {
    // URL Analysis
    NON_HTTPS_SENSITIVE: 25,
    IP_ADDRESS_DOMAIN: 30,
    SUSPICIOUS_TLD: 15,
    EXCESSIVE_SUBDOMAINS: 10,
    HOMOGRAPH_ATTACK: 40,
    TYPOSQUATTING: 35,
    URL_AT_SYMBOL: 20,
    URL_SHORTENER: 10,
    EMBEDDED_URL: 15,
    SUSPICIOUS_KEYWORD: 5, // per keyword

    // Content Analysis
    URGENCY_PHRASE: 8, // per phrase
    EXCESSIVE_EXCLAMATIONS: 10,
    HIDDEN_IFRAME: 25, // per iframe
    MISLEADING_LINK: 15, // per link
    OBFUSCATED_SCRIPT: 15, // per script

    // Form Analysis
    PASSWORD_NO_HTTPS: 35,
    EXTERNAL_FORM_ACTION: 30,
    HTTPS_LOGIN_UNKNOWN: 15,
    HTTP_LOGIN: 15,
    HTTPS_LOGIN_KNOWN: 2,
    CREDIT_CARD_REQUEST: 15,
    SSN_REQUEST: 20,

    // Behavioral Analysis
    AUTO_SUBMIT_FORM: 20,
    POPUP_WINDOW: 10,
    RIGHT_CLICK_DISABLED: 5,
    CLIPBOARD_ACCESS: 10
  },

  // Detection Patterns
  PATTERNS: {
    // Suspicious TLDs
    SUSPICIOUS_TLDS: [
      '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
      '.live', '.site', '.online', '.club', '.bid', '.loan'
    ],

    // Suspicious keywords
    SUSPICIOUS_KEYWORDS: [
      'verify', 'urgent', 'suspended', 'locked', 'limited', 'unusual',
      'confirm', 'update', 'secure', 'expire', 'immediately', 'account-update',
      'security-alert', 'billing-problem', 'reset-password', 'click-here',
      'prize', 'winner', 'congratulations', 'claim', 'free-money'
    ],

    // Urgency phrases
    URGENCY_PHRASES: [
      'act now', 'immediate action', 'within 24 hours', 'account will be closed',
      'verify immediately', 'urgent action required', 'expire soon', 'last chance',
      'don\'t miss out', 'limited time', 'respond now', 'final notice'
    ],

    // URL shorteners
    URL_SHORTENERS: [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
      'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee'
    ],

    // URL patterns
    IP_ADDRESS_PATTERN: /^https?:\/\/\d+\.\d+\.\d+\.\d+/,
    PUNYCODE_PATTERN: /xn--/,
    DEDUPLICATION_PATTERN: /(.)\1+/g
  },

  // Typosquatting Detection
  TYPOSQUATTING: {
    MAX_LEVENSHTEIN_DISTANCE: 2,
    MIN_DOMAIN_LENGTH: 4, // Only flag typosquatting for domains > 4 chars
    KEYBOARD_PROXIMITY_THRESHOLD: 0.8 // 80% similarity
  },

  // UI Configuration
  UI: {
    // Badge colors (must match Chrome API format)
    BADGE_COLORS: {
      SAFE: '#22c55e',
      LOW: '#3b82f6',
      MEDIUM: '#f59e0b',
      HIGH: '#ea580c',
      CRITICAL: '#dc2626'
    },

    // Badge text
    BADGE_TEXT: {
      SAFE: '',
      LOW: '',
      MEDIUM: '!',
      HIGH: '!!',
      CRITICAL: '!!!'
    },

    // Animation durations
    ANIMATION: {
      SCORE_DURATION_MS: 1000,
      CIRCLE_DELAY_MS: 100,
      FADE_IN_MS: 300,
      SLIDE_UP_MS: 400
    }
  },

  // Feature Flags (for A/B testing or gradual rollout)
  FEATURES: {
    ENABLE_CACHING: true,
    ENABLE_SHADOW_DOM_PROTECTION: true,
    ENABLE_FORM_MONITORING: true,
    ENABLE_MUTATION_OBSERVER: true,
    ENABLE_PRE_NAVIGATION_BLOCKING: true,
    ENABLE_TELEMETRY: false, // Set to true when ready
    ENABLE_ADVANCED_TYPOSQUATTING: true
  },

  // Logging Configuration
  LOGGING: {
    ENABLED: true,
    LEVEL: 'info', // 'debug', 'info', 'warn', 'error'
    MAX_LOG_ENTRIES: 100
  },

  // Storage Keys
  STORAGE_KEYS: {
    STATS: 'phishing_detector_stats',
    CACHE: 'phishing_detector_cache',
    BYPASS_PREFIX: 'phishing_detector_bypass_',
    SETTINGS: 'phishing_detector_settings'
  }
};

// Freeze configuration to prevent accidental modifications
Object.freeze(CONFIG);
Object.freeze(CONFIG.RISK_THRESHOLDS);
Object.freeze(CONFIG.PERFORMANCE);
Object.freeze(CONFIG.SCORE_WEIGHTS);
Object.freeze(CONFIG.PATTERNS);
Object.freeze(CONFIG.TYPOSQUATTING);
Object.freeze(CONFIG.UI);
Object.freeze(CONFIG.FEATURES);
Object.freeze(CONFIG.LOGGING);
Object.freeze(CONFIG.STORAGE_KEYS);

// Export for use in other modules
// Check if already defined to prevent redeclaration errors
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CONFIG;
}

// Make available globally for service workers (only if not already defined)
if (typeof self !== 'undefined' && typeof self.CONFIG === 'undefined') {
  self.CONFIG = CONFIG;
}
