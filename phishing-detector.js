/**
 * Phishing Detection Engine - Refactored
 * Multi-layered analysis system with performance optimizations
 * @module phishing-detector
 */

/**
 * Phishing Detector Class
 * Analyzes URLs and web pages for phishing indicators
 */
class PhishingDetector {
  /**
   * Create a phishing detector instance
   * @param {Object} config - Configuration object (defaults to global CONFIG)
   */
  constructor(config = typeof CONFIG !== 'undefined' ? CONFIG : null) {
    if (!config) {
      throw new Error('PhishingDetector requires config object');
    }

    this.config = config;
    this.logger = typeof Logger !== 'undefined' ? Logger : console;

    // Initialize cache if available
    this.cache = null;
    if (typeof CacheManager !== 'undefined' && config.FEATURES.ENABLE_CACHING) {
      this.cache = new CacheManager(
        config.PERFORMANCE.CACHE_MAX_ENTRIES,
        config.PERFORMANCE.CACHE_TTL_MS
      );
    }

    // Lazy-load data patterns (don't load in constructor)
    this._dataLoaded = false;
    this._legitimateDomains = null;
    this._homographs = null;
    this._charSubstitutions = null;
    this._keyboardProximity = null;

    // Memoization cache for expensive calculations
    this._levenshteinCache = new Map();
  }

  /**
   * Lazy load detection data
   * @private
   */
  _ensureDataLoaded() {
    if (this._dataLoaded) return;

    // Load legitimate domains
    this._legitimateDomains = [
      // Tech Giants
      'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
      'twitter.com', 'instagram.com', 'youtube.com', 'linkedin.com', 'tiktok.com',
      'zoom.us', 'dropbox.com', 'adobe.com', 'salesforce.com', 'slack.com',
      // Financial
      'paypal.com', 'stripe.com', 'square.com', 'chase.com', 'bankofamerica.com',
      'wellsfargo.com', 'citibank.com', 'venmo.com', 'cashapp.com', 'coinbase.com',
      // E-commerce
      'ebay.com', 'etsy.com', 'walmart.com', 'target.com', 'bestbuy.com',
      'shopify.com', 'alibaba.com', 'aliexpress.com',
      // Developer
      'github.com', 'gitlab.com', 'stackoverflow.com', 'npmjs.com', 'pypi.org',
      'docker.com', 'heroku.com', 'vercel.com', 'netlify.com',
      // Entertainment
      'netflix.com', 'spotify.com', 'hulu.com', 'twitch.tv', 'discord.com',
      'reddit.com', 'imgur.com', 'medium.com',
      // Education
      'wikipedia.org', 'coursera.org', 'udemy.com', 'khanacademy.org',
      // Government
      'irs.gov', 'usps.com', 'gov.uk', 'canada.ca'
    ];

    // Homograph attack characters
    this._homographs = {
      'a': ['а', 'ɑ', 'α'], 'e': ['е', 'ė', 'ē'], 'o': ['о', 'ο', '0'],
      'p': ['р', 'ρ'], 'c': ['с', 'ϲ'], 'i': ['і', 'ı', '1', 'l'],
      'x': ['х', 'χ'], 'y': ['у', 'ү'], 'h': ['һ'], 'b': ['ь'],
      's': ['ѕ'], 'j': ['ј']
    };

    // Character substitutions
    this._charSubstitutions = {
      '0': 'o', '1': 'il', '3': 'e', '5': 's', '8': 'b', '@': 'a', '$': 's'
    };

    // Keyboard proximity
    this._keyboardProximity = {
      'q': ['w', 'a'], 'w': ['q', 'e', 's', 'a'], 'e': ['w', 'r', 'd', 's'],
      'r': ['e', 't', 'f', 'd'], 't': ['r', 'y', 'g', 'f'], 'y': ['t', 'u', 'h', 'g'],
      'u': ['y', 'i', 'j', 'h'], 'i': ['u', 'o', 'k', 'j'], 'o': ['i', 'p', 'l', 'k'],
      'p': ['o', 'l'], 'a': ['q', 'w', 's', 'z'], 's': ['a', 'w', 'e', 'd', 'z', 'x'],
      'd': ['s', 'e', 'r', 'f', 'x', 'c'], 'f': ['d', 'r', 't', 'g', 'c', 'v'],
      'g': ['f', 't', 'y', 'h', 'v', 'b'], 'h': ['g', 'y', 'u', 'j', 'b', 'n'],
      'j': ['h', 'u', 'i', 'k', 'n', 'm'], 'k': ['j', 'i', 'o', 'l', 'm'],
      'l': ['k', 'o', 'p'], 'z': ['a', 's', 'x'], 'x': ['z', 's', 'd', 'c'],
      'c': ['x', 'd', 'f', 'v'], 'v': ['c', 'f', 'g', 'b'], 'b': ['v', 'g', 'h', 'n'],
      'n': ['b', 'h', 'j', 'm'], 'm': ['n', 'j', 'k']
    };

    this._dataLoaded = true;
  }

  /**
   * Main analysis function
   * @param {string} url - URL to analyze
   * @param {Document} doc - DOM document to analyze (optional)
   * @returns {Object} Risk assessment
   */
  analyze(url, doc = null) {
    // Input validation
    if (!url || typeof url !== 'string') {
      this.logger.warn('Invalid URL provided to analyze()');
      return this._createSafeResult();
    }

    // Check cache first
    if (this.cache && this.cache.has(url)) {
      this.logger.debug('Cache hit for URL:', url);
      return this.cache.get(url);
    }

    const results = {
      score: 0,
      level: 'safe',
      threats: [],
      details: {},
      timestamp: Date.now()
    };

    try {
      // Ensure data is loaded
      this._ensureDataLoaded();

      // Layer 1: URL Analysis (fast, always run)
      const urlAnalysis = this._analyzeURL(url);
      this._mergeAnalysis(results, urlAnalysis);

      // Layer 2-4: Content analysis (only if document provided)
      if (doc) {
        const contentAnalysis = this._analyzeContent(doc);
        this._mergeAnalysis(results, contentAnalysis);

        const formAnalysis = this._analyzeForms(doc, url);
        this._mergeAnalysis(results, formAnalysis);

        const behaviorAnalysis = this._analyzeBehavior(doc);
        this._mergeAnalysis(results, behaviorAnalysis);
      }

      // Determine risk level
      results.level = this._getRiskLevel(results.score);

      // Cache result
      if (this.cache) {
        this.cache.set(url, results);
      }

    } catch (error) {
      this.logger.error('Analysis error:', error);
      results.error = error.message;
    }

    return results;
  }

  /**
   * Merge analysis results
   * @private
   */
  _mergeAnalysis(results, analysis) {
    results.score += analysis.score;
    if (analysis.threats && analysis.threats.length > 0) {
      results.threats.push(...analysis.threats);
    }
  }

  /**
   * Create safe default result
   * @private
   */
  _createSafeResult() {
    return {
      score: 0,
      level: 'safe',
      threats: [],
      details: {},
      timestamp: Date.now(),
      error: 'Invalid input'
    };
  }

  /**
   * Analyze URL for suspicious patterns
   * @private
   */
  _analyzeURL(url) {
    const analysis = { score: 0, threats: [], details: {} };

    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      const path = urlObj.pathname.toLowerCase();
      const fullURL = url.toLowerCase();
      const weights = this.config.SCORE_WEIGHTS;

      // Protocol check
      if (urlObj.protocol !== 'https:' && this._isSensitivePath(path)) {
        analysis.score += weights.NON_HTTPS_SENSITIVE;
        analysis.threats.push('Non-HTTPS connection on sensitive page');
      }

      // IP address check
      if (this.config.PATTERNS.IP_ADDRESS_PATTERN.test(url)) {
        analysis.score += weights.IP_ADDRESS_DOMAIN;
        analysis.threats.push('Using IP address instead of domain name');
      }

      // Suspicious TLD
      if (this._hasSuspiciousTLD(domain)) {
        analysis.score += weights.SUSPICIOUS_TLD;
        analysis.threats.push('Suspicious top-level domain');
      }

      // Excessive subdomains
      const subdomainCount = this._getSubdomainCount(domain);
      if (subdomainCount > 3) {
        analysis.score += weights.EXCESSIVE_SUBDOMAINS;
        analysis.threats.push('Excessive subdomains detected');
      }

      // Suspicious keywords
      const keywords = this._findSuspiciousKeywords(fullURL);
      if (keywords.length > 0) {
        analysis.score += keywords.length * weights.SUSPICIOUS_KEYWORD;
        analysis.threats.push(`Suspicious keywords: ${keywords.slice(0, 3).join(', ')}`);
      }

      // Homograph attack
      if (this._detectHomographAttack(domain)) {
        analysis.score += weights.HOMOGRAPH_ATTACK;
        analysis.threats.push('Possible homograph attack (lookalike characters)');
      }

      // Typosquatting
      const typoTarget = this._detectTyposquatting(domain);
      if (typoTarget) {
        analysis.score += weights.TYPOSQUATTING;
        analysis.threats.push(`Possible typosquatting: similar to ${typoTarget}`);
      }

      // URL manipulation
      if (fullURL.includes('@')) {
        analysis.score += weights.URL_AT_SYMBOL;
        analysis.threats.push('URL contains @ symbol (possible redirect)');
      }

      // URL shortener
      if (this._isURLShortener(domain)) {
        analysis.score += weights.URL_SHORTENER;
        analysis.threats.push('URL shortener detected');
      }

      // Embedded URL
      if (this._hasEmbeddedURL(path)) {
        analysis.score += weights.EMBEDDED_URL;
        analysis.threats.push('Embedded URL in path (redirect chain)');
      }

      analysis.details = {
        protocol: urlObj.protocol,
        domain: domain,
        isHTTPS: urlObj.protocol === 'https:',
        subdomainCount: subdomainCount
      };

    } catch (error) {
      this.logger.error('URL analysis error:', error);
    }

    return analysis;
  }

  /**
   * Check if path is sensitive
   * @private
   */
  _isSensitivePath(path) {
    return path.includes('login') || path.includes('payment') || path.includes('checkout');
  }

  /**
   * Check if domain has suspicious TLD
   * @private
   */
  _hasSuspiciousTLD(domain) {
    return this.config.PATTERNS.SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld));
  }

  /**
   * Get subdomain count
   * @private
   */
  _getSubdomainCount(domain) {
    return domain.split('.').length - 2;
  }

  /**
   * Find suspicious keywords in URL
   * @private
   */
  _findSuspiciousKeywords(url) {
    return this.config.PATTERNS.SUSPICIOUS_KEYWORDS.filter(kw => url.includes(kw));
  }

  /**
   * Check if domain is a URL shortener
   * @private
   */
  _isURLShortener(domain) {
    return this.config.PATTERNS.URL_SHORTENERS.some(sh => domain.includes(sh));
  }

  /**
   * Check if path has embedded URL
   * @private
   */
  _hasEmbeddedURL(path) {
    return (path.match(/http/g) || []).length > 0;
  }

  /**
   * Detect homograph attacks
   * @private
   */
  _detectHomographAttack(domain) {
    // Punycode check
    if (this.config.PATTERNS.PUNYCODE_PATTERN.test(domain)) {
      return true;
    }

    // Check for lookalike characters
    for (const [latin, alts] of Object.entries(this._homographs)) {
      for (const alt of alts) {
        if (domain.includes(alt)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Detect typosquatting (optimized with early returns)
   * @private
   */
  _detectTyposquatting(domain) {
    const currentBase = domain.split('.')[0];

    for (const legitimate of this._legitimateDomains) {
      const legitBase = legitimate.split('.')[0];

      // Skip exact matches
      if (legitBase === currentBase) continue;

      // Skip if length difference is too large
      if (Math.abs(legitBase.length - currentBase.length) > 3) continue;

      // Check Levenshtein distance (with memoization)
      const distance = this._getLevenshteinDistance(legitBase, currentBase);
      if (distance > 0 && distance <= this.config.TYPOSQUATTING.MAX_LEVENSHTEIN_DISTANCE &&
        legitBase.length >= this.config.TYPOSQUATTING.MIN_DOMAIN_LENGTH) {
        return legitimate;
      }

      // Check domain inclusion
      if (currentBase.includes(legitBase) && currentBase !== legitBase) {
        return legitimate;
      }

      // Check character substitution
      if (this._checkCharSubstitution(currentBase, legitBase)) {
        return legitimate;
      }

      // Check keyboard proximity
      if (this._detectKeyboardProximityAttack(currentBase, legitBase)) {
        return legitimate;
      }

      // Check doubled characters
      if (this._checkDoubledChars(currentBase, legitBase)) {
        return legitimate;
      }
    }

    return null;
  }

  /**
   * Get Levenshtein distance with memoization
   * @private
   */
  _getLevenshteinDistance(str1, str2) {
    const key = `${str1}:${str2}`;

    if (this._levenshteinCache.has(key)) {
      return this._levenshteinCache.get(key);
    }

    const distance = this._calculateLevenshteinDistance(str1, str2);

    // Limit cache size
    if (this._levenshteinCache.size > 1000) {
      const firstKey = this._levenshteinCache.keys().next().value;
      this._levenshteinCache.delete(firstKey);
    }

    this._levenshteinCache.set(key, distance);
    return distance;
  }

  /**
   * Calculate Levenshtein distance
   * @private
   */
  _calculateLevenshteinDistance(str1, str2) {
    const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(0));

    for (let i = 0; i <= str2.length; i++) matrix[i][0] = i;
    for (let j = 0; j <= str1.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2[i - 1] === str1[j - 1]) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Check character substitution
   * @private
   */
  _checkCharSubstitution(current, legitimate) {
    let normalized = current;
    for (const [fake, real] of Object.entries(this._charSubstitutions)) {
      normalized = normalized.replace(new RegExp(fake, 'g'), real);
    }
    return normalized === legitimate;
  }

  /**
   * Detect keyboard proximity attack
   * @private
   */
  _detectKeyboardProximityAttack(current, legitimate) {
    if (Math.abs(current.length - legitimate.length) > 2) return false;

    let matchScore = 0;
    const maxLen = Math.max(current.length, legitimate.length);

    for (let i = 0; i < Math.min(current.length, legitimate.length); i++) {
      const currChar = current[i];
      const legitChar = legitimate[i];

      if (currChar === legitChar) {
        matchScore++;
      } else if (this._keyboardProximity[legitChar]?.includes(currChar)) {
        matchScore += 0.5;
      }
    }

    return (matchScore / maxLen) > this.config.TYPOSQUATTING.KEYBOARD_PROXIMITY_THRESHOLD;
  }

  /**
   * Check for doubled characters
   * @private
   */
  _checkDoubledChars(current, legitimate) {
    const deduped = current.replace(this.config.PATTERNS.DEDUPLICATION_PATTERN, '$1');
    return deduped === legitimate;
  }

  /**
   * Analyze page content
   * @private
   */
  _analyzeContent(doc) {
    const analysis = { score: 0, threats: [] };

    try {
      const bodyText = doc.body?.innerText?.toLowerCase() || '';
      const weights = this.config.SCORE_WEIGHTS;

      // Urgency language
      const urgencyMatches = this._findUrgencyPhrases(bodyText);
      if (urgencyMatches.length > 0) {
        analysis.score += urgencyMatches.length * weights.URGENCY_PHRASE;
        analysis.threats.push(`Urgency tactics: ${urgencyMatches.length} phrases`);
      }

      // Excessive exclamations
      const exclamationCount = (bodyText.match(/!/g) || []).length;
      if (exclamationCount > 10) {
        analysis.score += weights.EXCESSIVE_EXCLAMATIONS;
        analysis.threats.push('Excessive exclamation marks');
      }

      // Hidden iframes
      const hiddenIframes = this._findHiddenIframes(doc);
      if (hiddenIframes > 0) {
        analysis.score += hiddenIframes * weights.HIDDEN_IFRAME;
        analysis.threats.push(`${hiddenIframes} hidden iframe(s) detected`);
      }

      // Misleading links
      const misleadingLinks = this._findMisleadingLinks(doc);
      if (misleadingLinks > 0) {
        analysis.score += misleadingLinks * weights.MISLEADING_LINK;
        analysis.threats.push(`${misleadingLinks} misleading link(s)`);
      }

      // Obfuscated scripts
      const obfuscatedScripts = this._findObfuscatedScripts(doc);
      if (obfuscatedScripts > 0) {
        analysis.score += obfuscatedScripts * weights.OBFUSCATED_SCRIPT;
        analysis.threats.push(`${obfuscatedScripts} obfuscated script(s)`);
      }

    } catch (error) {
      this.logger.error('Content analysis error:', error);
    }

    return analysis;
  }

  /**
   * Find urgency phrases in text
   * @private
   */
  _findUrgencyPhrases(text) {
    return this.config.PATTERNS.URGENCY_PHRASES.filter(phrase =>
      text.includes(phrase.toLowerCase())
    );
  }

  /**
   * Find hidden iframes
   * @private
   */
  _findHiddenIframes(doc) {
    const iframes = doc.querySelectorAll('iframe');
    let count = 0;

    for (const iframe of iframes) {
      const style = window.getComputedStyle(iframe);
      if (style.display === 'none' || style.visibility === 'hidden' ||
        iframe.offsetWidth === 0 || iframe.offsetHeight === 0) {
        count++;
      }
    }

    return count;
  }

  /**
   * Find misleading links
   * @private
   */
  _findMisleadingLinks(doc) {
    const links = doc.querySelectorAll('a[href]');
    let count = 0;

    for (const link of links) {
      const displayText = link.textContent.toLowerCase();
      const actualHref = link.href.toLowerCase();

      for (const domain of this._legitimateDomains) {
        if (displayText.includes(domain) && !actualHref.includes(domain)) {
          count++;
          break;
        }
      }
    }

    return count;
  }

  /**
   * Find obfuscated scripts
   * @private
   */
  _findObfuscatedScripts(doc) {
    const scripts = doc.querySelectorAll('script');
    let count = 0;

    for (const script of scripts) {
      const content = script.textContent;
      if (content.includes('eval(') || content.includes('unescape(')) {
        count++;
      }
    }

    return count;
  }

  /**
   * Analyze forms
   * @private
   */
  _analyzeForms(doc, url) {
    const analysis = { score: 0, threats: [] };

    try {
      const forms = doc.querySelectorAll('form');
      const weights = this.config.SCORE_WEIGHTS;
      const urlObj = new URL(url);

      for (const form of forms) {
        const formData = this._analyzeForm(form, urlObj);
        analysis.score += formData.score;
        analysis.threats.push(...formData.threats);
      }

    } catch (error) {
      this.logger.error('Form analysis error:', error);
    }

    return analysis;
  }

  /**
   * Analyze single form
   * @private
   */
  _analyzeForm(form, urlObj) {
    const result = { score: 0, threats: [] };
    const inputs = form.querySelectorAll('input');
    const weights = this.config.SCORE_WEIGHTS;

    let hasPassword = false;
    let hasEmail = false;
    let hasCreditCard = false;
    let hasSSN = false;

    // Check input types
    for (const input of inputs) {
      const combined = `${input.type} ${input.name} ${input.id} ${input.placeholder}`.toLowerCase();

      if (input.type === 'password' || combined.includes('password')) hasPassword = true;
      if (input.type === 'email' || combined.includes('email')) hasEmail = true;
      if (combined.includes('card') || combined.includes('cvv')) hasCreditCard = true;
      if (combined.includes('ssn') || combined.includes('social')) hasSSN = true;
    }

    // Check form action
    const action = form.action || '';
    const isExternalAction = action && !action.includes(urlObj.hostname);

    // Scoring
    if (hasPassword && urlObj.protocol !== 'https:') {
      result.score += weights.PASSWORD_NO_HTTPS;
      result.threats.push('Password field on non-HTTPS page');
    }

    if (isExternalAction && (hasPassword || hasEmail || hasCreditCard)) {
      result.score += weights.EXTERNAL_FORM_ACTION;
      result.threats.push('Sensitive form submits to external domain');
    }

    if (hasEmail && hasPassword) {
      const isKnownDomain = this._legitimateDomains.some(d => urlObj.hostname.includes(d));
      if (urlObj.protocol === 'https:' && isKnownDomain) {
        result.score += weights.HTTPS_LOGIN_KNOWN;
      } else if (urlObj.protocol === 'https:') {
        result.score += weights.HTTPS_LOGIN_UNKNOWN;
      } else {
        result.score += weights.HTTP_LOGIN;
        result.threats.push('Login form on non-HTTPS page');
      }
    }

    if (hasCreditCard) {
      result.score += weights.CREDIT_CARD_REQUEST;
      result.threats.push('Credit card information requested');
    }

    if (hasSSN) {
      result.score += weights.SSN_REQUEST;
      result.threats.push('Social Security Number requested');
    }

    return result;
  }

  /**
   * Analyze behavioral patterns
   * @private
   */
  _analyzeBehavior(doc) {
    const analysis = { score: 0, threats: [] };

    try {
      const weights = this.config.SCORE_WEIGHTS;
      const bodyHTML = doc.body?.innerHTML || '';

      // Auto-submit forms
      if (bodyHTML.includes('submit()')) {
        analysis.score += weights.AUTO_SUBMIT_FORM;
        analysis.threats.push('Auto-submitting form detected');
      }

      // Popup windows
      if (bodyHTML.includes('window.open(')) {
        analysis.score += weights.POPUP_WINDOW;
        analysis.threats.push('Popup window code detected');
      }

      // Right-click disabled
      if (doc.body?.hasAttribute('oncontextmenu')) {
        analysis.score += weights.RIGHT_CLICK_DISABLED;
        analysis.threats.push('Right-click disabled');
      }

      // Clipboard access
      if (bodyHTML.includes('clipboard')) {
        analysis.score += weights.CLIPBOARD_ACCESS;
        analysis.threats.push('Clipboard access detected');
      }

    } catch (error) {
      this.logger.error('Behavior analysis error:', error);
    }

    return analysis;
  }

  /**
   * Get risk level from score
   * @private
   */
  _getRiskLevel(score) {
    const thresholds = this.config.RISK_THRESHOLDS;
    if (score >= thresholds.CRITICAL) return 'critical';
    if (score >= thresholds.HIGH) return 'high';
    if (score >= thresholds.MEDIUM) return 'medium';
    if (score >= thresholds.LOW) return 'low';
    return 'safe';
  }

  /**
   * Get cache statistics
   * @returns {Object|null} Cache stats or null
   */
  getCacheStats() {
    return this.cache ? this.cache.getStats() : null;
  }

  /**
   * Clear cache
   */
  clearCache() {
    if (this.cache) {
      this.cache.clear();
    }
  }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PhishingDetector;
}
