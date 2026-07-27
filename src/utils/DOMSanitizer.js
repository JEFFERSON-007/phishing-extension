/**
 * DOM Sanitizer Utility
 * Secure DOM element construction and HTML sanitization to eliminate XSS risks.
 * @module DOMSanitizer
 */

export class DOMSanitizer {
  /**
   * Escape special HTML characters in text string.
   * @param {string} str - Raw input text.
   * @returns {string} Escaped HTML string.
   */
  static escapeHTML(str) {
    if (!str || typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Safely create a DOM Element without innerHTML vulnerabilities.
   * @param {string} tag - HTML tag name (e.g. 'div', 'span').
   * @param {Record<string, string>} [attributes={}] - Attribute key-value dictionary.
   * @param {string|Array<Node|string>} [children=''] - Child text or nodes.
   * @returns {HTMLElement} Created DOM element.
   */
  static createElement(tag, attributes = {}, children = '') {
    const element = document.createElement(tag);

    for (const [key, value] of Object.entries(attributes)) {
      if (key.startsWith('on')) {
        // Disallow inline event attributes to prevent execution
        continue;
      }
      if (key === 'style' && typeof value === 'object') {
        Object.assign(element.style, value);
      } else {
        element.setAttribute(key, String(value));
      }
    }

    if (Array.isArray(children)) {
      for (const child of children) {
        if (typeof child === 'string') {
          element.appendChild(document.createTextNode(child));
        } else if (child instanceof Node) {
          element.appendChild(child);
        }
      }
    } else if (typeof children === 'string' && children.length > 0) {
      element.textContent = children;
    }

    return element;
  }

  /**
   * Sanitize URL string to guard against javascript: or data: URIs.
   * @param {string} url - Target URL string.
   * @returns {string} Sanitized safe URL or empty string.
   */
  static sanitizeURL(url) {
    if (!url || typeof url !== 'string') return '';
    const trimmed = url.trim();
    if (trimmed.toLowerCase().startsWith('javascript:') || trimmed.toLowerCase().startsWith('vbscript:')) {
      return 'about:blank';
    }
    return trimmed;
  }
}
