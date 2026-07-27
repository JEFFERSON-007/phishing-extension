/**
 * Cryptographic & Hashing Utility
 * Provides fast SHA-256 hashing and secure token generation using Web Crypto API.
 * @module CryptoUtils
 */

export class CryptoUtils {
  /**
   * Compute SHA-256 hash of string using browser Web Crypto API.
   * @param {string} str - Raw string input.
   * @returns {Promise<string>} Hex-encoded SHA-256 digest string.
   */
  static async sha256(str) {
    if (!str || typeof str !== 'string') return '';
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Fast sync hash for in-memory string identifiers.
   * @param {string} str 
   * @returns {string} 32-bit hex hash string.
   */
  static fastHash(str) {
    if (!str || typeof str !== 'string') return '0';
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0; // Convert to 32bit integer
    }
    return (hash >>> 0).toString(16);
  }

  /**
   * Generate secure random UUID v4 string.
   * @returns {string}
   */
  static generateUUID() {
    if (typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    return '10000000-1000-4000-8000-100000000000'.replace(/[018]/g, c =>
      (Number(c) ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> Number(c) / 4).toString(16)
    );
  }
}
