/**
 * Chrome Storage Adapter Module
 * Promisified, type-safe storage interface wrapping chrome.storage.local with in-memory fallback.
 * @module ChromeStorageAdapter
 */

export class ChromeStorageAdapter {
  constructor() {
    /** @type {Map<string, *>} */
    this._fallbackStore = new Map();
    /** @type {boolean} */
    this.isChromeStorageAvailable = typeof chrome !== 'undefined' && Boolean(chrome.storage?.local);
  }

  /**
   * Get one or multiple keys from storage.
   * @param {string|string[]} keys 
   * @returns {Promise<Record<string, *>>}
   */
  async get(keys) {
    const keyArray = Array.isArray(keys) ? keys : [keys];

    if (this.isChromeStorageAvailable) {
      return new Promise((resolve) => {
        chrome.storage.local.get(keyArray, (result) => {
          if (chrome.runtime?.lastError) {
            // eslint-disable-next-line no-console
            console.error('Storage read error:', chrome.runtime.lastError);
            resolve({});
          } else {
            resolve(result || {});
          }
        });
      });
    }

    const output = {};
    for (const k of keyArray) {
      if (this._fallbackStore.has(k)) {
        output[k] = this._fallbackStore.get(k);
      }
    }
    return output;
  }

  /**
   * Set key-value pairs in storage.
   * @param {Record<string, *>} items 
   * @returns {Promise<void>}
   */
  async set(items) {
    if (!items || typeof items !== 'object') return;

    if (this.isChromeStorageAvailable) {
      return new Promise((resolve, reject) => {
        chrome.storage.local.set(items, () => {
          if (chrome.runtime?.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve();
          }
        });
      });
    }

    for (const [key, val] of Object.entries(items)) {
      this._fallbackStore.set(key, val);
    }
  }

  /**
   * Remove items by keys.
   * @param {string|string[]} keys 
   * @returns {Promise<void>}
   */
  async remove(keys) {
    const keyArray = Array.isArray(keys) ? keys : [keys];

    if (this.isChromeStorageAvailable) {
      return new Promise((resolve) => {
        chrome.storage.local.remove(keyArray, () => resolve());
      });
    }

    for (const k of keyArray) {
      this._fallbackStore.delete(k);
    }
  }

  /**
   * Clear all stored extension data.
   * @returns {Promise<void>}
   */
  async clear() {
    if (this.isChromeStorageAvailable) {
      return new Promise((resolve) => {
        chrome.storage.local.clear(() => resolve());
      });
    }
    this._fallbackStore.clear();
  }
}
