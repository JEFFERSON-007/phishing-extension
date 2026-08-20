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
    /** @type {Record<string, *>} Pending writes for debouncing */
    this._pendingWrites = {};
    /** @type {number|null} Timer ID for debouncing */
    this._writeTimer = null;
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
   * Set key-value pairs with debouncing to reduce disk I/O.
   * @param {Record<string, *>} items 
   * @param {number} delayMs 
   */
  async debouncedSet(items, delayMs = 1000) {
    Object.assign(this._pendingWrites, items);
    
    if (this._writeTimer) {
      clearTimeout(this._writeTimer);
    }
    
    this._writeTimer = setTimeout(() => {
      this.flush();
    }, delayMs);
  }

  /**
   * Immediately write all pending debounced items to storage.
   * @returns {Promise<void>}
   */
  async flush() {
    if (this._writeTimer) {
      clearTimeout(this._writeTimer);
      this._writeTimer = null;
    }
    
    if (Object.keys(this._pendingWrites).length > 0) {
      const itemsToSave = { ...this._pendingWrites };
      this._pendingWrites = {};
      await this.set(itemsToSave);
    }
  }

  /**
   * Clear all stored extension data.
   * @returns {Promise<void>}
   */
  async clear() {
    this._pendingWrites = {};
    if (this._writeTimer) clearTimeout(this._writeTimer);
    if (this.isChromeStorageAvailable) {
      return new Promise((resolve) => {
        chrome.storage.local.clear(() => resolve());
      });
    }
    this._fallbackStore.clear();
  }
}
