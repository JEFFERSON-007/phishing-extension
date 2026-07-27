/**
 * Multi-Layer LRU Cache Module
 * High-performance bounded caching with Time-To-Live (TTL) expiration and memory optimization.
 * @module MultiLayerCache
 */

export class MultiLayerCache {
  /**
   * Create a MultiLayerCache instance.
   * @param {number} [maxEntries=1000] - Maximum entry count.
   * @param {number} [ttlMs=1800000] - Time To Live in milliseconds (default 30 mins).
   */
  constructor(maxEntries = 1000, ttlMs = 30 * 60 * 1000) {
    /** @type {number} */
    this.maxEntries = maxEntries;
    /** @type {number} */
    this.ttlMs = ttlMs;
    /** @type {Map<string, { value: *, timestamp: number }>} */
    this.cache = new Map();

    /** @type {number} */
    this.hits = 0;
    /** @type {number} */
    this.misses = 0;
  }

  /**
   * Retrieve item from cache if present and non-expired.
   * @param {string} key 
   * @returns {*|null} Cached item value or null if expired/absent.
   */
  get(key) {
    if (!this.cache.has(key)) {
      this.misses++;
      return null;
    }

    const item = this.cache.get(key);
    const now = Date.now();

    if (now - item.timestamp > this.ttlMs) {
      this.cache.delete(key);
      this.misses++;
      return null;
    }

    // Refresh key position for LRU semantics
    this.cache.delete(key);
    this.cache.set(key, item);
    this.hits++;
    return item.value;
  }

  /**
   * Insert item into LRU cache.
   * @param {string} key 
   * @param {*} value 
   */
  set(key, value) {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxEntries) {
      // Evict least recently used (first inserted key in Map)
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key, {
      value,
      timestamp: Date.now()
    });
  }

  /**
   * Check if active key exists.
   * @param {string} key 
   * @returns {boolean}
   */
  has(key) {
    return this.get(key) !== null;
  }

  /**
   * Delete entry.
   * @param {string} key 
   * @returns {boolean}
   */
  delete(key) {
    return this.cache.delete(key);
  }

  /**
   * Clear all entries and reset stats.
   */
  clear() {
    this.cache.clear();
    this.hits = 0;
    this.misses = 0;
  }

  /**
   * Evict all expired entries.
   */
  purgeExpired() {
    const now = Date.now();
    for (const [key, item] of this.cache.entries()) {
      if (now - item.timestamp > this.ttlMs) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Return cache health and hit-ratio metrics.
   * @returns {{ size: number, maxEntries: number, hits: number, misses: number, hitRatio: number }}
   */
  getStats() {
    const total = this.hits + this.misses;
    return {
      size: this.cache.size,
      maxEntries: this.maxEntries,
      hits: this.hits,
      misses: this.misses,
      hitRatio: total > 0 ? parseFloat((this.hits / total).toFixed(4)) : 0.0
    };
  }
}
