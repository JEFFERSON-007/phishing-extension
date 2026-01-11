/**
 * Cache Manager Module
 * LRU cache with TTL support for analysis results
 * @module cache-manager
 */

/**
 * LRU Cache with TTL support
 */
class CacheManager {
    /**
     * Create a cache manager
     * @param {number} maxEntries - Maximum number of entries
     * @param {number} ttlMs - Time to live in milliseconds
     */
    constructor(maxEntries = 1000, ttlMs = 30 * 60 * 1000) {
        this.maxEntries = maxEntries;
        this.ttlMs = ttlMs;
        this.cache = new Map();
        this.accessOrder = new Map(); // Track access order for LRU
        this.stats = {
            hits: 0,
            misses: 0,
            evictions: 0,
            sets: 0
        };
    }

    /**
     * Generate cache key from URL
     * @param {string} url - URL to cache
     * @returns {string} Cache key
     */
    _generateKey(url) {
        try {
            // Normalize URL for consistent caching
            const urlObj = new URL(url);
            // Remove hash and some query params that don't affect security
            urlObj.hash = '';
            return urlObj.toString().toLowerCase();
        } catch (e) {
            return url.toLowerCase();
        }
    }

    /**
     * Check if cache entry is expired
     * @param {Object} entry - Cache entry
     * @returns {boolean} True if expired
     */
    _isExpired(entry) {
        return Date.now() - entry.timestamp > this.ttlMs;
    }

    /**
     * Evict least recently used entry
     */
    _evictLRU() {
        // Find least recently used
        let lruKey = null;
        let lruTime = Infinity;

        for (const [key, time] of this.accessOrder.entries()) {
            if (time < lruTime) {
                lruTime = time;
                lruKey = key;
            }
        }

        if (lruKey) {
            this.cache.delete(lruKey);
            this.accessOrder.delete(lruKey);
            this.stats.evictions++;
        }
    }

    /**
     * Get cached analysis result
     * @param {string} url - URL to lookup
     * @returns {Object|null} Cached analysis or null
     */
    get(url) {
        const key = this._generateKey(url);
        const entry = this.cache.get(key);

        if (!entry) {
            this.stats.misses++;
            return null;
        }

        // Check if expired
        if (this._isExpired(entry)) {
            this.cache.delete(key);
            this.accessOrder.delete(key);
            this.stats.misses++;
            return null;
        }

        // Update access time (for LRU)
        this.accessOrder.set(key, Date.now());
        this.stats.hits++;

        return entry.data;
    }

    /**
     * Set cache entry
     * @param {string} url - URL to cache
     * @param {Object} data - Analysis data to cache
     */
    set(url, data) {
        const key = this._generateKey(url);

        // Evict if at capacity
        if (this.cache.size >= this.maxEntries && !this.cache.has(key)) {
            this._evictLRU();
        }

        // Store with timestamp
        this.cache.set(key, {
            data: data,
            timestamp: Date.now()
        });

        // Update access order
        this.accessOrder.set(key, Date.now());
        this.stats.sets++;
    }

    /**
     * Check if URL is in cache and not expired
     * @param {string} url - URL to check
     * @returns {boolean} True if cached
     */
    has(url) {
        const key = this._generateKey(url);
        const entry = this.cache.get(key);

        if (!entry) return false;

        if (this._isExpired(entry)) {
            this.cache.delete(key);
            this.accessOrder.delete(key);
            return false;
        }

        return true;
    }

    /**
     * Clear cache
     */
    clear() {
        this.cache.clear();
        this.accessOrder.clear();
        this.stats = {
            hits: 0,
            misses: 0,
            evictions: 0,
            sets: 0
        };
    }

    /**
     * Remove specific entry
     * @param {string} url - URL to remove
     */
    delete(url) {
        const key = this._generateKey(url);
        this.cache.delete(key);
        this.accessOrder.delete(key);
    }

    /**
     * Clean up expired entries
     * @returns {number} Number of entries removed
     */
    cleanup() {
        let removed = 0;
        const now = Date.now();

        for (const [key, entry] of this.cache.entries()) {
            if (now - entry.timestamp > this.ttlMs) {
                this.cache.delete(key);
                this.accessOrder.delete(key);
                removed++;
            }
        }

        return removed;
    }

    /**
     * Get cache statistics
     * @returns {Object} Cache stats
     */
    getStats() {
        const total = this.stats.hits + this.stats.misses;
        const hitRate = total > 0 ? (this.stats.hits / total) * 100 : 0;

        return {
            ...this.stats,
            size: this.cache.size,
            maxEntries: this.maxEntries,
            hitRate: hitRate.toFixed(2) + '%',
            memoryUsage: this._estimateMemoryUsage()
        };
    }

    /**
     * Estimate memory usage (rough approximation)
     * @returns {string} Human-readable memory size
     */
    _estimateMemoryUsage() {
        // Rough estimate: each entry ~1KB
        const bytes = this.cache.size * 1024;

        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }

    /**
     * Export cache to JSON (for persistence)
     * @returns {string} JSON string of cache
     */
    export() {
        const entries = Array.from(this.cache.entries()).map(([key, entry]) => ({
            key,
            data: entry.data,
            timestamp: entry.timestamp
        }));

        return JSON.stringify({
            entries,
            stats: this.stats,
            metadata: {
                maxEntries: this.maxEntries,
                ttlMs: this.ttlMs,
                exportedAt: Date.now()
            }
        });
    }

    /**
     * Import cache from JSON
     * @param {string} jsonString - JSON string to import
     * @returns {boolean} True if successful
     */
    import(jsonString) {
        try {
            const data = JSON.parse(jsonString);
            const now = Date.now();

            // Clear existing cache
            this.clear();

            // Import non-expired entries
            if (data.entries) {
                for (const entry of data.entries) {
                    if (now - entry.timestamp <= this.ttlMs) {
                        this.cache.set(entry.key, {
                            data: entry.data,
                            timestamp: entry.timestamp
                        });
                        this.accessOrder.set(entry.key, entry.timestamp);
                    }
                }
            }

            // Restore stats if available
            if (data.stats) {
                this.stats = { ...this.stats, ...data.stats };
            }

            return true;
        } catch (e) {
            console.error('Cache import failed:', e);
            return false;
        }
    }

    /**
     * Save cache to Chrome storage
     * @param {string} storageKey - Storage key to use
     * @returns {Promise<void>}
     */
    async saveToStorage(storageKey = 'phishing_detector_cache') {
        if (typeof chrome !== 'undefined' && chrome.storage) {
            try {
                const cacheData = this.export();
                await chrome.storage.local.set({ [storageKey]: cacheData });
            } catch (e) {
                console.error('Failed to save cache to storage:', e);
            }
        }
    }

    /**
     * Load cache from Chrome storage
     * @param {string} storageKey - Storage key to use
     * @returns {Promise<boolean>} True if loaded successfully
     */
    async loadFromStorage(storageKey = 'phishing_detector_cache') {
        if (typeof chrome !== 'undefined' && chrome.storage) {
            try {
                const result = await chrome.storage.local.get(storageKey);
                if (result[storageKey]) {
                    return this.import(result[storageKey]);
                }
            } catch (e) {
                console.error('Failed to load cache from storage:', e);
            }
        }
        return false;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CacheManager;
}
