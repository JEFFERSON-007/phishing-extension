/**
 * Plugin Registry & Detector Discovery Engine
 * Manages registration, prioritization, and lifecycle of modular security detectors.
 * @module PluginRegistry
 */

import { DetectorInterface } from './DetectorInterface.js';

export class PluginRegistry {
  constructor() {
    /** @type {Map<string, DetectorInterface>} */
    this.detectors = new Map();
  }

  /**
   * Register a new detector plugin.
   * @param {DetectorInterface} detector 
   */
  register(detector) {
    if (!(detector instanceof DetectorInterface)) {
      throw new TypeError(`Detector must inherit from DetectorInterface`);
    }

    const name = detector.name();
    if (this.detectors.has(name)) {
      // eslint-disable-next-line no-console
      console.warn(`Overwriting existing detector registration: ${name}`);
    }

    this.detectors.set(name, detector);
  }

  /**
   * Unregister a detector plugin by name.
   * @param {string} name 
   * @returns {boolean}
   */
  unregister(name) {
    if (this.detectors.has(name)) {
      const detector = this.detectors.get(name);
      try {
        detector.cleanup();
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`Error cleaning up detector ${name}:`, err);
      }
      return this.detectors.delete(name);
    }
    return false;
  }

  /**
   * Get registered detector by name.
   * @param {string} name 
   * @returns {DetectorInterface|undefined}
   */
  get(name) {
    return this.detectors.get(name);
  }

  /**
   * Get all enabled detectors sorted by priority (highest first).
   * @param {Record<string, *>} [context] - Optional analysis context filter.
   * @returns {DetectorInterface[]}
   */
  getSortedDetectors(context = null) {
    const list = Array.from(this.detectors.values()).filter(d => {
      if (!d.enabled()) return false;
      if (context && !d.supports(context)) return false;
      return true;
    });

    return list.sort((a, b) => b.priority() - a.priority());
  }

  /**
   * Initialize all registered detectors with configuration.
   * @param {Record<string, *>} config 
   * @returns {Promise<void>}
   */
  async initializeAll(config) {
    for (const detector of this.detectors.values()) {
      try {
        await detector.initialize(config);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`Failed to initialize detector ${detector.name()}:`, err);
      }
    }
  }
}
