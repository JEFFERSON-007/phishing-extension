/**
 * Abstract Detector Interface Contract
 * Defines the standard lifecycle and mandatory methods for all security detectors & plugins.
 * @module DetectorInterface
 */

/**
 * Finding Object Specification
 * @typedef {Object} Finding
 * @property {string} id - Unique rule identifier.
 * @property {string} type - Finding type (e.g. 'HOMOGRAPH_ATTACK', 'CREDENTIAL_HARVESTING').
 * @property {string} description - Human-readable explanation.
 * @property {number} score - Contributed risk points (0-100).
 * @property {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'} severity - Severity tier.
 * @property {Record<string, *>} [metadata] - Contextual metadata.
 */

/**
 * Detector Result Output
 * @typedef {Object} DetectorResult
 * @property {number} score - Combined score (0-100).
 * @property {number} confidence - Confidence level (0.0 - 1.0).
 * @property {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'} severity - Highest severity detected.
 * @property {Finding[]} findings - Array of detailed findings.
 * @property {Record<string, *>} metadata - Arbitrary detector metadata.
 * @property {number} executionTime - Execution duration in milliseconds.
 */

export class DetectorInterface {
  constructor() {
    if (new.target === DetectorInterface) {
      throw new TypeError('Cannot instantiate abstract class DetectorInterface directly');
    }
  }

  /**
   * Return unique detector name.
   * @abstract
   * @returns {string}
   */
  name() {
    throw new Error('Method name() must be implemented');
  }

  /**
   * Return detector semantic version.
   * @abstract
   * @returns {string}
   */
  version() {
    return '1.0.0';
  }

  /**
   * Return execution priority (higher numbers execute earlier).
   * @abstract
   * @returns {number}
   */
  priority() {
    return 100;
  }

  /**
   * Return enabled state.
   * @abstract
   * @returns {boolean}
   */
  enabled() {
    return true;
  }

  /**
   * Check if detector supports the given analysis context.
   * @abstract
   * @param {Record<string, *>} context - Execution payload (e.g., { url, dom, headers }).
   * @returns {boolean}
   */
  supports(context) {
    return Boolean(context);
  }

  /**
   * Initialize detector instance with system configuration.
   * @abstract
   * @param {Record<string, *>} config 
   * @returns {Promise<void>|void}
   */
  initialize(config) {
    // Optional override
  }

  /**
   * Execute analysis against context payload.
   * @abstract
   * @param {Record<string, *>} context 
   * @returns {Promise<DetectorResult>}
   */
  async analyze(context) {
    throw new Error('Method analyze() must be implemented');
  }

  /**
   * Cleanup temporary resources or caches.
   * @abstract
   * @returns {Promise<void>|void}
   */
  cleanup() {
    // Optional override
  }
}
