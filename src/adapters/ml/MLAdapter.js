/**
 * ML Adapter Interface & Fallback Stub
 * Predefined abstract contract for plugging custom machine learning models into the detection pipeline.
 * NOTE: Contains NO ML libraries, zero weights, and zero online calls by default.
 * @module MLAdapter
 */

/**
 * ML Prediction Result
 * @typedef {Object} MLPrediction
 * @property {number} score - Risk score between 0.0 and 1.0.
 * @property {number} confidence - Model confidence score between 0.0 and 1.0.
 * @property {string} predictedClass - Class name (e.g., 'phishing', 'benign').
 * @property {Record<string, number>} featureImportances - Feature attribution weights.
 */

export class MLAdapter {
  constructor() {
    this.isLoaded = false;
    this.modelPath = null;
  }

  /**
   * Return adapter / model version string.
   * @returns {string}
   */
  version() {
    return '1.0.0-stub';
  }

  /**
   * Load custom ML model weights/artefact from local URI.
   * @param {string} modelPath 
   * @returns {Promise<boolean>}
   */
  async loadModel(modelPath) {
    this.modelPath = modelPath;
    // Stub implementation: Returns true to confirm interface contract readiness
    this.isLoaded = true;
    return true;
  }

  /**
   * Predict classification score given input feature map.
   * @param {Record<string, *>} features - Feature vector (URL features, DOM metrics, NLP tokens).
   * @returns {Promise<MLPrediction>}
   */
  async predict(features) {
    if (!features) {
      return this._fallbackResult();
    }

    // Default Fallback Stub: Returns zero risk contribution when no ML model is attached
    return {
      score: 0.0,
      confidence: 0.0,
      predictedClass: 'benign',
      featureImportances: {}
    };
  }

  /**
   * Return current model prediction confidence capability.
   * @returns {number}
   */
  confidence() {
    return this.isLoaded ? 1.0 : 0.0;
  }

  /**
   * Return metadata details about the loaded model.
   * @returns {Record<string, *>}
   */
  metadata() {
    return {
      name: 'MLAdapterStub',
      modelPath: this.modelPath,
      isLoaded: this.isLoaded,
      supportedFrameworks: ['TensorFlow.js', 'ONNX Runtime Web', 'Custom JS Engine']
    };
  }

  /**
   * @private
   * @returns {MLPrediction}
   */
  _fallbackResult() {
    return {
      score: 0.0,
      confidence: 0.0,
      predictedClass: 'unknown',
      featureImportances: {}
    };
  }
}
