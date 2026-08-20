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

export class MLAdapterBase {
  constructor(name) {
    this.name = name;
    this.isLoaded = false;
    this.modelPath = null;
  }

  version() { return '1.0.0-stub'; }

  async load(modelPath) {
    this.modelPath = modelPath;
    this.isLoaded = true;
    return true;
  }

  async predict(features) {
    return this._fallbackResult();
  }

  async unload() {
    this.isLoaded = false;
    this.modelPath = null;
    return true;
  }

  healthCheck() {
    return { name: this.name, loaded: this.isLoaded, path: this.modelPath };
  }

  _fallbackResult() {
    return { score: 0.0, confidence: 0.0, predictedClass: 'benign', featureImportances: {} };
  }
}

export class URLModel extends MLAdapterBase {
  constructor() { super('URLModel'); }
}

export class DOMModel extends MLAdapterBase {
  constructor() { super('DOMModel'); }
}

export class NLPModel extends MLAdapterBase {
  constructor() { super('NLPModel'); }
}

/** Legacy MLAdapter wrapper to maintain compatibility with DetectionScheduler */
export class MLAdapter {
  constructor() {
    this.urlModel = new URLModel();
    this.domModel = new DOMModel();
    this.nlpModel = new NLPModel();
  }
  
  async predict(context) {
    // Structural stub
    return { score: 0.0, confidence: 0.0, predictedClass: 'benign' };
  }
}
