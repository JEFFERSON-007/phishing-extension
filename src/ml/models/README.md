# 🧠 Custom ML Model Upload & Integration Guide

This directory is the dedicated location for uploading your trained machine learning model artifacts (URL classifier, DOM NLP model, or Visual CNN).

---

## 📁 1. Directory Structure for Uploading Models

Place your model files inside `src/ml/models/`:

```
src/ml/models/
├── url-model/
│   ├── model.json                  # TensorFlow.js architecture & topology
│   └── group1-shard1of1.bin        # Weight binary shards
│   <!-- OR for ONNX -->
│   └── model.onnx                  # ONNX Runtime model file
└── README.md
```

---

## ⚙️ 2. How to Wire Your ML Model into the Platform

### Step A: Update `manifest.json` (Expose Model Artifacts)
Ensure your model files are listed in `manifest.json` under `web_accessible_resources`:

```json
"web_accessible_resources": [
  {
    "resources": [
      "src/ml/models/*"
    ],
    "matches": ["<all_urls>"]
  }
]
```

### Step B: Attach Model in `src/background/service-worker.js`
In `src/background/service-worker.js`, initialize your model during startup:

```javascript
import { MLAdapter } from '../adapters/ml/MLAdapter.js';

// Load model locally from extension URL
const modelPath = chrome.runtime.getURL('src/ml/models/url-model/model.json');
await engine.mlAdapter.loadModel(modelPath);
```

### Step C: Customize Feature Extractor in `src/adapters/ml/MLAdapter.js`
In `src/adapters/ml/MLAdapter.js`, update the `predict(features)` method to pass feature vectors into your model:

```javascript
async predict(features) {
  if (!this.isLoaded) return this._fallbackResult();

  // Extract feature vector from context (e.g. Shannon entropy, URL length, dot count, homograph count)
  const inputVector = [
    features.url.length,
    features.entropy || 0,
    features.homographCount || 0
  ];

  // Run prediction (e.g. tf.predict or ortSession.run)
  const score = await myModel.predict(inputVector);

  return {
    score: score, // Value between 0.0 and 1.0
    confidence: 0.95,
    predictedClass: score > 0.5 ? 'phishing' : 'benign',
    featureImportances: { urlEntropy: 0.4, homographs: 0.6 }
  };
}
```

---

## 🔒 Security Guarantee
Loading models from `chrome.runtime.getURL('src/ml/models/...')` maintains **100% offline privacy** — zero network requests are made to external servers!
