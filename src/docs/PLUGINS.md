# Plugin & ML Extension Developer Guide

## How to Create a Custom Detector Plugin

Every detector plugin must inherit from `DetectorInterface`:

```javascript
import { DetectorInterface } from '../plugins/DetectorInterface.js';

export class CustomDetector extends DetectorInterface {
  name() { return 'CustomDetector'; }
  version() { return '1.0.0'; }
  priority() { return 500; }
  enabled() { return true; }

  supports(context) {
    return Boolean(context && context.url);
  }

  async analyze(context) {
    const findings = [];
    let score = 0;

    if (context.url.includes('suspicious-keyword')) {
      findings.push({
        id: 'CUSTOM_THREAT_RULE',
        type: 'CUSTOM_INDICATOR',
        description: 'Detected custom threat indicator.',
        score: 30,
        severity: 'MEDIUM'
      });
      score = 30;
    }

    return {
      score,
      confidence: 0.9,
      severity: 'MEDIUM',
      findings,
      metadata: { detector: this.name() },
      executionTime: 1.2
    };
  }
}
```

### Registering the Plugin
To register your plugin, simply import it in `service-worker.js`:

```javascript
import { CustomDetector } from './detectors/custom/CustomDetector.js';
registry.register(new CustomDetector());
```

---

## How to Attach a Custom ML Model via `MLAdapter`

To plug your trained machine learning model (TensorFlow.js, ONNX Runtime Web, or custom WASM) into the pipeline:

1. Subclass `MLAdapter` in `src/adapters/ml/`:
```javascript
import { MLAdapter } from './MLAdapter.js';

export class CustomONNXAdapter extends MLAdapter {
  async loadModel(modelPath) {
    // Load ONNX or TensorFlow model session
    this.session = await ort.InferenceSession.create(modelPath);
    this.isLoaded = true;
    return true;
  }

  async predict(features) {
    if (!this.isLoaded) return this._fallbackResult();
    // Run model inference
    const tensor = this._convertFeaturesToTensor(features);
    const output = await this.session.run({ input: tensor });
    const score = output.probability.data[0];

    return {
      score,
      confidence: 0.95,
      predictedClass: score > 0.5 ? 'phishing' : 'benign',
      featureImportances: {}
    };
  }
}
```

2. Assign your ML adapter to `engine.mlAdapter` in `service-worker.js`.
