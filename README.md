# IIPS - Enterprise Hybrid Browser Security Platform

A modular, enterprise-grade, offline-first browser security platform providing real-time phishing, scam, and threat detection using multi-layered heuristic analysis, a dynamic plugin registry, weighted risk fusion, explainable threat reasoning, and pluggable ML/OCR/Visual adapters.

[![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Privacy First](https://img.shields.io/badge/Privacy-100%25%20Offline-green.svg)](#-privacy--zero-telemetry)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features & Capabilities

### Specialized Security Detectors (src/detectors/)
* **URL Analysis**: Unicode normalization (NFC/NFD), Punycode decoding (xn--), homograph lookalikes, Shannon entropy calculation, typosquatting with keyboard proximity matrix, character substitutions (0 to o, 1 to l, @ to a), raw IP hostnames, non-standard ports, tracking parameters, data/blob URLs, and high-risk TLDs (.tk, .xyz, .top, etc.).
* **Form Protection**: Detects credential harvesting, OTP inputs, banking forms, credit card requests, Social Security Numbers (SSN), Government IDs, crypto wallet seed phrases, hidden off-screen inputs, and autofill exploitation vectors.
* **DOM & Script Scanning**: Incremental TreeWalker DOM scanner detecting hidden zero-pixel IFrames, canvas tricks, script obfuscation (eval(), unescape(), hex encoding), misleading display link texts, and fake fullscreen clickjacking masks.
* **Behavioral Monitoring**: Tracks unauthorized clipboard read/writes, right-click context menu restrictions, popup window spam, auto-submitting forms, and sensitive API permissions (WebUSB, Bluetooth, WebRTC).
* **SSL/TLS Transport Security**: Verifies scheme integrity, insecure HTTP credentials, and offline transport state.
* **Brand Impersonation**: Rules-based title and domain spoofing checks using Levenshtein distance against global brand target lists (Google, PayPal, Chase, Apple, Amazon, Microsoft, Meta).
* **Network Inspector**: Detects mixed content assets, insecure WebSockets (ws:// on HTTPS origins), and cross-origin resource leakage.
* **Reputation Engine**: Offline-first reputation lookup with pluggable interfaces for optional cloud databases (Safe Browsing, VirusTotal, PhishTank; disabled by default).

### Central Detection Engine & Risk Fusion (src/core/)
* **Plugin Registry (DetectorInterface)**: Modular architecture allowing new detector plugins to be registered, prioritized, and executed dynamically.
* **Risk Fusion Engine**: Combines detector outputs using confidence weighting, priority multipliers, and severity caps rather than simple linear addition.
* **Explainable AI Engine**: Generates evidence-backed, human-readable threat reasons mapped directly to detector findings without AI hallucinations.
* **Enterprise Policy Engine**: Evaluates domain whitelists, blacklists, temporary session overrides, and custom enterprise rules.

### ML, Visual & OCR Adapters (src/adapters/)
* **Zero ML Dependencies**: The platform ships 100% offline with zero machine learning dependencies, zero weights, and zero online calls by default.
* **Predefined Extension Adapters**: Clean interface contracts (MLAdapter, VisualAdapter, OCRAdapter) allow custom TensorFlow.js, ONNX Runtime Web, OpenCV, or Tesseract models to be plugged in seamlessly.

---

## Architecture & Project Layout

```
IIPS/
├── manifest.json              # Chrome Manifest V3 configuration
├── README.md                  # Main platform documentation
├── HOW-IT-WORKS.md            # Detailed protection flow breakdown
├── icons/                     # Platform visual assets
└── src/
    ├── core/
    │   ├── engine/            # Central DetectionEngine orchestrator
    │   ├── fusion/            # Weighted RiskFusionEngine
    │   ├── explainable/       # ExplainableAIEngine (Threat explanations)
    │   └── policy/            # EnterprisePolicyEngine (Whitelists & Overrides)
    ├── detectors/             # Modular Security Detectors
    │   ├── url/               # URLDetector
    │   ├── form/              # FormDetector
    │   ├── dom/               # DOMDetector
    │   ├── behavior/          # BehaviorDetector
    │   ├── certificate/       # CertificateAnalyzer
    │   ├── dns/               # DomainIntelligence
    │   ├── brand/             # BrandImpersonationDetector
    │   ├── network/           # NetworkAnalyzer
    │   └── reputation/        # ReputationEngine
    ├── adapters/              # Future Extensible Adapters
    │   ├── ml/                # MLAdapter stub (TensorFlow/ONNX contract)
    │   ├── visual/            # VisualAdapter stub (pHash/Canvas contract)
    │   └── ocr/               # OCRAdapter stub (Text recognition contract)
    ├── plugins/               # DetectorInterface & PluginRegistry
    ├── cache/                 # MultiLayerCache (Bounded LRU with TTL)
    ├── utils/                 # DOMSanitizer, EntropyUtils, PunycodeUtils, CryptoUtils, Logger
    ├── storage/               # ChromeStorageAdapter (Local storage wrapper)
    ├── background/            # Service Worker (Pre-nav interceptor & badge UI)
    ├── content/               # Content script (DOM observer & Shadow DOM overlay)
    ├── ui/
    │   ├── popup/             # Security popup controls
    │   ├── warning/           # Standalone warning page & JSON export
    │   └── dashboard/         # Enterprise Security Dashboard
    ├── tests/                 # Unit & integration test suites
    └── docs/                  # Architecture, Plugin & Security guides
```

---

## Installation & Setup

### Chrome / Edge / Brave
1. Download or clone this repository:
   ```bash
   git clone https://github.com/JEFFERSON-007/phishing-extension.git
   ```
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked**.
5. Select the repository root folder (`Phishing Extension`).
6. The IIPS icon will appear in your toolbar.

### Firefox
1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on**.
3. Select `manifest.json` from the extension folder.

---

## Risk Tiers & Scoring

Scores are calculated on a **0-100 Scale** across 5 threat levels:

| Risk Score | Classification | Toolbar Badge | Default Action |
| :---: | :---: | :---: | :--- |
| **0 - 19** | **SAFE** | None | Normal browsing |
| **20 - 39** | **LOW** | None | Silent tracking & score update |
| **40 - 59** | **MEDIUM** | Yellow "!" | Warning badge indicator |
| **60 - 79** | **HIGH** | Orange "!!" | Renders isolated Shadow DOM warning overlay |
| **80 - 100** | **CRITICAL** | Red "!!!" | Pre-navigation block to standalone warning page |

---

## Privacy & Zero Telemetry Guarantee

* **100% Offline-First**: All analysis runs locally inside client browser JavaScript.
* **Zero Telemetry**: No user data, URLs, or DOM contents are ever transmitted to external servers.
* **Zero External API Dependencies**: No cloud APIs required for default operation.
* **Anti-Tamper Security**: Post-load overlays render within an isolated `#iips-detector-root` Shadow DOM (`mode: 'closed'`).

---

## Developer Documentation

For detailed technical guides and architecture diagrams, check out the documentation in `src/docs/`:
* Architecture Guide (`src/docs/ARCHITECTURE.md`): Technical architecture specification and SOLID principles.
* Plugin & ML Guide (`src/docs/PLUGINS.md`): How to build custom detectors and attach ML models via `MLAdapter`.
* Security Model (`src/docs/SECURITY.md`): Threat model, CSP constraints, and memory isolation design.

---

## License

This project is open-source and provided for personal and educational security use.
