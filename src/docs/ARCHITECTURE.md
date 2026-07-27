# Enterprise Browser Security Platform — Architecture Guide

## Overview
The **Phishing Detector Security Platform** is a modular, offline-first browser security engine built on Chrome Manifest V3 standards.

```
URL / DOM Context
      │
      ▼
EnterprisePolicyEngine ──(Whitelist/Override Match?)──► Return Immediate Allowed State
      │
      ▼ (No Override)
PluginRegistry (Sorted Enabled Detectors)
      │
      ├── URLDetector (Homographs, Entropy, Punycode, TLDs)
      ├── FormDetector (Credential, SSN, OTP, Crypto harvesting)
      ├── DOMDetector (Hidden IFrames, Obfuscated scripts, Fake Overlays)
      ├── BehaviorDetector (Clipboard, Popups, Auto-submits)
      ├── CertificateAnalyzer (SSL/TLS security state)
      ├── BrandImpersonationDetector (Levenshtein, Title matching)
      ├── NetworkAnalyzer (Mixed Content, WebSockets)
      ├── ReputationEngine (Offline threat lists)
      └── DomainIntelligence (DNS & Domain Metadata)
      │
      ▼
RiskFusionEngine (Weighted Fusion & Priority Multipliers)
      │
      ▼
MLAdapter Slot (Extensible Custom Model Plugin - Zero Dependencies by default)
      │
      ▼
ExplainableAIEngine (Deterministic Human-Readable Reasons)
      │
      ▼
Enforcement (Service Worker Badge & Shadow DOM Warning Overlay)
```

## SOLID Principles & Key Component Responsibilities

1. **`DetectorInterface`**: Abstract contract requiring `name()`, `priority()`, `supports()`, and `analyze()`.
2. **`PluginRegistry`**: Dynamically manages detector discovery, registration, and priority sorting.
3. **`DetectionEngine`**: Parallel execution manager providing error isolation for each detector.
4. **`RiskFusionEngine`**: Fuses scores using confidence multipliers instead of linear additions.
5. **`ExplainableAIEngine`**: Maps findings directly to evidence-backed reasons without AI hallucinations.
6. **`MLAdapter` / `VisualAdapter` / `OCRAdapter`**: Clean interface slots allowing custom ML models, visual hash algorithms, or OCR engines to be attached seamlessly without altering core logic.
