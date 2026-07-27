# Security Assumptions & Threat Model

## Offline-First Privacy Guarantee
- Zero telemetry data, zero tracking, zero external network calls by default.
- 100% of URL, DOM, Form, and Behavioral analysis occurs locally in client JavaScript.

## DOM Isolation & Anti-Tampering
- Post-load security warning overlays are rendered inside an isolated **Shadow Root** with closed mode (`attachShadow({ mode: 'closed' })`).
- Malicious host page JavaScript cannot query, hide, or manipulate the Shadow DOM overlay node.

## Content Security Policy (CSP) & XSS Defenses
- Extension pages operate under strict Content Security Policy (`script-src 'self'`).
- `eval()`, `new Function()`, and inline scripts are strictly prohibited.
- All DOM node creations utilize `DOMSanitizer.createElement()` to prevent HTML injection XSS.
