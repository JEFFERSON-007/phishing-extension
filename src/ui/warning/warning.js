/**
 * Standalone Warning Page Logic
 * Parses URL query parameters, displays threat evidence, exports JSON diagnostic logs, and handles double-confirmation bypass.
 * @module warning
 */

document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get('url') || 'Unknown URL';
  const score = params.get('score') || '80';
  const reason = params.get('reason') || 'High risk phishing threat detected.';

  document.getElementById('score-val').textContent = score;
  document.getElementById('target-url').textContent = targetUrl;
  document.getElementById('reasons-list').innerHTML = `<div class="reason-item">• ${decodeURIComponent(reason)}</div>`;

  document.getElementById('btn-back')?.addEventListener('click', () => {
    window.history.back();
  });

  document.getElementById('btn-export')?.addEventListener('click', () => {
    const data = {
      timestamp: new Date().toISOString(),
      targetUrl,
      riskScore: parseInt(score, 10),
      reason: decodeURIComponent(reason)
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing-threat-report-${Date.now()}.json`;
    a.click();
  });

  document.getElementById('btn-proceed')?.addEventListener('click', () => {
    if (confirm('Warning: Proceeding to this site may expose your accounts to security risks. Continue anyway?')) {
      try {
        const hostname = new URL(targetUrl).hostname;
        if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
          chrome.runtime.sendMessage({ action: 'ALLOW_SESSION_DOMAIN', domain: hostname }, () => {
            window.location.href = targetUrl;
          });
        } else {
          window.location.href = targetUrl;
        }
      } catch {
        window.location.href = targetUrl;
      }
    }
  });
});
