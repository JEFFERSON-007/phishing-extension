/**
 * Popup Interface Logic
 * Fetches current active tab security status and updates popup dashboard elements safely.
 * @module popup
 */

document.addEventListener('DOMContentLoaded', async () => {
  const scoreNum = document.getElementById('score-number');
  const statusTitle = document.getElementById('status-title');
  const gaugeCircle = document.getElementById('gauge-circle');
  const findingsList = document.getElementById('findings-list');
  const btnRescan = document.getElementById('btn-rescan');
  const btnDashboard = document.getElementById('btn-dashboard');

  let currentTabId = null;

  if (typeof chrome !== 'undefined' && chrome.tabs) {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs[0] && tabs[0].id) {
        currentTabId = tabs[0].id;
        fetchSecurityStatus(currentTabId);
      }
    } catch {}
  }

  btnRescan?.addEventListener('click', () => {
    if (currentTabId && typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.sendMessage(currentTabId, { action: 'TRIGGER_DOM_SCAN' }, () => {
        if (chrome.runtime.lastError) {
          // Ignore connection errors on unscriptable tabs (e.g. chrome:// extensions)
        }
      });
      statusTitle.textContent = 'Re-scanning...';
      setTimeout(() => fetchSecurityStatus(currentTabId), 800);
    }
  });

  btnDashboard?.addEventListener('click', () => {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url: chrome.runtime.getURL('src/ui/dashboard/dashboard.html') });
    }
  });

  function fetchSecurityStatus(tabId) {
    if (typeof chrome === 'undefined' || !chrome.runtime) return;

    chrome.runtime.sendMessage({ action: 'GET_TAB_SECURITY_STATUS', tabId }, (response) => {
      if (chrome.runtime.lastError) {
        // Silently handle disconnected background worker or non-web tabs
        renderDefaultSafeState();
        return;
      }
      if (response && response.result) {
        renderStatus(response.result);
      } else {
        renderDefaultSafeState();
      }
    });
  }

  function escapeHTML(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function renderDefaultSafeState() {
    scoreNum.textContent = '0';
    statusTitle.textContent = 'SAFE';
    gaugeCircle.style.borderColor = '#22c55e';
    findingsList.innerHTML = '<div class="finding-empty">No suspicious threat indicators detected on this active tab.</div>';
    
    ['url-status', 'form-status', 'dom-status', 'behavior-status'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = 'Safe';
    });
  }

  function renderStatus(result) {
    const score = result.riskScore || 0;
    scoreNum.textContent = String(score);
    statusTitle.textContent = result.classification || 'SAFE';

    let color = '#22c55e';
    if (score >= 80) color = '#dc2626';
    else if (score >= 60) color = '#ea580c';
    else if (score >= 40) color = '#f59e0b';

    gaugeCircle.style.borderColor = color;

    const triggered = result.detectorsTriggered || [];
    const urlEl = document.getElementById('url-status');
    const formEl = document.getElementById('form-status');
    const domEl = document.getElementById('dom-status');
    const behEl = document.getElementById('behavior-status');

    if (urlEl) urlEl.textContent = (triggered.includes('URLDetector') || triggered.includes('ReputationEngine') || triggered.includes('BrandImpersonationDetector')) ? 'Flagged' : 'Safe';
    if (formEl) formEl.textContent = triggered.includes('FormDetector') ? 'Flagged' : 'Safe';
    if (domEl) domEl.textContent = triggered.includes('DOMDetector') ? 'Flagged' : 'Safe';
    if (behEl) behEl.textContent = triggered.includes('BehaviorDetector') ? 'Flagged' : 'Safe';

    if (result.reasons && result.reasons.length > 0) {
      findingsList.innerHTML = result.reasons.map(r => `<div class="finding-item">• ${escapeHTML(r)}</div>`).join('');
    } else {
      renderDefaultSafeState();
    }
  }
});
