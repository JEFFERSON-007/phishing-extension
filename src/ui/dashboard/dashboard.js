/**
 * Enterprise Dashboard Interface Logic
 * Fetches platform stats and detector telemetry from storage.
 * @module dashboard
 */

document.addEventListener('DOMContentLoaded', async () => {
  const statScanned = document.getElementById('stat-scanned');
  const statBlocked = document.getElementById('stat-blocked');

  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    chrome.storage.local.get(['phishing_detector_stats'], (data) => {
      const stats = data.phishing_detector_stats || { sitesScanned: 0, threatsBlocked: 0 };
      if (statScanned) statScanned.textContent = String(stats.sitesScanned);
      if (statBlocked) statBlocked.textContent = String(stats.threatsBlocked);
    });
  }
});
