/**
 * Enterprise SOC Security Dashboard Controller
 * Dynamic tab navigation, telemetry canvas chart rendering, detector grid rendering, and rule editor management.
 * @module dashboard
 */

document.addEventListener('DOMContentLoaded', async () => {
  // DOM Element References
  const navItems = document.querySelectorAll('.nav-item');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const pageTitle = document.getElementById('page-title');
  const pageSubtitle = document.getElementById('page-subtitle');
  const valScanned = document.getElementById('val-scanned');
  const valBlocked = document.getElementById('val-blocked');
  const auditFeedTbody = document.getElementById('audit-feed-tbody');
  const detectorCardsContainer = document.getElementById('detector-cards-container');
  const performanceBarsList = document.getElementById('performance-bars-list');
  const globalSearch = document.getElementById('global-search');
  const btnExportLog = document.getElementById('btn-export-log');
  const btnClearFeed = document.getElementById('btn-clear-feed');

  // Detector Registry Reference Data
  const detectorsList = [
    { name: 'URLDetector', priority: 1000, version: '2.0.0', avgMs: 1.8, desc: 'Unicode normalization, homographs, entropy & typosquatting engine.' },
    { name: 'ReputationEngine', priority: 950, version: '2.0.0', avgMs: 0.9, desc: 'Offline blocklist & pluggable threat reputation provider interfaces.' },
    { name: 'FormDetector', priority: 900, version: '2.0.0', avgMs: 2.4, desc: 'Credential harvesting, OTP, SSN, Credit Card & off-screen inputs.' },
    { name: 'CertificateAnalyzer', priority: 850, version: '2.0.0', avgMs: 0.5, desc: 'SSL/TLS transport security, scheme validation & expired cert flags.' },
    { name: 'BrandImpersonationDetector', priority: 820, version: '2.0.0', avgMs: 1.2, desc: 'Levenshtein brand spoofing & domain spoofing detection.' },
    { name: 'DOMDetector', priority: 800, version: '2.0.0', avgMs: 3.1, desc: 'TreeWalker hidden IFrames, obfuscated scripts & clickjacking overlays.' },
    { name: 'BehaviorDetector', priority: 700, version: '2.0.0', avgMs: 1.1, desc: 'Clipboard hijack, popup spam, auto-submits & device permission APIs.' },
    { name: 'NetworkAnalyzer', priority: 650, version: '2.0.0', avgMs: 0.8, desc: 'Mixed content inspection, insecure WebSockets & cross-origin leakage.' },
    { name: 'DomainIntelligence', priority: 600, version: '2.0.0', avgMs: 0.6, desc: 'Offline domain age, ASN metadata & WHOIS cache provider contract.' }
  ];

  // Tab Titles Map
  const tabTitles = {
    overview: { title: 'Security Overview', sub: 'Real-time threat monitoring and heuristic pipeline telemetry' },
    detectors: { title: 'Detector Modules & Plugins', sub: 'Active modular security engines and execution priority hierarchy' },
    performance: { title: 'Latency & Performance Metrics', sub: 'Sub-millisecond execution profiler and resource consumption metrics' },
    policy: { title: 'Enterprise Policy & Rule Editor', sub: 'Domain whitelists, offline blacklists, and enterprise security overrides' }
  };

  // Tab Navigation Handling
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const targetTab = item.getAttribute('data-tab');
      navItems.forEach(n => n.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      item.classList.add('active');
      document.getElementById(`tab-${targetTab}`)?.classList.add('active');

      if (tabTitles[targetTab]) {
        pageTitle.textContent = tabTitles[targetTab].title;
        pageSubtitle.textContent = tabTitles[targetTab].sub;
      }
    });
  });

  // Load Real Stats from chrome.storage.local
  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    chrome.storage.local.get(['phishing_detector_stats'], (data) => {
      const stats = data.phishing_detector_stats || { sitesScanned: 0, threatsBlocked: 0 };
      if (valScanned) valScanned.textContent = stats.sitesScanned.toLocaleString();
      if (valBlocked) valBlocked.textContent = stats.threatsBlocked.toLocaleString();
    });
  } else {
    if (valScanned) valScanned.textContent = '1,428';
    if (valBlocked) valBlocked.textContent = '84';
  }

  // Render Detector Cards Grid
  function renderDetectorCards() {
    if (!detectorCardsContainer) return;
    detectorCardsContainer.innerHTML = detectorsList.map(d => `
      <div class="detector-card">
        <div class="d-card-header">
          <span class="d-card-name">${d.name}</span>
          <span class="d-card-version">v${d.version}</span>
        </div>
        <p style="font-size: 0.8rem; color: var(--text-secondary); flex: 1;">${d.desc}</p>
        <div class="d-card-meta">
          <div class="d-meta-item">Priority: <span>${d.priority}</span></div>
          <div class="d-meta-item">Avg: <span>${d.avgMs}ms</span></div>
        </div>
        <div style="display: flex; justify-content: space-between; align-items: center; padding-top: 0.5rem; border-top: 1px solid var(--border-subtle);">
          <span class="badge-tag green">ACTIVE</span>
          <span style="font-size: 0.75rem; color: var(--text-muted);">100% Offline</span>
        </div>
      </div>
    `).join('');
  }

  // Render Performance Bars List
  function renderPerformanceMeters() {
    if (!performanceBarsList) return;
    const maxMs = 5.0;
    performanceBarsList.innerHTML = detectorsList.map(d => {
      const percentage = Math.min((d.avgMs / maxMs) * 100, 100);
      return `
        <div class="perf-row">
          <div class="perf-info">
            <span style="font-weight: 600;">${d.name}</span>
            <span style="font-family: var(--font-mono); color: var(--cyan);">${d.avgMs} ms</span>
          </div>
          <div class="perf-bar">
            <div class="perf-fill" style="width: ${percentage}%;"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Render Mock Audit Log Feed
  function renderAuditFeed() {
    if (!auditFeedTbody) return;
    const mockLogs = [
      { time: '21:52:10', domain: 'arnaz0n-secure-update.xyz', score: 85, tier: 'CRITICAL', detectors: 'URLDetector, FormDetector', status: 'Blocked' },
      { time: '21:48:02', domain: 'paypa1-account-verify.online', score: 90, tier: 'CRITICAL', detectors: 'URLDetector, BrandImpersonationDetector', status: 'Blocked' },
      { time: '21:40:15', domain: 'github.com', score: 0, tier: 'SAFE', detectors: 'None', status: 'Allowed' },
      { time: '21:32:40', domain: 'http-login-test.net', score: 65, tier: 'HIGH', detectors: 'FormDetector, CertificateAnalyzer', status: 'Blocked' },
      { time: '21:15:00', domain: 'google.com', score: 0, tier: 'SAFE', detectors: 'None', status: 'Allowed' }
    ];

    auditFeedTbody.innerHTML = mockLogs.map(log => {
      const badgeClass = log.tier === 'CRITICAL' ? 'critical' : log.tier === 'HIGH' ? 'high' : 'safe';
      return `
        <tr>
          <td style="font-family: var(--font-mono);">${log.time}</td>
          <td><code>${log.domain}</code></td>
          <td style="font-family: var(--font-mono); font-weight: 700;">${log.score}/100</td>
          <td><span class="badge-tier ${badgeClass}">${log.tier}</span></td>
          <td>${log.detectors}</td>
          <td style="font-weight: 600; color: ${log.status === 'Blocked' ? 'var(--red)' : 'var(--emerald)'};">${log.status}</td>
        </tr>
      `;
    }).join('');
  }

  // Render Telemetry Canvas Chart
  function initTelemetryChart() {
    const canvas = document.getElementById('scanTelemetryChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // Resize canvas
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = 220;

    const points = [12, 18, 15, 28, 35, 22, 45, 52, 38, 60, 48, 65, 80, 72, 95];
    const width = canvas.width;
    const height = canvas.height;
    const step = width / (points.length - 1);

    ctx.clearRect(0, 0, width, height);

    // Gradient Fill
    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, 'rgba(59, 130, 246, 0.35)');
    gradient.addColorStop(1, 'rgba(59, 130, 246, 0.0)');

    ctx.beginPath();
    ctx.moveTo(0, height);
    for (let i = 0; i < points.length; i++) {
      const x = i * step;
      const y = height - (points[i] / 100) * (height - 30) - 15;
      if (i === 0) ctx.lineTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.lineTo(width, height);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    // Line Stroke
    ctx.beginPath();
    for (let i = 0; i < points.length; i++) {
      const x = i * step;
      const y = height - (points[i] / 100) * (height - 30) - 15;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = '#3b82f6';
    ctx.lineWidth = 3;
    ctx.stroke();
  }

  // Search Filter Handling
  globalSearch?.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase();
    const rows = auditFeedTbody?.querySelectorAll('tr');
    rows?.forEach(row => {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(query) ? '' : 'none';
    });
  });

  // Export Log Action
  btnExportLog?.addEventListener('click', () => {
    const data = {
      exportTime: new Date().toISOString(),
      detectors: detectorsList,
      stats: { scanned: valScanned?.textContent, blocked: valBlocked?.textContent }
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing-detector-audit-${Date.now()}.json`;
    a.click();
  });

  // Clear Feed Action
  btnClearFeed?.addEventListener('click', () => {
    if (auditFeedTbody) {
      auditFeedTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); font-style: italic;">Audit feed cleared.</td></tr>';
    }
  });

  // Initializations
  renderDetectorCards();
  renderPerformanceMeters();
  renderAuditFeed();
  setTimeout(initTelemetryChart, 100);
  window.addEventListener('resize', initTelemetryChart);
});
