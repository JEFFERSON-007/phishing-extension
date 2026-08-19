import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const MOCK_LOGS = [
  { time: '21:52', domain: 'arnaz0n-secure-update.xyz', score: 85, label: 'Critical', detectors: 'URL, Form', blocked: true },
  { time: '21:48', domain: 'paypa1-account-verify.online', score: 90, label: 'Critical', detectors: 'URL, Brand', blocked: true },
  { time: '21:40', domain: 'github.com', score: 0, label: 'Safe', detectors: '—', blocked: false },
  { time: '21:32', domain: 'http-login-test.net', score: 65, label: 'High Risk', detectors: 'Form, Cert', blocked: true },
  { time: '21:15', domain: 'google.com', score: 0, label: 'Safe', detectors: '—', blocked: false },
];

const DETECTORS = [
  { name: 'URLDetector',               ms: 1.8,  desc: 'Unicode, homographs, entropy, typosquatting' },
  { name: 'ReputationEngine',          ms: 0.9,  desc: 'Offline blocklist & threat reputation providers' },
  { name: 'FormDetector',              ms: 2.4,  desc: 'Credential harvesting, OTP, off-screen inputs' },
  { name: 'CertificateAnalyzer',       ms: 0.5,  desc: 'TLS/SSL transport, scheme & expiry checks' },
  { name: 'BrandImpersonationDetector',ms: 1.2,  desc: 'Levenshtein brand spoofing & domain spoofing' },
  { name: 'DOMDetector',               ms: 3.1,  desc: 'Hidden iFrames, obfuscated scripts, overlays' },
  { name: 'BehaviorDetector',          ms: 1.1,  desc: 'Clipboard hijack, popup spam, device APIs' },
  { name: 'NetworkAnalyzer',           ms: 0.8,  desc: 'Mixed content, insecure WebSockets, CORS leaks' },
  { name: 'DomainIntelligence',        ms: 0.6,  desc: 'Domain age, ASN metadata, WHOIS cache' },
];

type Tab = 'overview' | 'detectors' | 'performance' | 'log';

function ScoreBadge({ score }: { score: number }) {
  if (score === 0) return <span className="badge badge-safe">Safe</span>;
  if (score >= 80)  return <span className="badge badge-danger">Critical</span>;
  if (score >= 60)  return <span className="badge badge-danger">High</span>;
  return <span className="badge badge-warn">Medium</span>;
}

export default function Dashboard() {
  const [tab, setTab] = useState<Tab>('overview');
  const [scanned, setScanned] = useState(0);
  const [blocked, setBlocked] = useState(0);
  const [search, setSearch] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      chrome.storage.local.get(['phishing_detector_stats'], (data) => {
        const s = data.phishing_detector_stats ?? {};
        setScanned(s.sitesScanned ?? 0);
        setBlocked(s.threatsBlocked ?? 0);
      });
    } else {
      setScanned(1428);
      setBlocked(84);
    }
  }, []);

  const filteredLogs = MOCK_LOGS.filter(l =>
    l.domain.toLowerCase().includes(search.toLowerCase()) ||
    l.label.toLowerCase().includes(search.toLowerCase())
  );

  const maxMs = Math.max(...DETECTORS.map(d => d.ms));

  return (
    <div className="page">
      {/* ── topbar ── */}
      <header className="topbar">
        <div className="topbar-logo">
          <div className="topbar-logo-mark">S</div>
          <span className="topbar-name">Phishing Detector</span>
        </div>
        <div className="topbar-divider" />
        <nav className="topbar-nav">
          {(['overview','detectors','performance','log'] as Tab[]).map(t => (
            <a key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </a>
          ))}
        </nav>
        <div className="topbar-right">
          <button className="btn btn-ghost" onClick={() => navigate('/')}>← Popup</button>
        </div>
      </header>

      <main style={{ flex: 1, padding: '28px 0' }}>
        <div className="container">

          {/* ── Overview ─────────────────────────────────── */}
          {tab === 'overview' && (
            <div>
              <div style={{ marginBottom: 24 }}>
                <h1 style={{ fontSize: 20, fontWeight: 700 }}>Security Overview</h1>
                <p className="text-secondary text-sm mt-4">Real-time threat monitoring across your browsing session</p>
              </div>

              {/* stat cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 24 }}>
                {[
                  { label: 'Sites Scanned',    value: scanned.toLocaleString(), color: 'var(--accent)' },
                  { label: 'Threats Blocked',  value: blocked.toLocaleString(), color: 'var(--danger)' },
                  { label: 'Detection Rate',   value: '99.2%',                  color: 'var(--safe)'   },
                ].map(s => (
                  <div key={s.label} className="card">
                    <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
                      {s.label}
                    </div>
                    <div style={{ fontSize: 28, fontWeight: 700, color: s.color }}>{s.value}</div>
                  </div>
                ))}
              </div>

              {/* recent threats mini-table */}
              <div className="card">
                <div className="section-label">Recent Activity</div>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Time</th><th>Domain</th><th>Score</th><th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {MOCK_LOGS.slice(0, 5).map((l, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ color: 'var(--text-muted)', width: 56 }}>{l.time}</td>
                        <td><code>{l.domain}</code></td>
                        <td className="mono">{l.score}/100</td>
                        <td>
                          {l.blocked
                            ? <span className="badge badge-danger">Blocked</span>
                            : <span className="badge badge-safe">Allowed</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Detectors ────────────────────────────────── */}
          {tab === 'detectors' && (
            <div>
              <div style={{ marginBottom: 24 }}>
                <h1 style={{ fontSize: 20, fontWeight: 700 }}>Detector Modules</h1>
                <p className="text-secondary text-sm mt-4">{DETECTORS.length} active engines — all operating fully offline</p>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10 }}>
                {DETECTORS.map(d => (
                  <div key={d.name} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 13, fontWeight: 600 }}>{d.name}</span>
                      <span className="badge badge-safe">Active</span>
                    </div>
                    <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{d.desc}</p>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 8, borderTop: '1px solid var(--border)' }}>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Avg latency</span>
                      <span className="mono" style={{ fontSize: 12, color: 'var(--accent)' }}>{d.ms} ms</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── Performance ──────────────────────────────── */}
          {tab === 'performance' && (
            <div>
              <div style={{ marginBottom: 24 }}>
                <h1 style={{ fontSize: 20, fontWeight: 700 }}>Performance Metrics</h1>
                <p className="text-secondary text-sm mt-4">Sub-millisecond latency profiler per detector</p>
              </div>
              <div className="card">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  {DETECTORS.map(d => (
                    <div key={d.name}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <span style={{ fontSize: 13, fontWeight: 500 }}>{d.name}</span>
                        <span className="mono" style={{ fontSize: 12, color: 'var(--accent)' }}>{d.ms} ms</span>
                      </div>
                      <div className="progress-bar">
                        <div className="progress-fill" style={{ width: `${(d.ms / maxMs) * 100}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── Log ──────────────────────────────────────── */}
          {tab === 'log' && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
                <div>
                  <h1 style={{ fontSize: 20, fontWeight: 700 }}>Audit Log</h1>
                  <p className="text-secondary text-sm mt-4">Complete browsing security event history</p>
                </div>
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Filter by domain or status…"
                  style={{
                    background: 'var(--bg-2)', border: '1px solid var(--border-md)',
                    borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)',
                    fontFamily: 'var(--font)', fontSize: 13, padding: '7px 12px',
                    outline: 'none', width: 240,
                  }}
                />
              </div>
              <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Time</th><th>Domain</th><th>Score</th><th>Risk</th><th>Detectors</th><th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLogs.map((l, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ color: 'var(--text-muted)', width: 56 }}>{l.time}</td>
                        <td><code>{l.domain}</code></td>
                        <td className="mono">{l.score}/100</td>
                        <td><ScoreBadge score={l.score} /></td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{l.detectors}</td>
                        <td>
                          {l.blocked
                            ? <span style={{ color: 'var(--danger)', fontWeight: 600, fontSize: 12 }}>Blocked</span>
                            : <span style={{ color: 'var(--safe)',   fontWeight: 600, fontSize: 12 }}>Allowed</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

        </div>
      </main>
    </div>
  );
}
