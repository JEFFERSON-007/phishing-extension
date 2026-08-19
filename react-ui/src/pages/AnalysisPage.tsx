import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const CHECKS = [
  { id: 'url',  label: 'URL Pattern Analysis',   desc: 'Unicode normalisation, typosquatting, homographs' },
  { id: 'rep',  label: 'Domain Reputation',       desc: 'Offline blocklist, threat intelligence feeds' },
  { id: 'tls',  label: 'TLS / Certificate',       desc: 'Issuer validity, expiry, HSTS enforcement' },
  { id: 'form', label: 'Form Heuristics',          desc: 'Credential & PII capture patterns detected' },
  { id: 'dom',  label: 'DOM Integrity',            desc: 'Hidden iFrames, obfuscated scripts, overlays' },
  { id: 'beh',  label: 'Behaviour Signals',        desc: 'Clipboard hijack, popup spam, redirect chains' },
];

type StatusMap = Record<string, 'checking' | 'pass' | 'warn' | 'fail'>;

export default function AnalysisPage() {
  const [url, setUrl] = useState('');
  const [started, setStarted] = useState(false);
  const [status, setStatus] = useState<StatusMap>({});
  const [done, setDone] = useState(false);
  const navigate = useNavigate();

  function runAnalysis() {
    if (!url.trim()) return;
    setStarted(true);
    setDone(false);
    const result: StatusMap = {};

    // Simulate progressive checks
    CHECKS.forEach((c, i) => {
      setTimeout(() => {
        setStatus(prev => ({ ...prev, [c.id]: 'checking' }));
      }, i * 350);

      setTimeout(() => {
        const r = Math.random();
        result[c.id] = r < 0.15 ? 'fail' : r < 0.25 ? 'warn' : 'pass';
        setStatus({ ...result });
        if (i === CHECKS.length - 1) setDone(true);
      }, i * 350 + 600);
    });
  }

  const totalScore = Object.values(status).reduce((acc, v) => {
    if (v === 'fail') return acc + 30;
    if (v === 'warn') return acc + 15;
    return acc;
  }, 0);

  return (
    <div className="page">
      {/* topbar */}
      <header className="topbar">
        <div className="topbar-logo">
          <div className="topbar-logo-mark">S</div>
          <span className="topbar-name">Phishing Detector</span>
        </div>
        <div className="topbar-divider" />
        <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>Manual Analysis</span>
        <div className="topbar-right">
          <button className="btn btn-ghost" onClick={() => navigate('/')}>← Back</button>
        </div>
      </header>

      <main style={{ flex: 1, padding: '40px 0' }}>
        <div className="container" style={{ maxWidth: 640 }}>
          <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>Analyse a URL</h1>
          <p className="text-secondary text-sm" style={{ marginBottom: 28 }}>
            Run a full security analysis against any URL using all detection engines.
          </p>

          {/* URL input */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 28 }}>
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runAnalysis()}
              placeholder="https://example.com"
              style={{
                flex: 1, background: 'var(--bg-2)',
                border: '1px solid var(--border-md)',
                borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)', fontSize: 13,
                padding: '9px 14px', outline: 'none',
              }}
            />
            <button className="btn btn-primary" onClick={runAnalysis} style={{ padding: '9px 20px' }}>
              Analyse
            </button>
          </div>

          {/* checks */}
          {started && (
            <div className="card" style={{ marginBottom: 20, padding: 0, overflow: 'hidden' }}>
              {CHECKS.map((c, i) => {
                const s = status[c.id];
                const dotCls = s === 'pass' ? 'dot-safe' : s === 'fail' ? 'dot-danger' : s === 'warn' ? 'dot-warn' : 'dot-muted';
                return (
                  <div key={c.id} style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: '13px 16px',
                    borderBottom: i < CHECKS.length - 1 ? '1px solid var(--border)' : 'none',
                  }}>
                    <span className={`dot ${dotCls}`} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 13, fontWeight: 500 }}>{c.label}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{c.desc}</div>
                    </div>
                    <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', color:
                      s === 'pass'     ? 'var(--safe)'   :
                      s === 'fail'     ? 'var(--danger)' :
                      s === 'warn'     ? 'var(--warn)'   :
                      s === 'checking' ? 'var(--accent)'  : 'var(--text-muted)',
                    }}>
                      {s === 'checking' ? 'Checking…' : s ? s.toUpperCase() : '—'}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* result */}
          {done && (
            <div className="card" style={{
              borderColor: totalScore >= 60 ? 'var(--danger)' : totalScore >= 30 ? 'var(--warn)' : 'var(--safe)',
              textAlign: 'center', padding: '24px 20px',
            }}>
              <div style={{ fontSize: 36, fontWeight: 700, color:
                totalScore >= 60 ? 'var(--danger)' : totalScore >= 30 ? 'var(--warn)' : 'var(--safe)',
              }}>
                {totalScore}/100
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 8 }}>
                {totalScore >= 60 ? 'High phishing risk — exercise caution' :
                 totalScore >= 30 ? 'Some suspicious signals detected'      :
                 'No significant threats detected'}
              </div>
              <div style={{ marginTop: 16, display: 'flex', justifyContent: 'center', gap: 8 }}>
                <button className="btn btn-ghost" onClick={() => { setStarted(false); setDone(false); setUrl(''); }}>
                  Reset
                </button>
                <button className="btn btn-primary" onClick={() => navigate('/dashboard')}>
                  View Dashboard
                </button>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
