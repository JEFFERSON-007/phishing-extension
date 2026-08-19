import React, { useState, useEffect } from 'react';

/* ── helpers ────────────────────────────────────────────────── */
function classifyScore(score: number) {
  if (score >= 80) return { label: 'Critical', cls: 'danger', dotCls: 'dot-danger', color: '#EF4444' };
  if (score >= 60) return { label: 'High Risk', cls: 'danger', dotCls: 'dot-danger', color: '#F97316' };
  if (score >= 40) return { label: 'Suspicious', cls: 'warn',   dotCls: 'dot-warn',   color: '#F59E0B' };
  return              { label: 'Safe',     cls: 'safe',   dotCls: 'dot-safe',   color: '#22C55E' };
}

const SIGNALS = [
  { id: 'url',  label: 'URL Analysis' },
  { id: 'form', label: 'Form Activity' },
  { id: 'dom',  label: 'DOM Integrity' },
  { id: 'cert', label: 'Certificate' },
];

/* ── ScoreRing ──────────────────────────────────────────────── */
function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 44;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  return (
    <div className="score-ring">
      <svg viewBox="0 0 100 100" width="100" height="100">
        <circle className="score-ring-track" cx="50" cy="50" r={r} />
        <circle
          className="score-ring-fill"
          cx="50" cy="50" r={r}
          stroke={color}
          strokeDasharray={circ}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="score-ring-label">
        <span className="score-ring-number" style={{ color }}>{score}</span>
        <span className="score-ring-sub">risk</span>
      </div>
    </div>
  );
}

/* ── Main Popup Component ──────────────────────────────────── */
export default function Popup() {
  const [score, setScore] = useState(0);
  const [url, setUrl] = useState('Loading…');
  const [signals, setSignals] = useState<Record<string, 'safe' | 'flagged'>>({
    url: 'safe', form: 'safe', dom: 'safe', cert: 'safe',
  });
  const [reasons, setReasons] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  const info = classifyScore(score);

  useEffect(() => {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (!tab) return;
        setUrl(tab.url ?? 'Unknown');
        chrome.runtime.sendMessage(
          { action: 'GET_TAB_SECURITY_STATUS', tabId: tab.id },
          (res) => {
            if (chrome.runtime.lastError || !res?.result) { setLoading(false); return; }
            const r = res.result;
            setScore(r.riskScore ?? 0);
            setReasons(r.reasons ?? []);
            const triggered: string[] = r.detectorsTriggered ?? [];
            setSignals({
              url:  triggered.some(d => ['URLDetector','ReputationEngine','BrandImpersonationDetector'].includes(d)) ? 'flagged' : 'safe',
              form: triggered.includes('FormDetector')     ? 'flagged' : 'safe',
              dom:  triggered.includes('DOMDetector')      ? 'flagged' : 'safe',
              cert: triggered.includes('CertificateAnalyzer') ? 'flagged' : 'safe',
            });
            setLoading(false);
          }
        );
      });
    } else {
      /* dev-mode mock */
      setTimeout(() => {
        setScore(72);
        setUrl('https://paypa1-secure-login.com');
        setSignals({ url: 'flagged', form: 'flagged', dom: 'safe', cert: 'flagged' });
        setReasons([
          'Domain contains typosquatting pattern',
          'Credential form detected on HTTP',
          'Certificate issued less than 24 h ago',
        ]);
        setLoading(false);
      }, 600);
    }
  }, []);

  function handleRescan() {
    setLoading(true);
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) chrome.tabs.sendMessage(tabs[0].id, { action: 'TRIGGER_DOM_SCAN' });
        setTimeout(() => setLoading(false), 800);
      });
    } else {
      setTimeout(() => setLoading(false), 800);
    }
  }

  function handleDashboard() {
    if (typeof chrome !== 'undefined') {
      chrome.tabs.create({ url: chrome.runtime.getURL('src/ui/dashboard/dashboard.html') });
    } else {
      window.open('/dashboard', '_blank');
    }
  }

  return (
    <div style={{ width: 340, minHeight: 420, background: 'var(--bg)', display: 'flex', flexDirection: 'column' }}>
      {/* ── header ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '12px 16px', borderBottom: '1px solid var(--border)',
      }}>
        <div style={{
          width: 24, height: 24, background: 'var(--accent)',
          borderRadius: 6, display: 'flex', alignItems: 'center',
          justifyContent: 'center', fontSize: 11, fontWeight: 700, color: '#fff',
        }}>S</div>
        <span style={{ fontSize: 13, fontWeight: 600 }}>Phishing Detector</span>
        <div style={{ marginLeft: 'auto' }}>
          <span className={`badge badge-${info.cls}`}>
            <span className={`dot dot-${info.cls}`} />
            {info.label}
          </span>
        </div>
      </div>

      {/* ── score + url ── */}
      <div style={{ padding: '20px 16px', display: 'flex', gap: 16, alignItems: 'center' }}>
        <ScoreRing score={score} color={info.color} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
            Active Site
          </div>
          <div className="mono truncate" style={{ fontSize: 12, color: 'var(--text-primary)' }}>{url}</div>
          {loading && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>Scanning…</div>
          )}
        </div>
      </div>

      <div className="sep" />

      {/* ── signals ── */}
      <div style={{ padding: '14px 16px' }}>
        <div className="section-label">Security Signals</div>
        <div className="signals-grid">
          {SIGNALS.map(s => {
            const flagged = signals[s.id] === 'flagged';
            return (
              <div key={s.id} className="card-sm" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className={`dot ${flagged ? 'dot-danger' : 'dot-safe'}`} />
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{s.label}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── findings ── */}
      {reasons.length > 0 && (
        <>
          <div className="sep" />
          <div style={{ padding: '14px 16px', flex: 1 }}>
            <div className="section-label">Threat Indicators</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {reasons.map((r, i) => (
                <div key={i} style={{
                  fontSize: 12, color: 'var(--text-secondary)',
                  background: 'var(--bg-2)', borderRadius: 6,
                  padding: '6px 10px', borderLeft: '2px solid var(--danger)',
                }}>
                  {r}
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      <div className="sep" />

      {/* ── actions ── */}
      <div style={{ padding: '12px 16px', display: 'flex', gap: 8 }}>
        <button className="btn btn-ghost" style={{ flex: 1, fontSize: 12 }} onClick={handleRescan}>
          ↺ Rescan
        </button>
        <button className="btn btn-primary" style={{ flex: 1, fontSize: 12 }} onClick={handleDashboard}>
          Dashboard →
        </button>
      </div>
    </div>
  );
}
