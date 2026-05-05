import { FormEvent, useEffect, useMemo, useState } from 'react';

type TabKey = 'overview' | 'access' | 'ops' | 'attack';

type ZonePolicy = {
  zone: string;
  key: string;
  description: string;
  requiredRole: string[];
  rule: string;
};

type Session = {
  id: string;
  userId: string;
  userName: string;
  role: string;
  location: string;
  ipAddress: string;
  deviceId: string;
  deviceTrusted: boolean;
  riskScore: number;
  riskLevel: string;
  mfaRequired: boolean;
  mfaCompleted: boolean;
  requestedZone: string;
  zoneDecision: string;
  policyReasons: string[];
  createdAt: string;
};

type EventItem = {
  id: string;
  time: string;
  kind: string;
  severity: string;
  user: string;
  zone: string;
  result: string;
  detail: string;
};

type AttackResult = {
  id: string;
  type: string;
  prevented: boolean;
  severity: string;
  detail: string;
  actor: string;
  time: string;
};

type ChartSeries = {
  label: string;
  success?: number;
  failed?: number;
  value?: number;
};

type DashboardPayload = {
  users: Array<{
    id: string;
    name: string;
    email: string;
    role: string;
    department: string;
    knownDevices: string[];
    typicalLocations: string[];
    homeIpPrefix: string;
  }>;
  zonePolicies: ZonePolicy[];
  metrics: {
    successfulLogins: number;
    blockedAttempts: number;
    stepUpChallenges: number;
    trustedDevices: number;
  };
  activeSessions: Session[];
  recentEvents: EventItem[];
  attackResults: AttackResult[];
  charts: {
    loginActivity: ChartSeries[];
    deviceTrust: ChartSeries[];
    riskDistribution: ChartSeries[];
  };
  demoCredentials: Array<{
    email: string;
    password: string;
    role: string;
  }>;
};

type LoginResponse = {
  status: 'allowed' | 'mfa_required' | 'denied';
  session: Session;
  policyDecision: {
    allowed: boolean;
    reasons: string[];
  };
  risk: {
    score: number;
    level: string;
    deviceTrusted: boolean;
    summary: string;
  };
  mfaCode: string | null;
  dashboard: DashboardPayload;
};

const tabs: Array<{ key: TabKey; label: string }> = [
  { key: 'overview', label: 'Overview' },
  { key: 'access', label: 'Access Portal' },
  { key: 'ops', label: 'Security Ops' },
  { key: 'attack', label: 'Attack Lab' },
];

const attackOptions = [
  { key: 'brute_force', label: 'Brute force login' },
  { key: 'session_hijack', label: 'Session hijack' },
  { key: 'admin_bypass', label: 'Unauthorized admin access' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [dashboard, setDashboard] = useState<DashboardPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [loginLoading, setLoginLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState('');
  const [loginMessage, setLoginMessage] = useState('Use the demo identities to test context-aware access.');
  const [mfaCode, setMfaCode] = useState('');
  const [attackResult, setAttackResult] = useState<AttackResult | null>(null);
  const [attackMode, setAttackMode] = useState(true);
  const [selectedAttack, setSelectedAttack] = useState('session_hijack');
  const [currentSession, setCurrentSession] = useState<Session | null>(null);
  const [loginForm, setLoginForm] = useState({
    email: 'admin@zerotrust.demo',
    password: 'admin123',
    deviceId: 'device-admin-thinkpad',
    location: 'Bengaluru, IN',
    ipAddress: '10.20.44.18',
    loginHour: '11',
    requestedZone: 'admin',
    zeroTrustEnabled: true,
  });

  useEffect(() => {
    void refreshDashboard();
  }, []);

  const topRiskEvents = useMemo(
    () => dashboard?.recentEvents.filter((item) => item.severity !== 'low').slice(0, 3) ?? [],
    [dashboard],
  );

  async function refreshDashboard() {
    setLoading(true);
    try {
      const response = await fetch('/api/zero-trust/bootstrap');
      const data = (await response.json()) as DashboardPayload;
      setDashboard(data);
    } finally {
      setLoading(false);
    }
  }

  async function handleLoginSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoginLoading(true);

    try {
      const response = await fetch('/api/zero-trust/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...loginForm,
          loginHour: Number(loginForm.loginHour),
        }),
      });
      const data = (await response.json()) as LoginResponse | { message?: string; dashboard?: DashboardPayload };
      if (!response.ok) {
        setLoginMessage((data as { message?: string }).message ?? 'Access denied.');
        if ((data as { dashboard?: DashboardPayload }).dashboard) {
          setDashboard((data as { dashboard: DashboardPayload }).dashboard);
        }
        return;
      }

      const success = data as LoginResponse;
      setCurrentSession(success.session);
      setDashboard(success.dashboard);
      setMfaCode(success.mfaCode ?? '');
      setLoginMessage(
        success.status === 'mfa_required'
          ? `Risk score ${success.risk.score} triggered step-up authentication. Mock OTP: ${success.mfaCode}`
          : success.policyDecision.reasons.join(' '),
      );
    } finally {
      setLoginLoading(false);
    }
  }

  async function handleMfaVerify() {
    if (!currentSession) return;

    setActionLoading('mfa');
    try {
      const response = await fetch('/api/zero-trust/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: currentSession.id, code: mfaCode }),
      });
      const data = await response.json();
      if (!response.ok) {
        setLoginMessage(data.message ?? 'OTP verification failed.');
        return;
      }

      setCurrentSession(data.session as Session);
      setDashboard(data.dashboard as DashboardPayload);
      setLoginMessage((data.policyDecision?.reasons as string[]).join(' '));
    } finally {
      setActionLoading('');
    }
  }

  async function handleRecheck(scenario: 'stable' | 'ip_shift' | 'behavior_anomaly') {
    if (!currentSession) return;

    setActionLoading(scenario);
    try {
      const response = await fetch('/api/zero-trust/session/recheck', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: currentSession.id, scenario }),
      });
      const data = await response.json();
      setCurrentSession(data.session as Session);
      setDashboard(data.dashboard as DashboardPayload);
      setLoginMessage((data.outcome?.message as string) ?? 'Session re-evaluated.');
    } finally {
      setActionLoading('');
    }
  }

  async function handleAttackRun() {
    setActionLoading('attack');
    try {
      const response = await fetch('/api/zero-trust/attacks/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attackType: selectedAttack,
          zeroTrustEnabled: attackMode,
        }),
      });
      const data = await response.json();
      setAttackResult(data.result as AttackResult);
      setDashboard(data.dashboard as DashboardPayload);
    } finally {
      setActionLoading('');
    }
  }

  async function handleReset() {
    setActionLoading('reset');
    try {
      const response = await fetch('/api/zero-trust/reset', {
        method: 'POST',
      });
      const data = (await response.json()) as DashboardPayload;
      setDashboard(data);
      setCurrentSession(null);
      setAttackResult(null);
      setLoginMessage('Simulation reset. Ready for a fresh walkthrough.');
      setMfaCode('');
    } finally {
      setActionLoading('');
    }
  }

  function applyDemoIdentity(email: string, password: string, role: string) {
    const presets: Record<string, Partial<typeof loginForm>> = {
      student: {
        requestedZone: 'student',
        deviceId: 'device-campus-laptop',
        location: 'Bengaluru, IN',
        ipAddress: '10.20.44.18',
        loginHour: '10',
      },
      teacher: {
        requestedZone: 'teacher',
        deviceId: 'device-faculty-mac',
        location: 'Bengaluru, IN',
        ipAddress: '10.20.44.18',
        loginHour: '14',
      },
      admin: {
        requestedZone: 'admin',
        deviceId: 'device-admin-thinkpad',
        location: 'Bengaluru, IN',
        ipAddress: '10.20.44.18',
        loginHour: '11',
      },
    };

    setLoginForm((current) => ({
      ...current,
      email,
      password,
      ...presets[role],
    }));
  }

  if (loading || !dashboard) {
    return (
      <div className="shell loading-shell">
        <div className="loading-card">
          <p className="eyebrow">Zero Trust Access Demo</p>
          <h1>Preparing the policy engine...</h1>
        </div>
      </div>
    );
  }

  return (
    <div className="shell">
      <div className="aurora aurora-one" />
      <div className="aurora aurora-two" />

      <header className="masthead">
        <div className="brand-block">
          <p className="eyebrow">Professional Zero Trust Security Platform</p>
          <h1>Verify every request. Segment every zone. Visualize every decision.</h1>
          <p className="hero-copy">
            A polished React + Express demonstration of adaptive MFA, device trust, micro-segmentation, continuous
            authentication, and attack-response intelligence.
          </p>
        </div>

        <div className="hero-rail">
          <div className="metric-card">
            <span>Blocked threats</span>
            <strong>{dashboard.metrics.blockedAttempts}</strong>
            <p>Failed admin bypass, session theft, and invalid credentials caught by policy.</p>
          </div>
          <div className="metric-strip">
            <article>
              <strong>{dashboard.metrics.successfulLogins}</strong>
              <span>successful logins</span>
            </article>
            <article>
              <strong>{dashboard.metrics.stepUpChallenges}</strong>
              <span>step-up MFA prompts</span>
            </article>
            <article>
              <strong>{dashboard.metrics.trustedDevices}</strong>
              <span>trusted devices</span>
            </article>
          </div>
        </div>
      </header>

      <nav className="tab-row">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            className={tab.key === activeTab ? 'tab-chip active' : 'tab-chip'}
            onClick={() => setActiveTab(tab.key)}
            type="button"
          >
            {tab.label}
          </button>
        ))}
        <button className="tab-chip ghost" disabled={actionLoading === 'reset'} onClick={() => void handleReset()} type="button">
          {actionLoading === 'reset' ? 'Resetting...' : 'Reset Demo'}
        </button>
      </nav>

      <main className="workspace">
        {activeTab === 'overview' && (
          <section className="page-grid">
            <div className="panel story-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Architecture</p>
                  <h2>Three layers that make the project evaluator-ready</h2>
                </div>
              </div>

              <div className="pillar-grid">
                <article className="pillar-card">
                  <span className="pill-icon">01</span>
                  <h3>Core Security System</h3>
                  <p>Risk-based MFA, RBAC + ABAC, device trust, session telemetry, and segmented zones.</p>
                </article>
                <article className="pillar-card">
                  <span className="pill-icon">02</span>
                  <h3>Attack Simulation</h3>
                  <p>Run the same brute force, session hijack, and admin-bypass scenarios with and without Zero Trust.</p>
                </article>
                <article className="pillar-card">
                  <span className="pill-icon">03</span>
                  <h3>Security Dashboard</h3>
                  <p>A mini SOC surface showing risk, trusted devices, threat history, and continuous-auth decisions.</p>
                </article>
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Micro-Segmentation</p>
                  <h2>Zones with strict, visible policy rules</h2>
                </div>
              </div>

              <div className="zone-list">
                {dashboard.zonePolicies.map((policy) => (
                  <article className="zone-card" key={policy.key}>
                    <div className="zone-head">
                      <h3>{policy.zone}</h3>
                      <span>{policy.requiredRole.join(' / ')}</span>
                    </div>
                    <p>{policy.description}</p>
                    <small>{policy.rule}</small>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Risk Lens</p>
                  <h2>Login activity</h2>
                </div>
              </div>
              <div className="bar-chart">
                {dashboard.charts.loginActivity.map((item) => (
                  <div className="bar-group" key={item.label}>
                    <div className="bar-stack">
                      <div className="bar success" style={{ height: `${(item.success ?? 0) * 6}px` }} />
                      <div className="bar danger" style={{ height: `${(item.failed ?? 0) * 6}px` }} />
                    </div>
                    <span>{item.label}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">High Priority</p>
                  <h2>Recent alerts</h2>
                </div>
              </div>
              <div className="alert-stack">
                {topRiskEvents.map((item) => (
                  <article className={`alert-card ${item.severity}`} key={item.id}>
                    <div className="alert-top">
                      <strong>{item.kind}</strong>
                      <span>{item.severity}</span>
                    </div>
                    <p>{item.detail}</p>
                  </article>
                ))}
              </div>
            </div>
          </section>
        )}

        {activeTab === 'access' && (
          <section className="page-grid access-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Adaptive Access</p>
                  <h2>Context-aware login portal</h2>
                </div>
              </div>

              <div className="credential-row">
                {dashboard.demoCredentials.map((cred) => (
                  <button
                    className="mini-credential"
                    key={cred.email}
                    onClick={() => applyDemoIdentity(cred.email, cred.password, cred.role)}
                    type="button"
                  >
                    {cred.role}
                  </button>
                ))}
              </div>

              <form className="form-grid" onSubmit={handleLoginSubmit}>
                <label className="field">
                  <span>Email</span>
                  <input
                    className="input"
                    value={loginForm.email}
                    onChange={(event) => setLoginForm({ ...loginForm, email: event.target.value })}
                  />
                </label>
                <label className="field">
                  <span>Password</span>
                  <input
                    className="input"
                    value={loginForm.password}
                    onChange={(event) => setLoginForm({ ...loginForm, password: event.target.value })}
                  />
                </label>
                <label className="field">
                  <span>Device fingerprint</span>
                  <input
                    className="input"
                    value={loginForm.deviceId}
                    onChange={(event) => setLoginForm({ ...loginForm, deviceId: event.target.value })}
                  />
                </label>
                <label className="field">
                  <span>Location</span>
                  <input
                    className="input"
                    value={loginForm.location}
                    onChange={(event) => setLoginForm({ ...loginForm, location: event.target.value })}
                  />
                </label>
                <label className="field">
                  <span>IP address</span>
                  <input
                    className="input"
                    value={loginForm.ipAddress}
                    onChange={(event) => setLoginForm({ ...loginForm, ipAddress: event.target.value })}
                  />
                </label>
                <label className="field">
                  <span>Login hour</span>
                  <input
                    className="input"
                    type="number"
                    min="0"
                    max="23"
                    value={loginForm.loginHour}
                    onChange={(event) => setLoginForm({ ...loginForm, loginHour: event.target.value })}
                  />
                </label>
                <label className="field">
                  <span>Requested zone</span>
                  <select
                    className="input"
                    value={loginForm.requestedZone}
                    onChange={(event) => setLoginForm({ ...loginForm, requestedZone: event.target.value })}
                  >
                    {dashboard.zonePolicies.map((policy) => (
                      <option key={policy.key} value={policy.key}>
                        {policy.zone}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="toggle">
                  <input
                    checked={loginForm.zeroTrustEnabled}
                    onChange={(event) => setLoginForm({ ...loginForm, zeroTrustEnabled: event.target.checked })}
                    type="checkbox"
                  />
                  <span>Zero Trust policy mode enabled</span>
                </label>
                <button className="primary-button" disabled={loginLoading} type="submit">
                  {loginLoading ? 'Evaluating access...' : 'Request access'}
                </button>
              </form>

              <div className="status-banner">
                <strong>Decision stream</strong>
                <p>{loginMessage}</p>
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Live Session</p>
                  <h2>Risk score and continuous authentication</h2>
                </div>
              </div>

              {currentSession ? (
                <div className="session-stack">
                  <div className="session-card">
                    <div className="session-top">
                      <div>
                        <strong>{currentSession.userName}</strong>
                        <p>
                          {currentSession.role} requesting {currentSession.requestedZone}
                        </p>
                      </div>
                      <span className={`risk-pill ${currentSession.riskLevel}`}>{currentSession.riskScore}</span>
                    </div>
                    <div className="session-grid">
                      <span>Trusted device: {currentSession.deviceTrusted ? 'Yes' : 'No'}</span>
                      <span>MFA: {currentSession.mfaCompleted ? 'Verified' : currentSession.mfaRequired ? 'Required' : 'Not needed'}</span>
                      <span>Location: {currentSession.location}</span>
                      <span>Decision: {currentSession.zoneDecision}</span>
                    </div>
                    <ul>
                      {currentSession.policyReasons.map((reason) => (
                        <li key={reason}>{reason}</li>
                      ))}
                    </ul>
                  </div>

                  {currentSession.mfaRequired && !currentSession.mfaCompleted && (
                    <div className="inline-actions">
                      <input
                        className="input"
                        placeholder="Enter MFA code"
                        value={mfaCode}
                        onChange={(event) => setMfaCode(event.target.value)}
                      />
                      <button className="primary-button" disabled={actionLoading === 'mfa'} onClick={() => void handleMfaVerify()} type="button">
                        {actionLoading === 'mfa' ? 'Verifying...' : 'Verify OTP'}
                      </button>
                    </div>
                  )}

                  <div className="inline-actions">
                    <button
                      className="ghost-button"
                      disabled={actionLoading === 'stable'}
                      onClick={() => void handleRecheck('stable')}
                      type="button"
                    >
                      Healthy recheck
                    </button>
                    <button
                      className="ghost-button"
                      disabled={actionLoading === 'ip_shift'}
                      onClick={() => void handleRecheck('ip_shift')}
                      type="button"
                    >
                      Simulate IP shift
                    </button>
                    <button
                      className="ghost-button"
                      disabled={actionLoading === 'behavior_anomaly'}
                      onClick={() => void handleRecheck('behavior_anomaly')}
                      type="button"
                    >
                      Behavior anomaly
                    </button>
                  </div>
                </div>
              ) : (
                <div className="empty-state">
                  <h3>No active session yet</h3>
                  <p>Submit a login request to watch adaptive MFA and policy enforcement react to context.</p>
                </div>
              )}
            </div>
          </section>
        )}

        {activeTab === 'ops' && (
          <section className="page-grid ops-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">SOC Dashboard</p>
                  <h2>Trusted device posture</h2>
                </div>
              </div>
              <div className="donut-legend">
                {dashboard.charts.deviceTrust.map((item) => (
                  <article className="legend-card" key={item.label}>
                    <strong>{item.value}%</strong>
                    <span>{item.label}</span>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Risk Distribution</p>
                  <h2>Live population posture</h2>
                </div>
              </div>
              <div className="distribution-list">
                {dashboard.charts.riskDistribution.map((item) => (
                  <div className="distribution-row" key={item.label}>
                    <span>{item.label}</span>
                    <div className="distribution-track">
                      <div className="distribution-fill" style={{ width: `${item.value}%` }} />
                    </div>
                    <strong>{item.value}%</strong>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Recent Events</p>
                  <h2>Security log stream</h2>
                </div>
              </div>
              <div className="log-table">
                {dashboard.recentEvents.map((item) => (
                  <article className="log-row" key={item.id}>
                    <div>
                      <strong>{item.kind}</strong>
                      <p>{item.detail}</p>
                    </div>
                    <span>{item.user}</span>
                    <span>{item.zone}</span>
                    <span className={`status-pill ${item.result}`}>{item.result}</span>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Active Sessions</p>
                  <h2>Continuous-auth watchlist</h2>
                </div>
              </div>
              <div className="session-list">
                {dashboard.activeSessions.length > 0 ? (
                  dashboard.activeSessions.map((item) => (
                    <article className="session-row" key={item.id}>
                      <div>
                        <strong>{item.userName}</strong>
                        <p>
                          {item.role} on {item.deviceId}
                        </p>
                      </div>
                      <span>{item.location}</span>
                      <span className={`risk-pill ${item.riskLevel}`}>{item.riskScore}</span>
                      <span className={`status-pill ${item.zoneDecision}`}>{item.zoneDecision}</span>
                    </article>
                  ))
                ) : (
                  <div className="empty-inline">No new sessions yet. Use the Access Portal to generate telemetry.</div>
                )}
              </div>
            </div>
          </section>
        )}

        {activeTab === 'attack' && (
          <section className="page-grid attack-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Attack Lab</p>
                  <h2>Run the same scenario with and without Zero Trust</h2>
                </div>
              </div>

              <div className="attack-controls">
                <select
                  className="input"
                  value={selectedAttack}
                  onChange={(event) => setSelectedAttack(event.target.value)}
                >
                  {attackOptions.map((item) => (
                    <option key={item.key} value={item.key}>
                      {item.label}
                    </option>
                  ))}
                </select>
                <label className="toggle">
                  <input checked={attackMode} onChange={(event) => setAttackMode(event.target.checked)} type="checkbox" />
                  <span>{attackMode ? 'Zero Trust ON' : 'Zero Trust OFF'}</span>
                </label>
                <button className="primary-button" disabled={actionLoading === 'attack'} onClick={() => void handleAttackRun()} type="button">
                  {actionLoading === 'attack' ? 'Simulating...' : 'Run simulation'}
                </button>
              </div>

              {attackResult ? (
                <div className={`attack-result ${attackResult.prevented ? 'safe' : 'breach'}`}>
                  <div className="attack-top">
                    <strong>{attackResult.type}</strong>
                    <span>{attackResult.prevented ? 'Blocked' : 'Breach path'}</span>
                  </div>
                  <p>{attackResult.detail}</p>
                </div>
              ) : (
                <div className="empty-state">
                  <h3>No simulation run yet</h3>
                  <p>Start with session hijacking to show why continuous authentication matters after login.</p>
                </div>
              )}
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Comparison Feed</p>
                  <h2>Latest attack outcomes</h2>
                </div>
              </div>

              <div className="comparison-stack">
                {dashboard.attackResults.map((item) => (
                  <article className="comparison-card" key={item.id}>
                    <div className="comparison-top">
                      <strong>{item.type}</strong>
                      <span className={item.prevented ? 'good' : 'bad'}>{item.prevented ? 'Prevented' : 'Compromised'}</span>
                    </div>
                    <p>{item.detail}</p>
                  </article>
                ))}
              </div>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
