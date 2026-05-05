import { FormEvent, useEffect, useMemo, useState } from 'react';

type TabKey = 'overview' | 'identity' | 'ops' | 'attack';

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
  userAgent: string;
  deviceTrusted: boolean;
  riskScore: number;
  riskLevel: string;
  behaviorScore: number;
  mfaRequired: boolean;
  mfaCompleted: boolean;
  requestedZone: string;
  zoneDecision: string;
  policyReasons: string[];
  createdAt: string;
  refreshTokenId: string | null;
  revoked: boolean;
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

type DeviceRecord = {
  userId: string;
  deviceId: string;
  trusted: boolean;
  lastUsed: string;
  ipAddress: string;
  location: string;
  userAgent: string;
};

type ChartSeries = {
  label: string;
  success?: number;
  failed?: number;
  value?: number;
};

type Tokens = {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresIn: number;
  refreshTokenExpiresIn: number;
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
  deviceRecords: DeviceRecord[];
  securityFeatures: string[];
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
  risk?: {
    score: number;
    level: string;
    deviceTrusted: boolean;
    summary: string;
  };
  policyDecision?: {
    allowed: boolean;
    reasons: string[];
  };
  mfaCode?: string | null;
  message?: string;
  tokens?: Tokens;
  dashboard: DashboardPayload;
};

type ProtectedResponse = {
  status: string;
  resource?: {
    zone: string;
    owner: string;
    items: string[];
  };
  reasons?: string[];
  dashboard: DashboardPayload;
};

const tabs: Array<{ key: TabKey; label: string }> = [
  { key: 'overview', label: 'Overview' },
  { key: 'identity', label: 'Identity & Access' },
  { key: 'ops', label: 'Security Ops' },
  { key: 'attack', label: 'Attack Lab' },
];

const attackOptions = [
  { key: 'brute_force', label: 'Brute force login' },
  { key: 'session_hijack', label: 'Token reuse / session hijack' },
  { key: 'admin_bypass', label: 'Direct admin URL access' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [dashboard, setDashboard] = useState<DashboardPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [currentSession, setCurrentSession] = useState<Session | null>(null);
  const [tokens, setTokens] = useState<Tokens | null>(null);
  const [decisionStream, setDecisionStream] = useState('Adaptive identity checks are ready.');
  const [mfaCode, setMfaCode] = useState('');
  const [attackMode, setAttackMode] = useState(true);
  const [selectedAttack, setSelectedAttack] = useState('session_hijack');
  const [attackResult, setAttackResult] = useState<AttackResult | null>(null);
  const [protectedResult, setProtectedResult] = useState('');
  const [registerMessage, setRegisterMessage] = useState('');
  const [loginForm, setLoginForm] = useState({
    email: 'admin@zerotrust.demo',
    password: 'admin123',
    deviceId: 'device-admin-thinkpad',
    userAgent: 'Chrome on Windows',
    location: 'Bengaluru, IN',
    ipAddress: '10.20.44.18',
    loginHour: '11',
    behaviorScore: '10',
    requestedZone: 'admin',
    zeroTrustEnabled: true,
  });
  const [registerForm, setRegisterForm] = useState({
    name: 'Ishita Kapoor',
    email: 'ishita@zerotrust.demo',
    password: 'securepass123',
    role: 'student',
    department: 'MCA',
    location: 'Bengaluru, IN',
    ipAddress: '10.20.99.20',
  });

  useEffect(() => {
    void refreshDashboard();
  }, []);

  const highPriorityAlerts = useMemo(
    () => dashboard?.recentEvents.filter((entry) => entry.severity !== 'low').slice(0, 4) ?? [],
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

  async function handleRegister(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy('register');
    try {
      const response = await fetch('/api/zero-trust/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(registerForm),
      });
      const data = await response.json();
      if (!response.ok) {
        setRegisterMessage(data.error ?? 'Registration failed.');
        return;
      }
      setDashboard(data.dashboard as DashboardPayload);
      setRegisterMessage(`Registered ${data.item.name}. You can now sign in with that identity.`);
    } finally {
      setBusy('');
    }
  }

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy('login');
    try {
      const response = await fetch('/api/zero-trust/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...loginForm,
          loginHour: Number(loginForm.loginHour),
          behaviorScore: Number(loginForm.behaviorScore),
        }),
      });
      const data = (await response.json()) as LoginResponse;
      setDashboard(data.dashboard);
      if (!response.ok || data.status === 'denied') {
        setDecisionStream(data.message ?? 'Access denied by policy.');
        setCurrentSession(data.session ?? null);
        setTokens(null);
        return;
      }

      setCurrentSession(data.session);
      setTokens(data.tokens ?? null);
      setMfaCode(data.mfaCode ?? '');
      setDecisionStream(
        data.status === 'mfa_required'
          ? `Risk score ${data.risk?.score} triggered adaptive MFA. Mock OTP: ${data.mfaCode}`
          : data.policyDecision?.reasons.join(' ') ?? 'Access granted.',
      );
    } finally {
      setBusy('');
    }
  }

  async function handleVerifyMfa() {
    if (!currentSession) return;
    setBusy('mfa');
    try {
      const response = await fetch('/api/zero-trust/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: currentSession.id, code: mfaCode }),
      });
      const data = await response.json();
      setDashboard(data.dashboard as DashboardPayload);
      if (!response.ok) {
        setDecisionStream(data.message ?? 'MFA verification failed.');
        return;
      }
      setCurrentSession(data.session as Session);
      setTokens(data.tokens as Tokens);
      setDecisionStream((data.policyDecision?.reasons as string[]).join(' '));
    } finally {
      setBusy('');
    }
  }

  async function callProtectedZone(zone: string) {
    if (!tokens) {
      setProtectedResult('Sign in first to call protected APIs.');
      return;
    }
    setBusy(`protected-${zone}`);
    try {
      const response = await fetch(`/api/zero-trust/protected/${zone}`, {
        headers: { Authorization: `Bearer ${tokens.accessToken}` },
      });
      const data = (await response.json()) as ProtectedResponse;
      if (data.dashboard) setDashboard(data.dashboard);
      if (!response.ok) {
        setProtectedResult((data.reasons ?? ['Protected API denied.']).join(' '));
        return;
      }
      setProtectedResult(`Allowed into ${zone}. Resources: ${(data.resource?.items ?? []).join(', ')}`);
    } finally {
      setBusy('');
    }
  }

  async function refreshAccessToken() {
    if (!tokens) return;
    setBusy('refresh');
    try {
      const response = await fetch('/api/zero-trust/token/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: tokens.refreshToken }),
      });
      const data = await response.json();
      if (!response.ok) {
        setDecisionStream(data.error ?? 'Refresh failed.');
        setTokens(null);
        return;
      }
      setTokens(data.tokens as Tokens);
      setDashboard(data.dashboard as DashboardPayload);
      setDecisionStream('Refresh token rotated successfully. Fresh access token issued.');
    } finally {
      setBusy('');
    }
  }

  async function logout() {
    if (!tokens) return;
    setBusy('logout');
    try {
      const response = await fetch('/api/zero-trust/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokens.accessToken}` },
      });
      const data = await response.json();
      if (data.dashboard) setDashboard(data.dashboard as DashboardPayload);
      setTokens(null);
      setCurrentSession(null);
      setProtectedResult('');
      setDecisionStream('Session invalidated and refresh tokens revoked.');
    } finally {
      setBusy('');
    }
  }

  async function recheckSession(scenario: 'stable' | 'ip_shift' | 'behavior_anomaly') {
    if (!tokens || !currentSession) return;
    setBusy(scenario);
    try {
      const response = await fetch('/api/zero-trust/session/recheck', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tokens.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ sessionId: currentSession.id, scenario }),
      });
      const data = await response.json();
      if (data.dashboard) setDashboard(data.dashboard as DashboardPayload);
      if (!response.ok) {
        setDecisionStream(data.error ?? 'Continuous-auth check failed.');
        return;
      }
      setCurrentSession(data.session as Session);
      setDecisionStream((data.outcome?.message as string) ?? 'Continuous-auth check completed.');
      if ((data.session as Session).revoked) {
        setTokens(null);
      }
    } finally {
      setBusy('');
    }
  }

  async function runAttackSimulation() {
    setBusy('attack');
    try {
      const response = await fetch('/api/zero-trust/attacks/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attackType: selectedAttack, zeroTrustEnabled: attackMode }),
      });
      const data = await response.json();
      setAttackResult(data.result as AttackResult);
      setDashboard(data.dashboard as DashboardPayload);
    } finally {
      setBusy('');
    }
  }

  async function resetDemo() {
    setBusy('reset');
    try {
      const response = await fetch('/api/zero-trust/reset', { method: 'POST' });
      const data = (await response.json()) as DashboardPayload;
      setDashboard(data);
      setCurrentSession(null);
      setTokens(null);
      setAttackResult(null);
      setProtectedResult('');
      setDecisionStream('Simulation reset. Start a new walkthrough.');
    } finally {
      setBusy('');
    }
  }

  function applyDemoIdentity(email: string, password: string, role: string) {
    const presets: Record<string, Partial<typeof loginForm>> = {
      student: {
        requestedZone: 'student',
        deviceId: 'device-campus-laptop',
        userAgent: 'Chrome on Windows',
        location: 'Bengaluru, IN',
        ipAddress: '10.20.44.18',
        loginHour: '10',
        behaviorScore: '12',
      },
      teacher: {
        requestedZone: 'teacher',
        deviceId: 'device-faculty-mac',
        userAgent: 'Safari on macOS',
        location: 'Bengaluru, IN',
        ipAddress: '10.20.44.18',
        loginHour: '14',
        behaviorScore: '15',
      },
      admin: {
        requestedZone: 'admin',
        deviceId: 'device-admin-thinkpad',
        userAgent: 'Edge on Windows',
        location: 'Bengaluru, IN',
        ipAddress: '10.20.44.18',
        loginHour: '11',
        behaviorScore: '10',
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
          <p className="eyebrow">ZeroTrustX</p>
          <h1>Loading the adaptive security simulator...</h1>
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
          <p className="eyebrow">ZeroTrustX - Adaptive Security Simulator for Modern Web Systems</p>
          <h1>Identity is verified continuously. Access is controlled dynamically.</h1>
          <p className="hero-copy">
            A professional Zero Trust demo with hashed-password authentication, JWT sessions, refresh rotation, device
            trust, policy enforcement, attack simulation, and a SOC-style monitoring layer.
          </p>
        </div>

        <div className="hero-rail">
          <div className="metric-card">
            <span>Live posture</span>
            <strong>{dashboard.metrics.blockedAttempts}</strong>
            <p>Threats blocked through adaptive MFA, protected APIs, segmentation, and runtime checks.</p>
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
        <button className="tab-chip ghost" disabled={busy === 'reset'} onClick={() => void resetDemo()} type="button">
          {busy === 'reset' ? 'Resetting...' : 'Reset Demo'}
        </button>
      </nav>

      <main className="workspace">
        {activeTab === 'overview' && (
          <section className="page-grid">
            <div className="panel story-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">System Layers</p>
                  <h2>The ZeroTrustX architecture is intentionally system-level</h2>
                </div>
              </div>
              <div className="pillar-grid">
                {[
                  ['Identity Layer', 'Email/password, hashed secrets, JWTs, refresh rotation, and session invalidation.'],
                  ['Device & Context Layer', 'Device fingerprint, user agent, IP address, behavior score, and location awareness.'],
                  ['Policy Engine', 'RBAC + ABAC decisions drive dynamic allow, challenge, restrict, or deny outcomes.'],
                  ['Enforcement Layer', 'Protected APIs validate JWT, role, risk, and micro-segment rules before returning data.'],
                  ['Monitoring Layer', 'Logs, device inventory, risk telemetry, and attack outcomes feed the dashboard.'],
                  ['Attack Simulation', 'Run the same scenario with Zero Trust on and off to show the contrast clearly.'],
                ].map(([title, body], index) => (
                  <article className="pillar-card" key={title}>
                    <span className="pill-icon">{String(index + 1).padStart(2, '0')}</span>
                    <h3>{title}</h3>
                    <p>{body}</p>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Hardening</p>
                  <h2>Security controls implemented</h2>
                </div>
              </div>
              <div className="feature-list">
                {dashboard.securityFeatures.map((feature) => (
                  <article className="feature-row" key={feature}>
                    <strong>{feature}</strong>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Micro-Segmentation</p>
                  <h2>Policy-mapped trust zones</h2>
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
                  <p className="eyebrow">Alert Feed</p>
                  <h2>High-priority signals</h2>
                </div>
              </div>
              <div className="alert-stack">
                {highPriorityAlerts.map((entry) => (
                  <article className={`alert-card ${entry.severity}`} key={entry.id}>
                    <div className="alert-top">
                      <strong>{entry.kind}</strong>
                      <span>{entry.severity}</span>
                    </div>
                    <p>{entry.detail}</p>
                  </article>
                ))}
              </div>
            </div>
          </section>
        )}

        {activeTab === 'identity' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Registration</p>
                  <h2>Create a test identity</h2>
                </div>
              </div>
              <form className="form-grid" onSubmit={handleRegister}>
                <input className="input" value={registerForm.name} onChange={(e) => setRegisterForm({ ...registerForm, name: e.target.value })} />
                <input className="input" value={registerForm.email} onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })} />
                <input className="input" value={registerForm.password} onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })} />
                <select className="input" value={registerForm.role} onChange={(e) => setRegisterForm({ ...registerForm, role: e.target.value })}>
                  <option value="student">Student</option>
                  <option value="teacher">Teacher</option>
                  <option value="admin">Admin</option>
                </select>
                <input className="input" value={registerForm.department} onChange={(e) => setRegisterForm({ ...registerForm, department: e.target.value })} />
                <button className="primary-button" disabled={busy === 'register'} type="submit">
                  {busy === 'register' ? 'Registering...' : 'Register identity'}
                </button>
              </form>
              {registerMessage && <div className="status-banner"><p>{registerMessage}</p></div>}
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Authentication</p>
                  <h2>Adaptive sign-in workflow</h2>
                </div>
              </div>
              <div className="credential-row">
                {dashboard.demoCredentials.map((cred) => (
                  <button className="mini-credential" key={cred.email} onClick={() => applyDemoIdentity(cred.email, cred.password, cred.role)} type="button">
                    {cred.role}
                  </button>
                ))}
              </div>
              <form className="form-grid" onSubmit={handleLogin}>
                <input className="input" value={loginForm.email} onChange={(e) => setLoginForm({ ...loginForm, email: e.target.value })} />
                <input className="input" value={loginForm.password} onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })} />
                <input className="input" value={loginForm.deviceId} onChange={(e) => setLoginForm({ ...loginForm, deviceId: e.target.value })} />
                <input className="input" value={loginForm.userAgent} onChange={(e) => setLoginForm({ ...loginForm, userAgent: e.target.value })} />
                <input className="input" value={loginForm.location} onChange={(e) => setLoginForm({ ...loginForm, location: e.target.value })} />
                <input className="input" value={loginForm.ipAddress} onChange={(e) => setLoginForm({ ...loginForm, ipAddress: e.target.value })} />
                <div className="dual-grid">
                  <input className="input" type="number" min="0" max="23" value={loginForm.loginHour} onChange={(e) => setLoginForm({ ...loginForm, loginHour: e.target.value })} />
                  <input className="input" type="number" min="0" max="100" value={loginForm.behaviorScore} onChange={(e) => setLoginForm({ ...loginForm, behaviorScore: e.target.value })} />
                </div>
                <select className="input" value={loginForm.requestedZone} onChange={(e) => setLoginForm({ ...loginForm, requestedZone: e.target.value })}>
                  {dashboard.zonePolicies.map((policy) => (
                    <option key={policy.key} value={policy.key}>
                      {policy.zone}
                    </option>
                  ))}
                </select>
                <label className="toggle">
                  <input checked={loginForm.zeroTrustEnabled} onChange={(e) => setLoginForm({ ...loginForm, zeroTrustEnabled: e.target.checked })} type="checkbox" />
                  <span>Zero Trust decisioning enabled</span>
                </label>
                <button className="primary-button" disabled={busy === 'login'} type="submit">
                  {busy === 'login' ? 'Evaluating...' : 'Request access'}
                </button>
              </form>
              <div className="status-banner">
                <strong>Decision stream</strong>
                <p>{decisionStream}</p>
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Session & API Protection</p>
                  <h2>JWTs, refresh, logout, and protected routes</h2>
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
                      <span>Behavior score: {currentSession.behaviorScore}</span>
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
                      <input className="input" value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} />
                      <button className="primary-button" disabled={busy === 'mfa'} onClick={() => void handleVerifyMfa()} type="button">
                        {busy === 'mfa' ? 'Verifying...' : 'Verify OTP'}
                      </button>
                    </div>
                  )}

                  <div className="token-grid">
                    <article className="token-card">
                      <strong>Access token</strong>
                      <p>{tokens ? `${tokens.accessToken.slice(0, 36)}...` : 'Not issued yet'}</p>
                    </article>
                    <article className="token-card">
                      <strong>Refresh token</strong>
                      <p>{tokens ? `${tokens.refreshToken.slice(0, 36)}...` : 'Not issued yet'}</p>
                    </article>
                  </div>

                  <div className="inline-actions">
                    <button className="ghost-button" disabled={busy === 'refresh'} onClick={() => void refreshAccessToken()} type="button">
                      Refresh JWT
                    </button>
                    <button className="ghost-button" onClick={() => void callProtectedZone('student')} type="button">
                      Call student API
                    </button>
                    <button className="ghost-button" onClick={() => void callProtectedZone('admin')} type="button">
                      Call admin API
                    </button>
                    <button className="ghost-button" disabled={busy === 'logout'} onClick={() => void logout()} type="button">
                      Logout
                    </button>
                  </div>

                  <div className="inline-actions">
                    <button className="ghost-button" onClick={() => void recheckSession('stable')} type="button">
                      Healthy recheck
                    </button>
                    <button className="ghost-button" onClick={() => void recheckSession('ip_shift')} type="button">
                      Simulate IP shift
                    </button>
                    <button className="ghost-button" onClick={() => void recheckSession('behavior_anomaly')} type="button">
                      Behavior anomaly
                    </button>
                  </div>

                  {protectedResult && <div className="status-banner"><p>{protectedResult}</p></div>}
                </div>
              ) : (
                <div className="empty-state">
                  <h3>No active session</h3>
                  <p>Complete a login flow to see signed tokens and protected API enforcement.</p>
                </div>
              )}
            </div>
          </section>
        )}

        {activeTab === 'ops' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Login Analytics</p>
                  <h2>Successful vs failed attempts</h2>
                </div>
              </div>
              <div className="bar-chart">
                {dashboard.charts.loginActivity.map((entry) => (
                  <div className="bar-group" key={entry.label}>
                    <div className="bar-stack">
                      <div className="bar success" style={{ height: `${(entry.success ?? 0) * 6}px` }} />
                      <div className="bar danger" style={{ height: `${(entry.failed ?? 0) * 6}px` }} />
                    </div>
                    <span>{entry.label}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Risk Distribution</p>
                  <h2>Current risk posture</h2>
                </div>
              </div>
              <div className="distribution-list">
                {dashboard.charts.riskDistribution.map((entry) => (
                  <div className="distribution-row" key={entry.label}>
                    <span>{entry.label}</span>
                    <div className="distribution-track">
                      <div className="distribution-fill" style={{ width: `${entry.value}%` }} />
                    </div>
                    <strong>{entry.value}%</strong>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Device Trust</p>
                  <h2>Tracked device inventory</h2>
                </div>
              </div>
              <div className="device-stack">
                {dashboard.deviceRecords.map((device) => (
                  <article className="device-card" key={`${device.userId}-${device.deviceId}`}>
                    <div className="device-top">
                      <strong>{device.deviceId}</strong>
                      <span className={device.trusted ? 'good' : 'bad'}>{device.trusted ? 'Trusted' : 'Unknown'}</span>
                    </div>
                    <p>{device.location}</p>
                    <small>{device.userAgent}</small>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Live Activity Feed</p>
                  <h2>Security log stream</h2>
                </div>
              </div>
              <div className="log-table">
                {dashboard.recentEvents.map((entry) => (
                  <article className="log-row" key={entry.id}>
                    <div>
                      <strong>{entry.kind}</strong>
                      <p>{entry.detail}</p>
                    </div>
                    <span>{entry.user}</span>
                    <span>{entry.zone}</span>
                    <span className={`status-pill ${entry.result}`}>{entry.result}</span>
                  </article>
                ))}
              </div>
            </div>
          </section>
        )}

        {activeTab === 'attack' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Attack Simulation Module</p>
                  <h2>Compare perimeter-only vs Zero Trust behavior</h2>
                </div>
              </div>
              <div className="attack-controls">
                <select className="input" value={selectedAttack} onChange={(e) => setSelectedAttack(e.target.value)}>
                  {attackOptions.map((item) => (
                    <option key={item.key} value={item.key}>
                      {item.label}
                    </option>
                  ))}
                </select>
                <label className="toggle">
                  <input checked={attackMode} onChange={(e) => setAttackMode(e.target.checked)} type="checkbox" />
                  <span>{attackMode ? 'Zero Trust ON' : 'Zero Trust OFF'}</span>
                </label>
                <button className="primary-button" disabled={busy === 'attack'} onClick={() => void runAttackSimulation()} type="button">
                  {busy === 'attack' ? 'Simulating...' : 'Run simulation'}
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
                  <h3>No attack run yet</h3>
                  <p>Use this panel to show how direct admin access or token reuse fails under Zero Trust.</p>
                </div>
              )}
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Outcome Feed</p>
                  <h2>Latest simulation results</h2>
                </div>
              </div>
              <div className="comparison-stack">
                {dashboard.attackResults.map((entry) => (
                  <article className="comparison-card" key={entry.id}>
                    <div className="comparison-top">
                      <strong>{entry.type}</strong>
                      <span className={entry.prevented ? 'good' : 'bad'}>{entry.prevented ? 'Prevented' : 'Compromised'}</span>
                    </div>
                    <p>{entry.detail}</p>
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
