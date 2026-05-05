import { useEffect, useMemo, useState } from 'react';

type PageKey = 'home' | 'architecture' | 'simulator' | 'dashboard' | 'attacks' | 'presentation';
type Role = 'student' | 'teacher' | 'admin';

type ZonePolicy = {
  zone: string;
  key: 'public' | 'student' | 'teacher' | 'admin';
  description: string;
  requiredRole: Array<Role | 'guest'>;
  rule: string;
};

type DemoUser = {
  id: string;
  name: string;
  email: string;
  password: string;
  role: Role;
  department: string;
  knownDevices: string[];
  typicalLocations: string[];
  homeIpPrefix: string;
};

type EventItem = {
  id: string;
  time: string;
  kind: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  user: string;
  zone: string;
  result: string;
  detail: string;
};

type AttackResult = {
  id: string;
  type: string;
  prevented: boolean;
  severity: 'high' | 'critical';
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

type Session = {
  id: string;
  userId: string;
  userName: string;
  role: Role;
  location: string;
  ipAddress: string;
  deviceId: string;
  userAgent: string;
  requestedZone: ZonePolicy['key'];
  deviceTrusted: boolean;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high';
  behaviorScore: number;
  mfaRequired: boolean;
  mfaCompleted: boolean;
  zoneDecision: string;
  policyReasons: string[];
  revoked: boolean;
};

type DashboardState = {
  users: DemoUser[];
  zonePolicies: ZonePolicy[];
  activeSessions: Session[];
  recentEvents: EventItem[];
  attackResults: AttackResult[];
  deviceRecords: DeviceRecord[];
  metrics: {
    successfulLogins: number;
    blockedAttempts: number;
    stepUpChallenges: number;
    trustedDevices: number;
  };
  charts: {
    loginActivity: Array<{ label: string; success: number; failed: number }>;
    riskDistribution: Array<{ label: string; value: number }>;
  };
};

const pages: Array<{ key: PageKey; label: string }> = [
  { key: 'home', label: 'Home' },
  { key: 'architecture', label: 'Architecture' },
  { key: 'simulator', label: 'Live Simulator' },
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'attacks', label: 'Attack Lab' },
  { key: 'presentation', label: 'Presentation Guide' },
];

const zonePolicies: ZonePolicy[] = [
  {
    zone: 'Public Zone',
    key: 'public',
    description: 'Landing pages, policy explainers, and awareness content.',
    requiredRole: ['guest', 'student', 'teacher', 'admin'],
    rule: 'Low-friction access with visibility logging.',
  },
  {
    zone: 'Student Workspace',
    key: 'student',
    description: 'Assignments, course materials, and student records.',
    requiredRole: ['student', 'teacher', 'admin'],
    rule: 'Unknown devices trigger step-up authentication.',
  },
  {
    zone: 'Faculty Tools',
    key: 'teacher',
    description: 'Grading, moderation, and academic workflow tools.',
    requiredRole: ['teacher', 'admin'],
    rule: 'Role, trusted context, and medium-risk thresholds enforced.',
  },
  {
    zone: 'Admin Control Plane',
    key: 'admin',
    description: 'Identity settings, logs, and sensitive operations.',
    requiredRole: ['admin'],
    rule: 'Approved geography, trusted network, and fresh MFA are mandatory.',
  },
];

const seedUsers: DemoUser[] = [
  {
    id: 'user-student-01',
    name: 'Aarav Sharma',
    email: 'student@zerotrust.demo',
    password: 'student123',
    role: 'student',
    department: 'BCA',
    knownDevices: ['device-campus-laptop'],
    typicalLocations: ['Bengaluru, IN'],
    homeIpPrefix: '10.20.',
  },
  {
    id: 'user-teacher-01',
    name: 'Prof. Kavya Iyer',
    email: 'teacher@zerotrust.demo',
    password: 'teacher123',
    role: 'teacher',
    department: 'Cyber Security',
    knownDevices: ['device-faculty-mac'],
    typicalLocations: ['Bengaluru, IN'],
    homeIpPrefix: '10.20.',
  },
  {
    id: 'user-admin-01',
    name: 'Rohan Menon',
    email: 'admin@zerotrust.demo',
    password: 'admin123',
    role: 'admin',
    department: 'IT Operations',
    knownDevices: ['device-admin-thinkpad'],
    typicalLocations: ['Bengaluru, IN'],
    homeIpPrefix: '10.20.',
  },
];

const defaultLogin = {
  email: 'admin@zerotrust.demo',
  password: 'admin123',
  deviceId: 'device-admin-thinkpad',
  userAgent: 'Edge on Windows',
  location: 'Bengaluru, IN',
  ipAddress: '10.20.44.18',
  loginHour: '11',
  behaviorScore: '10',
  requestedZone: 'admin' as ZonePolicy['key'],
  zeroTrustEnabled: true,
};

const attackOptions = [
  { key: 'brute_force', label: 'Brute force login' },
  { key: 'session_hijack', label: 'Token reuse / session hijack' },
  { key: 'admin_bypass', label: 'Direct admin URL access' },
];

function now() {
  return new Date().toISOString();
}

function shortTime(value: string) {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function classifyRisk(score: number): Session['riskLevel'] {
  if (score >= 70) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

function simulateAttack(attackType: string, zeroTrustEnabled: boolean): AttackResult {
  const map = {
    brute_force: {
      name: 'Brute force login',
      on: 'Rate limiting and adaptive checks throttle repeated credential abuse.',
      off: 'Without Zero Trust controls, repeated guesses keep hitting the login surface.',
    },
    session_hijack: {
      name: 'Session hijacking',
      on: 'Continuous authentication detects IP drift and invalidates the stolen session.',
      off: 'A stolen token continues to work after login in a perimeter-only model.',
    },
    admin_bypass: {
      name: 'Unauthorized admin access',
      on: 'Micro-segmentation and role checks block direct admin URL access instantly.',
      off: 'Weak segmentation allows lateral movement toward the admin zone.',
    },
  } as const;

  const item = map[attackType as keyof typeof map] ?? map.brute_force;
  return {
    id: `atk-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
    type: item.name,
    prevented: zeroTrustEnabled,
    severity: attackType === 'brute_force' ? 'high' : 'critical',
    detail: zeroTrustEnabled ? item.on : item.off,
    actor: zeroTrustEnabled ? 'Attack simulator' : 'Perimeter-only baseline',
    time: now(),
  };
}

function buildInitialState(): DashboardState {
  const devices: DeviceRecord[] = seedUsers.flatMap((user) =>
    user.knownDevices.map((deviceId) => ({
      userId: user.id,
      deviceId,
      trusted: true,
      lastUsed: now(),
      ipAddress: `${user.homeIpPrefix}44.18`,
      location: 'Bengaluru, IN',
      userAgent: 'Trusted Browser',
    })),
  );

  const attacks = [simulateAttack('brute_force', true), simulateAttack('session_hijack', true), simulateAttack('admin_bypass', false)];

  return {
    users: seedUsers,
    zonePolicies,
    activeSessions: [],
    recentEvents: [
      {
        id: 'evt-1',
        time: now(),
        kind: 'Trusted admin sign-in',
        severity: 'low',
        user: 'Rohan Menon',
        zone: 'admin',
        result: 'allowed',
        detail: 'Known device, campus IP, and approved hours satisfied policy.',
      },
      {
        id: 'evt-2',
        time: now(),
        kind: 'Impossible travel blocked',
        severity: 'high',
        user: 'Aarav Sharma',
        zone: 'student',
        result: 'blocked',
        detail: 'A new geography raised the risk score above the safe threshold.',
      },
      {
        id: 'evt-3',
        time: now(),
        kind: 'Behavior anomaly detected',
        severity: 'medium',
        user: 'Prof. Kavya Iyer',
        zone: 'teacher',
        result: 'limited_access',
        detail: 'Typing and navigation behavior deviated from the normal pattern.',
      },
    ],
    attackResults: attacks,
    deviceRecords: devices,
    metrics: {
      successfulLogins: 24,
      blockedAttempts: 7,
      stepUpChallenges: 5,
      trustedDevices: devices.filter((item) => item.trusted).length,
    },
    charts: {
      loginActivity: [
        { label: 'Mon', success: 12, failed: 4 },
        { label: 'Tue', success: 15, failed: 5 },
        { label: 'Wed', success: 17, failed: 6 },
        { label: 'Thu', success: 18, failed: 3 },
        { label: 'Fri', success: 16, failed: 7 },
        { label: 'Sat', success: 10, failed: 2 },
      ],
      riskDistribution: [
        { label: 'Low', value: 51 },
        { label: 'Medium', value: 31 },
        { label: 'High', value: 18 },
      ],
    },
  };
}

function scoreRisk(user: DemoUser, payload: typeof defaultLogin) {
  let score = 0;
  const reasons: string[] = [];
  const deviceTrusted = user.knownDevices.includes(payload.deviceId);
  const locationTrusted = user.typicalLocations.includes(payload.location);
  const ipTrusted = payload.ipAddress.startsWith(user.homeIpPrefix);
  const behaviorScore = Number(payload.behaviorScore);
  const hour = Number(payload.loginHour);

  if (!deviceTrusted) {
    score += 30;
    reasons.push('New device detected.');
  }
  if (!ipTrusted) {
    score += 20;
    reasons.push('New IP/network detected.');
  }
  if (!locationTrusted) {
    score += 40;
    reasons.push('Different location detected.');
  }
  if (hour >= 22 || hour <= 5) {
    score += 10;
    reasons.push('Odd login time.');
  }
  if (behaviorScore >= 60) {
    score += 15;
    reasons.push('Behavior pattern anomaly.');
  }
  if (payload.requestedZone === 'admin') {
    score += 8;
    reasons.push('Privileged zone requested.');
  }

  return {
    score,
    deviceTrusted,
    reasons: reasons.length > 0 ? reasons : ['Known device, trusted network, and expected context.'],
    level: classifyRisk(score),
  };
}

function evaluateAccess(params: {
  role: Role;
  requestedZone: ZonePolicy['key'];
  location: string;
  loginHour: number;
  riskScore: number;
  deviceTrusted: boolean;
  mfaSatisfied: boolean;
}) {
  const reasons: string[] = [];
  const zone = zonePolicies.find((item) => item.key === params.requestedZone) ?? zonePolicies[0];

  if (!zone.requiredRole.includes(params.role)) {
    reasons.push(`Role ${params.role} cannot access ${zone.zone}.`);
  }
  if (params.riskScore >= 70) {
    reasons.push('Risk score is above the maximum allowed threshold.');
  } else if (params.riskScore >= 30 && !params.mfaSatisfied) {
    reasons.push('Risk score requires MFA.');
  }
  if (params.requestedZone === 'admin') {
    if (!params.location.toLowerCase().includes('bengaluru')) {
      reasons.push('Admin access is limited to the approved geography.');
    }
    if (params.loginHour >= 22 || params.loginHour <= 5) {
      reasons.push('Admin access is blocked outside approved hours.');
    }
    if (!params.mfaSatisfied) {
      reasons.push('Fresh MFA is mandatory for the admin zone.');
    }
  }
  if ((params.requestedZone === 'student' || params.requestedZone === 'teacher') && !params.deviceTrusted && !params.mfaSatisfied) {
    reasons.push('Unknown device must complete step-up verification.');
  }

  return {
    allowed: reasons.length === 0,
    reasons: reasons.length > 0 ? reasons : ['Policy requirements satisfied.'],
  };
}

export default function App() {
  const [page, setPage] = useState<PageKey>('home');
  const [state, setState] = useState<DashboardState>(() => buildInitialState());
  const [loginForm, setLoginForm] = useState(defaultLogin);
  const [currentSession, setCurrentSession] = useState<Session | null>(null);
  const [decisionStream, setDecisionStream] = useState('This presentation mode runs entirely inside the browser, so it stays reliable during demos.');
  const [mfaCode, setMfaCode] = useState('482911');
  const [protectedResult, setProtectedResult] = useState('');
  const [attackMode, setAttackMode] = useState(true);
  const [selectedAttack, setSelectedAttack] = useState('session_hijack');
  const [attackResult, setAttackResult] = useState<AttackResult | null>(null);

  useEffect(() => {
    const syncFromHash = () => {
      const key = window.location.hash.replace('#', '') as PageKey;
      if (pages.some((item) => item.key === key)) {
        setPage(key);
      } else {
        setPage('home');
      }
    };

    syncFromHash();
    window.addEventListener('hashchange', syncFromHash);
    return () => window.removeEventListener('hashchange', syncFromHash);
  }, []);

  const highPriorityAlerts = useMemo(
    () => state.recentEvents.filter((item) => item.severity !== 'low').slice(0, 4),
    [state.recentEvents],
  );

  function navigate(next: PageKey) {
    window.location.hash = next;
  }

  function appendEvent(event: EventItem) {
    setState((current) => ({
      ...current,
      recentEvents: [event, ...current.recentEvents].slice(0, 12),
      metrics: {
        ...current.metrics,
        blockedAttempts:
          current.metrics.blockedAttempts + (event.result === 'blocked' || event.result === 'revoked' ? 1 : 0),
        stepUpChallenges: current.metrics.stepUpChallenges + (event.result === 'challenge' ? 1 : 0),
      },
    }));
  }

  function applyDemoIdentity(email: string, password: string, role: Role) {
    const presets: Record<Role, Partial<typeof defaultLogin>> = {
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

    setLoginForm((current) => ({ ...current, email, password, ...presets[role] }));
    navigate('simulator');
  }

  function handleLogin() {
    const user = state.users.find((item) => item.email === loginForm.email);
    if (!user || user.password !== loginForm.password) {
      const event: EventItem = {
        id: `evt-${Date.now()}`,
        time: now(),
        kind: 'Invalid login attempt',
        severity: 'high',
        user: loginForm.email || 'Unknown user',
        zone: loginForm.requestedZone,
        result: 'blocked',
        detail: 'Credential validation failed before access could be granted.',
      };
      appendEvent(event);
      setDecisionStream('Login blocked: invalid credentials.');
      return;
    }

    const risk = scoreRisk(user, loginForm);
    const needsMfa = loginForm.zeroTrustEnabled && risk.score >= 30;
    const decision = evaluateAccess({
      role: user.role,
      requestedZone: loginForm.requestedZone,
      location: loginForm.location,
      loginHour: Number(loginForm.loginHour),
      riskScore: risk.score,
      deviceTrusted: risk.deviceTrusted,
      mfaSatisfied: !needsMfa,
    });

    const session: Session = {
      id: `session-${Date.now()}`,
      userId: user.id,
      userName: user.name,
      role: user.role,
      location: loginForm.location,
      ipAddress: loginForm.ipAddress,
      deviceId: loginForm.deviceId,
      userAgent: loginForm.userAgent,
      requestedZone: loginForm.requestedZone,
      deviceTrusted: risk.deviceTrusted,
      riskScore: risk.score,
      riskLevel: risk.level,
      behaviorScore: Number(loginForm.behaviorScore),
      mfaRequired: needsMfa,
      mfaCompleted: false,
      zoneDecision: risk.score >= 70 ? 'denied' : needsMfa ? 'challenge' : decision.allowed ? 'allowed' : 'denied',
      policyReasons: risk.score >= 70 ? ['Risk score too high. Access blocked immediately.'] : decision.reasons,
      revoked: false,
    };

    setCurrentSession(session);
    setState((current) => ({
      ...current,
      activeSessions: [session, ...current.activeSessions.filter((item) => item.userId !== session.userId)].slice(0, 6),
      deviceRecords: [
        {
          userId: user.id,
          deviceId: loginForm.deviceId,
          trusted: risk.score < 30,
          lastUsed: now(),
          ipAddress: loginForm.ipAddress,
          location: loginForm.location,
          userAgent: loginForm.userAgent,
        },
        ...current.deviceRecords.filter((item) => !(item.userId === user.id && item.deviceId === loginForm.deviceId)),
      ].slice(0, 10),
      metrics: {
        ...current.metrics,
        successfulLogins: current.metrics.successfulLogins + (session.zoneDecision === 'allowed' ? 1 : 0),
        stepUpChallenges: current.metrics.stepUpChallenges + (needsMfa ? 1 : 0),
      },
    }));

    if (risk.score >= 70) {
      appendEvent({
        id: `evt-${Date.now()}`,
        time: now(),
        kind: 'High-risk login blocked',
        severity: 'critical',
        user: user.name,
        zone: loginForm.requestedZone,
        result: 'blocked',
        detail: risk.reasons.join(' '),
      });
      setDecisionStream(`Blocked. Risk score ${risk.score}. ${risk.reasons.join(' ')}`);
      return;
    }

    if (needsMfa) {
      appendEvent({
        id: `evt-${Date.now()}`,
        time: now(),
        kind: 'Adaptive MFA triggered',
        severity: 'medium',
        user: user.name,
        zone: loginForm.requestedZone,
        result: 'challenge',
        detail: risk.reasons.join(' '),
      });
      setDecisionStream(`MFA required. Risk score ${risk.score}. Demo OTP is 482911.`);
      return;
    }

    appendEvent({
      id: `evt-${Date.now()}`,
      time: now(),
      kind: 'Login allowed',
      severity: 'low',
      user: user.name,
      zone: loginForm.requestedZone,
      result: 'allowed',
      detail: decision.reasons.join(' '),
    });
    setDecisionStream(`Access allowed. Risk score ${risk.score}. ${decision.reasons.join(' ')}`);
  }

  function verifyMfa() {
    if (!currentSession) return;
    if (mfaCode !== '482911') {
      appendEvent({
        id: `evt-${Date.now()}`,
        time: now(),
        kind: 'MFA failed',
        severity: 'high',
        user: currentSession.userName,
        zone: currentSession.requestedZone,
        result: 'blocked',
        detail: 'Incorrect OTP entered during step-up authentication.',
      });
      setDecisionStream('Incorrect OTP. Access stays blocked.');
      return;
    }

    const decision = evaluateAccess({
      role: currentSession.role,
      requestedZone: currentSession.requestedZone,
      location: currentSession.location,
      loginHour: Number(loginForm.loginHour),
      riskScore: currentSession.riskScore,
      deviceTrusted: currentSession.deviceTrusted,
      mfaSatisfied: true,
    });

    const updated = {
      ...currentSession,
      mfaCompleted: true,
      zoneDecision: decision.allowed ? 'allowed' : 'denied',
      policyReasons: decision.reasons,
    };
    setCurrentSession(updated);
    setState((current) => ({
      ...current,
      activeSessions: current.activeSessions.map((item) => (item.id === updated.id ? updated : item)),
      metrics: {
        ...current.metrics,
        successfulLogins: current.metrics.successfulLogins + (decision.allowed ? 1 : 0),
      },
    }));
    appendEvent({
      id: `evt-${Date.now()}`,
      time: now(),
      kind: decision.allowed ? 'MFA verified' : 'Post-MFA policy block',
      severity: decision.allowed ? 'low' : 'high',
      user: updated.userName,
      zone: updated.requestedZone,
      result: decision.allowed ? 'allowed' : 'blocked',
      detail: decision.reasons.join(' '),
    });
    setDecisionStream(decision.allowed ? 'OTP accepted. Access granted.' : `OTP accepted, but policy still blocks access: ${decision.reasons.join(' ')}`);
  }

  function callProtectedZone(zone: ZonePolicy['key']) {
    if (!currentSession) {
      setProtectedResult('Login first to test a protected API route.');
      return;
    }
    const decision = evaluateAccess({
      role: currentSession.role,
      requestedZone: zone,
      location: currentSession.location,
      loginHour: Number(loginForm.loginHour),
      riskScore: currentSession.riskScore,
      deviceTrusted: currentSession.deviceTrusted,
      mfaSatisfied: currentSession.mfaCompleted || !currentSession.mfaRequired,
    });

    if (!decision.allowed) {
      appendEvent({
        id: `evt-${Date.now()}`,
        time: now(),
        kind: 'Protected API blocked',
        severity: 'high',
        user: currentSession.userName,
        zone,
        result: 'blocked',
        detail: decision.reasons.join(' '),
      });
      setProtectedResult(`403 Forbidden: ${decision.reasons.join(' ')}`);
      return;
    }

    appendEvent({
      id: `evt-${Date.now()}`,
      time: now(),
      kind: 'Protected API allowed',
      severity: 'low',
      user: currentSession.userName,
      zone,
      result: 'allowed',
      detail: 'JWT validation, role check, and policy evaluation all passed.',
    });
    setProtectedResult(`200 OK: ${currentSession.userName} accessed the ${zone} resources.`);
  }

  function recheckSession(mode: 'stable' | 'ip_shift' | 'behavior_anomaly') {
    if (!currentSession) return;
    let updated = { ...currentSession };
    let message = 'Session remains healthy.';

    if (mode === 'ip_shift') {
      updated.riskScore = Math.min(98, updated.riskScore + 26);
      updated.riskLevel = classifyRisk(updated.riskScore);
      updated.zoneDecision = updated.riskScore >= 70 ? 'revoked' : 'challenge';
      updated.revoked = updated.riskScore >= 70;
      message =
        updated.riskScore >= 70
          ? 'Continuous authentication revoked the session after the IP changed.'
          : 'Continuous authentication paused access and requires re-verification.';
    } else if (mode === 'behavior_anomaly') {
      updated.riskScore = Math.min(95, updated.riskScore + 18);
      updated.riskLevel = classifyRisk(updated.riskScore);
      updated.zoneDecision = 'limited';
      message = 'Behavioral anomaly increased risk and restricted features.';
    } else {
      updated.riskScore = Math.max(8, updated.riskScore - 4);
      updated.riskLevel = classifyRisk(updated.riskScore);
      updated.zoneDecision = updated.mfaCompleted || !updated.mfaRequired ? 'allowed' : updated.zoneDecision;
    }

    setCurrentSession(updated);
    setState((current) => ({
      ...current,
      activeSessions: current.activeSessions.map((item) => (item.id === updated.id ? updated : item)),
    }));
    appendEvent({
      id: `evt-${Date.now()}`,
      time: now(),
      kind: 'Continuous authentication check',
      severity: mode === 'stable' ? 'low' : 'medium',
      user: updated.userName,
      zone: updated.requestedZone,
      result: updated.zoneDecision,
      detail: message,
    });
    setDecisionStream(message);
  }

  function runAttackSimulation() {
    const result = simulateAttack(selectedAttack, attackMode);
    setAttackResult(result);
    setState((current) => ({
      ...current,
      attackResults: [result, ...current.attackResults].slice(0, 6),
    }));
    appendEvent({
      id: `evt-${Date.now()}`,
      time: now(),
      kind: result.type,
      severity: result.severity,
      user: result.actor,
      zone: 'simulation',
      result: result.prevented ? 'blocked' : 'breach',
      detail: result.detail,
    });
  }

  function resetDemo() {
    setState(buildInitialState());
    setCurrentSession(null);
    setProtectedResult('');
    setAttackResult(null);
    setDecisionStream('Simulation reset. Start a fresh walkthrough.');
    setPage('home');
    window.location.hash = 'home';
  }

  return (
    <div className="shell">
      <div className="aurora aurora-one" />
      <div className="aurora aurora-two" />

      <header className="masthead">
        <div className="brand-block">
          <p className="eyebrow">ZeroTrustX - Adaptive Security Simulator for Modern Web Systems</p>
          <h1>A multi-page Zero Trust showcase built for live presentations.</h1>
          <p className="hero-copy">
            This version is presentation-safe: the demo logic is built into the website itself, so you can open it on
            Vercel and still demonstrate authentication, risk scoring, policy enforcement, and attack response.
          </p>
          <div className="hero-actions">
            <button className="primary-button" onClick={() => navigate('simulator')} type="button">
              Open Live Simulator
            </button>
            <button className="ghost-button" onClick={() => navigate('presentation')} type="button">
              Show Presentation Guide
            </button>
          </div>
        </div>

        <div className="hero-rail">
          <div className="metric-card">
            <span>Demo posture</span>
            <strong>{state.metrics.blockedAttempts}</strong>
            <p>Blocked access attempts, suspicious flows, and attack simulations recorded in the live feed.</p>
          </div>
          <div className="metric-strip">
            <article>
              <strong>{state.metrics.successfulLogins}</strong>
              <span>successful logins</span>
            </article>
            <article>
              <strong>{state.metrics.stepUpChallenges}</strong>
              <span>step-up MFA prompts</span>
            </article>
            <article>
              <strong>{state.metrics.trustedDevices}</strong>
              <span>trusted devices</span>
            </article>
          </div>
        </div>
      </header>

      <nav className="tab-row">
        {pages.map((item) => (
          <button
            key={item.key}
            className={item.key === page ? 'tab-chip active' : 'tab-chip'}
            onClick={() => navigate(item.key)}
            type="button"
          >
            {item.label}
          </button>
        ))}
        <button className="tab-chip ghost" onClick={resetDemo} type="button">
          Reset Demo
        </button>
      </nav>

      <main className="workspace">
        {page === 'home' && (
          <section className="page-grid">
            <div className="panel story-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">What This Project Shows</p>
                  <h2>Zero Trust is not just login security</h2>
                </div>
              </div>
              <div className="pillar-grid">
                {[
                  ['Identity', 'Users are authenticated, challenged with MFA, and continuously re-evaluated.'],
                  ['Context', 'Device, IP, location, login time, and behavior all affect trust.'],
                  ['Policy', 'The policy engine decides allow, challenge, limit, or block.'],
                  ['Enforcement', 'Protected routes simulate API-level security enforcement.'],
                  ['Monitoring', 'The SOC-style dashboard tracks logs, sessions, and devices.'],
                  ['Attacks', 'The attack lab compares insecure behavior versus Zero Trust behavior.'],
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
                  <p className="eyebrow">Professor View</p>
                  <h2>What to click first</h2>
                </div>
              </div>
              <div className="feature-list">
                {[
                  'Go to Presentation Guide for the exact speaking flow.',
                  'Open Live Simulator and log in as admin.',
                  'Change the location or device to trigger MFA.',
                  'Call the admin API and then simulate IP shift.',
                  'Finish in Attack Lab with Zero Trust ON vs OFF.',
                ].map((item) => (
                  <article className="feature-row" key={item}>
                    <strong>{item}</strong>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Alerts</p>
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

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Current Status</p>
                  <h2>Decision stream</h2>
                </div>
              </div>
              <div className="status-banner">
                <strong>Live narration</strong>
                <p>{decisionStream}</p>
              </div>
            </div>
          </section>
        )}

        {page === 'architecture' && (
          <section className="page-grid">
            <div className="panel story-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Architecture</p>
                  <h2>Five-layer Zero Trust design</h2>
                </div>
              </div>
              <div className="roadmap-list">
                {[
                  ['1. Identity Layer', 'Login, MFA, session continuity, and tokenized access.'],
                  ['2. Device & Context Layer', 'IP, user agent, location, and device trust are captured.'],
                  ['3. Policy Engine', 'Rules combine role, risk, time, and route sensitivity.'],
                  ['4. Enforcement Layer', 'Protected routes simulate middleware and route guarding.'],
                  ['5. Monitoring Layer', 'Events, attacks, sessions, and device activity are visible on the dashboard.'],
                ].map(([title, body]) => (
                  <article className="roadmap-card" key={title}>
                    <strong>{title}</strong>
                    <p>{body}</p>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Micro-Segmentation</p>
                  <h2>Zone rules</h2>
                </div>
              </div>
              <div className="zone-list">
                {state.zonePolicies.map((policy) => (
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
          </section>
        )}

        {page === 'simulator' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Demo Identities</p>
                  <h2>Choose a user quickly</h2>
                </div>
              </div>
              <div className="credential-row">
                {state.users.map((user) => (
                  <button className="mini-credential" key={user.id} onClick={() => applyDemoIdentity(user.email, user.password, user.role)} type="button">
                    {user.role}
                  </button>
                ))}
              </div>
              <div className="helper-copy">
                Use `admin` to show strict controls, or change the location/device fields below to trigger a challenge.
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Login Simulation</p>
                  <h2>Adaptive access request</h2>
                </div>
              </div>
              <div className="form-grid">
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
                <select className="input" value={loginForm.requestedZone} onChange={(e) => setLoginForm({ ...loginForm, requestedZone: e.target.value as ZonePolicy['key'] })}>
                  {state.zonePolicies.map((policy) => (
                    <option key={policy.key} value={policy.key}>
                      {policy.zone}
                    </option>
                  ))}
                </select>
                <label className="toggle">
                  <input checked={loginForm.zeroTrustEnabled} onChange={(e) => setLoginForm({ ...loginForm, zeroTrustEnabled: e.target.checked })} type="checkbox" />
                  <span>Zero Trust mode enabled</span>
                </label>
                <button className="primary-button" onClick={handleLogin} type="button">
                  Run login flow
                </button>
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Session Results</p>
                  <h2>Show the professor exactly what the system decided</h2>
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
                      <button className="primary-button" onClick={verifyMfa} type="button">
                        Verify OTP
                      </button>
                    </div>
                  )}

                  <div className="inline-actions">
                    <button className="ghost-button" onClick={() => callProtectedZone('student')} type="button">
                      Test student API
                    </button>
                    <button className="ghost-button" onClick={() => callProtectedZone('admin')} type="button">
                      Test admin API
                    </button>
                    <button className="ghost-button" onClick={() => recheckSession('stable')} type="button">
                      Healthy recheck
                    </button>
                    <button className="ghost-button" onClick={() => recheckSession('ip_shift')} type="button">
                      Simulate IP shift
                    </button>
                    <button className="ghost-button" onClick={() => recheckSession('behavior_anomaly')} type="button">
                      Behavior anomaly
                    </button>
                  </div>

                  <div className="status-banner">
                    <strong>Protected route result</strong>
                    <p>{protectedResult || 'Use the buttons above to simulate API access and continuous-auth checks.'}</p>
                  </div>
                </div>
              ) : (
                <div className="empty-state">
                  <h3>No session yet</h3>
                  <p>Run a login flow first, then show MFA, API access, and continuous authentication.</p>
                </div>
              )}
            </div>
          </section>
        )}

        {page === 'dashboard' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Login Analytics</p>
                  <h2>Successful vs failed requests</h2>
                </div>
              </div>
              <div className="bar-chart">
                {state.charts.loginActivity.map((entry) => (
                  <div className="bar-group" key={entry.label}>
                    <div className="bar-stack">
                      <div className="bar success" style={{ height: `${entry.success * 6}px` }} />
                      <div className="bar danger" style={{ height: `${entry.failed * 6}px` }} />
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
                  <h2>Population risk posture</h2>
                </div>
              </div>
              <div className="distribution-list">
                {state.charts.riskDistribution.map((entry) => (
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
                  <h2>Tracked devices</h2>
                </div>
              </div>
              <div className="device-stack">
                {state.deviceRecords.map((device) => (
                  <article className="device-card" key={`${device.userId}-${device.deviceId}`}>
                    <div className="device-top">
                      <strong>{device.deviceId}</strong>
                      <span className={device.trusted ? 'good' : 'bad'}>{device.trusted ? 'Trusted' : 'Unknown'}</span>
                    </div>
                    <p>{device.location}</p>
                    <small>Last used at {shortTime(device.lastUsed)}</small>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Live Feed</p>
                  <h2>Recent security events</h2>
                </div>
              </div>
              <div className="log-table">
                {state.recentEvents.map((event) => (
                  <article className="log-row" key={event.id}>
                    <div>
                      <strong>{event.kind}</strong>
                      <p>{event.detail}</p>
                    </div>
                    <span>{event.user}</span>
                    <span>{event.zone}</span>
                    <span className={`status-pill ${event.result}`}>{event.result}</span>
                  </article>
                ))}
              </div>
            </div>
          </section>
        )}

        {page === 'attacks' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Attack Lab</p>
                  <h2>Without Zero Trust vs with Zero Trust</h2>
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
                <button className="primary-button" onClick={runAttackSimulation} type="button">
                  Run attack
                </button>
              </div>

              {attackResult ? (
                <div className={`attack-result ${attackResult.prevented ? 'safe' : 'breach'}`}>
                  <div className="attack-top">
                    <strong>{attackResult.type}</strong>
                    <span>{attackResult.prevented ? 'Blocked' : 'Compromised'}</span>
                  </div>
                  <p>{attackResult.detail}</p>
                </div>
              ) : (
                <div className="empty-state">
                  <h3>No attack run yet</h3>
                  <p>Run one scenario with Zero Trust ON, then OFF, to show the contrast clearly.</p>
                </div>
              )}
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Recorded Outcomes</p>
                  <h2>Latest comparisons</h2>
                </div>
              </div>
              <div className="comparison-stack">
                {state.attackResults.map((item) => (
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

        {page === 'presentation' && (
          <section className="page-grid">
            <div className="panel story-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">What To Tell Your Professor</p>
                  <h2>A clean 5-step demo script</h2>
                </div>
              </div>
              <div className="roadmap-list">
                {[
                  '1. Start on Home: explain that Zero Trust means never trust, always verify.',
                  '2. Open Architecture: show the five layers and micro-segmentation zones.',
                  '3. Open Live Simulator: log in as admin with normal values to show successful controlled access.',
                  '4. Change device or location: run login again to trigger MFA or a block due to risk scoring.',
                  '5. Open Attack Lab: run the same attack with Zero Trust ON and OFF to show the difference.',
                ].map((step) => (
                  <article className="roadmap-card" key={step}>
                    <strong>{step}</strong>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Best Demo Trick</p>
                  <h2>How to make the website feel alive</h2>
                </div>
              </div>
              <div className="feature-list">
                {[
                  'Use the admin profile first so your rules look strict and meaningful.',
                  'Then change the location from Bengaluru to Dubai to force a high-risk block.',
                  'After that, switch to student and try the admin API to show RBAC denial.',
                  'Finally, simulate IP shift after login to demonstrate continuous authentication.',
                ].map((item) => (
                  <article className="feature-row" key={item}>
                    <strong>{item}</strong>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">One-Sentence Pitch</p>
                  <h2>Say this clearly</h2>
                </div>
              </div>
              <div className="status-banner">
                <p>
                  Traditional systems trust users after login. My project continuously evaluates identity, device,
                  location, behavior, and requested resource, then dynamically adjusts access in real time.
                </p>
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Current Demo Status</p>
                  <h2>Ready to present</h2>
                </div>
              </div>
              <div className="status-banner">
                <p>
                  This version is multi-page, interactive, and self-contained, so you can present it even if a backend
                  service is unavailable.
                </p>
              </div>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
