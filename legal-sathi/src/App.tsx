import { useMemo, useState } from 'react';

type Role = 'student' | 'teacher' | 'admin';
type RouteKey = '/' | '/login' | '/dashboard' | '/admin' | '/attack-lab' | '/logs';
type ZoneKey = 'public' | 'student' | 'teacher' | 'admin';

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

type ZonePolicy = {
  key: ZoneKey;
  zone: string;
  description: string;
  requiredRole: Array<Role | 'guest'>;
  rule: string;
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
  requestedZone: ZoneKey;
  deviceTrusted: boolean;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high';
  behaviorScore: number;
  mfaRequired: boolean;
  mfaCompleted: boolean;
  zoneDecision: 'allowed' | 'challenge' | 'limited' | 'blocked' | 'revoked';
  policyReasons: string[];
  revoked: boolean;
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

type DeviceRecord = {
  userId: string;
  deviceId: string;
  trusted: boolean;
  lastUsed: string;
  ipAddress: string;
  location: string;
  userAgent: string;
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

type AppState = {
  users: DemoUser[];
  policies: ZonePolicy[];
  sessions: Session[];
  events: EventItem[];
  devices: DeviceRecord[];
  attacks: AttackResult[];
  metrics: {
    successfulLogins: number;
    blockedAttempts: number;
    stepUpChallenges: number;
    trustedDevices: number;
  };
};

const users: DemoUser[] = [
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

const policies: ZonePolicy[] = [
  {
    key: 'public',
    zone: 'Public Zone',
    description: 'Landing content, awareness pages, and system documentation.',
    requiredRole: ['guest', 'student', 'teacher', 'admin'],
    rule: 'No trust granted beyond public content visibility.',
  },
  {
    key: 'student',
    zone: 'Student Portal',
    description: 'Assignments, attendance, results, and student resources.',
    requiredRole: ['student', 'teacher', 'admin'],
    rule: 'Unknown devices trigger step-up verification before access.',
  },
  {
    key: 'teacher',
    zone: 'Faculty Workspace',
    description: 'Grading, moderation, and academic workflow tools.',
    requiredRole: ['teacher', 'admin'],
    rule: 'Role, context, and medium-risk policy checks enforced.',
  },
  {
    key: 'admin',
    zone: 'Admin Control Plane',
    description: 'Identity controls, audit logs, and sensitive operations.',
    requiredRole: ['admin'],
    rule: 'Fresh MFA, approved location, and strict role enforcement required.',
  },
];

const protectedRoutes: Record<Exclude<RouteKey, '/' | '/login'>, ZoneKey> = {
  '/dashboard': 'student',
  '/admin': 'admin',
  '/attack-lab': 'public',
  '/logs': 'admin',
};

const demoPresets: Record<Role, { route: RouteKey; zone: ZoneKey; deviceId: string; userAgent: string; location: string; ipAddress: string; loginHour: string; behaviorScore: string }> = {
  student: {
    route: '/dashboard',
    zone: 'student',
    deviceId: 'device-campus-laptop',
    userAgent: 'Chrome on Windows',
    location: 'Bengaluru, IN',
    ipAddress: '10.20.44.18',
    loginHour: '10',
    behaviorScore: '12',
  },
  teacher: {
    route: '/dashboard',
    zone: 'teacher',
    deviceId: 'device-faculty-mac',
    userAgent: 'Safari on macOS',
    location: 'Bengaluru, IN',
    ipAddress: '10.20.44.18',
    loginHour: '14',
    behaviorScore: '15',
  },
  admin: {
    route: '/admin',
    zone: 'admin',
    deviceId: 'device-admin-thinkpad',
    userAgent: 'Edge on Windows',
    location: 'Bengaluru, IN',
    ipAddress: '10.20.44.18',
    loginHour: '11',
    behaviorScore: '10',
  },
};

const attackOptions = [
  { key: 'brute_force', label: 'Brute force login' },
  { key: 'session_hijack', label: 'Token reuse / session hijack' },
  { key: 'admin_bypass', label: 'Direct admin URL access' },
];

function now() {
  return new Date().toISOString();
}

function readableTime(value: string) {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function riskLevel(score: number): Session['riskLevel'] {
  if (score >= 70) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

function simulateAttack(type: string, zeroTrustEnabled: boolean): AttackResult {
  const attackMap = {
    brute_force: {
      name: 'Brute force login',
      on: 'Rate limiting, OTP challenge, and monitoring block repeated login abuse.',
      off: 'Without Zero Trust controls, repeated guesses continue hitting the login surface.',
    },
    session_hijack: {
      name: 'Session hijacking',
      on: 'Continuous verification detects IP drift and revokes the stolen session.',
      off: 'A stolen session remains active after login in a perimeter-only model.',
    },
    admin_bypass: {
      name: 'Unauthorized admin access',
      on: 'Role-aware route protection and micro-segmentation block admin traversal instantly.',
      off: 'Weak segmentation exposes the admin surface once the user is inside.',
    },
  } as const;

  const item = attackMap[type as keyof typeof attackMap] ?? attackMap.brute_force;
  return {
    id: `atk-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
    type: item.name,
    prevented: zeroTrustEnabled,
    severity: type === 'brute_force' ? 'high' : 'critical',
    detail: zeroTrustEnabled ? item.on : item.off,
    actor: zeroTrustEnabled ? 'ZeroTrustX engine' : 'Legacy perimeter baseline',
    time: now(),
  };
}

function buildInitialState(): AppState {
  const devices: DeviceRecord[] = users.flatMap((user) =>
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

  return {
    users,
    policies,
    sessions: [],
    events: [
      {
        id: 'evt-1',
        time: now(),
        kind: 'Trusted admin sign-in',
        severity: 'low',
        user: 'Rohan Menon',
        zone: 'admin',
        result: 'allowed',
        detail: 'Known device, approved geography, and fresh verification satisfied access policy.',
      },
      {
        id: 'evt-2',
        time: now(),
        kind: 'Impossible travel blocked',
        severity: 'high',
        user: 'Aarav Sharma',
        zone: 'student',
        result: 'blocked',
        detail: 'Different geography and new network pushed risk above safe threshold.',
      },
      {
        id: 'evt-3',
        time: now(),
        kind: 'Behavior anomaly detected',
        severity: 'medium',
        user: 'Prof. Kavya Iyer',
        zone: 'teacher',
        result: 'limited',
        detail: 'Behavioral deviation reduced trust and restricted feature access.',
      },
    ],
    devices,
    attacks: [simulateAttack('brute_force', true), simulateAttack('session_hijack', true), simulateAttack('admin_bypass', false)],
    metrics: {
      successfulLogins: 24,
      blockedAttempts: 7,
      stepUpChallenges: 5,
      trustedDevices: devices.filter((device) => device.trusted).length,
    },
  };
}

export default function App() {
  const [route, setRoute] = useState<RouteKey>('/');
  const [state, setState] = useState<AppState>(() => buildInitialState());
  const [currentSession, setCurrentSession] = useState<Session | null>(null);
  const [loginForm, setLoginForm] = useState({
    email: 'admin@zerotrust.demo',
    password: 'admin123',
    deviceId: 'device-admin-thinkpad',
    userAgent: 'Edge on Windows',
    location: 'Bengaluru, IN',
    ipAddress: '10.20.44.18',
    loginHour: '11',
    behaviorScore: '10',
    requestedZone: 'admin' as ZoneKey,
    zeroTrustEnabled: true,
  });
  const [decisionStream, setDecisionStream] = useState(
    'This demo now shows real segmentation: public pages, login, dashboard, admin zone, attack lab, and logs.',
  );
  const [mfaCode, setMfaCode] = useState('482911');
  const [protectedResult, setProtectedResult] = useState('');
  const [selectedAttack, setSelectedAttack] = useState('session_hijack');
  const [attackMode, setAttackMode] = useState(true);
  const [attackResult, setAttackResult] = useState<AttackResult | null>(null);

  const highPriorityAlerts = useMemo(
    () => state.events.filter((event) => event.severity !== 'low').slice(0, 4),
    [state.events],
  );

  const loginChart = [
    { label: 'Mon', success: 12, failed: 4 },
    { label: 'Tue', success: 15, failed: 5 },
    { label: 'Wed', success: 17, failed: 6 },
    { label: 'Thu', success: 18, failed: 3 },
    { label: 'Fri', success: 16, failed: 7 },
    { label: 'Sat', success: 10, failed: 2 },
  ];

  const riskChart = [
    { label: 'Low', value: 51 },
    { label: 'Medium', value: 31 },
    { label: 'High', value: 18 },
  ];

  function pushEvent(event: EventItem) {
    setState((current) => ({
      ...current,
      events: [event, ...current.events].slice(0, 14),
      metrics: {
        ...current.metrics,
        blockedAttempts:
          current.metrics.blockedAttempts + (event.result === 'blocked' || event.result === 'revoked' ? 1 : 0),
        stepUpChallenges: current.metrics.stepUpChallenges + (event.result === 'challenge' ? 1 : 0),
      },
    }));
  }

  function navigate(next: RouteKey) {
    if (next === '/login' || next === '/' || next === '/attack-lab') {
      setRoute(next);
      return;
    }

    if (!currentSession || currentSession.revoked) {
      setDecisionStream(`Access to ${next} denied until a verified session exists.`);
      setRoute('/login');
      return;
    }

    const zone = protectedRoutes[next];
    const decision = evaluateRouteAccess(zone, currentSession, Number(loginForm.loginHour));
    if (!decision.allowed) {
      pushEvent({
        id: `evt-${Date.now()}`,
        time: now(),
        kind: 'Route access blocked',
        severity: 'high',
        user: currentSession.userName,
        zone,
        result: 'blocked',
        detail: decision.reasons.join(' '),
      });
      setDecisionStream(`Navigation blocked: ${decision.reasons.join(' ')}`);
      return;
    }

    setRoute(next);
  }

  function applyDemoPreset(role: Role) {
    const user = state.users.find((item) => item.role === role);
    if (!user) return;
    const preset = demoPresets[role];
    setLoginForm({
      email: user.email,
      password: user.password,
      requestedZone: preset.zone,
      deviceId: preset.deviceId,
      userAgent: preset.userAgent,
      location: preset.location,
      ipAddress: preset.ipAddress,
      loginHour: preset.loginHour,
      behaviorScore: preset.behaviorScore,
      zeroTrustEnabled: true,
    });
    setRoute('/login');
  }

  function computeRisk(user: DemoUser) {
    let score = 0;
    const reasons: string[] = [];
    const trustedDevice = user.knownDevices.includes(loginForm.deviceId);
    const trustedLocation = user.typicalLocations.includes(loginForm.location);
    const trustedNetwork = loginForm.ipAddress.startsWith(user.homeIpPrefix);
    const hour = Number(loginForm.loginHour);
    const behavior = Number(loginForm.behaviorScore);

    if (!trustedDevice) {
      score += 30;
      reasons.push('New device detected.');
    }
    if (!trustedNetwork) {
      score += 20;
      reasons.push('New IP/network detected.');
    }
    if (!trustedLocation) {
      score += 40;
      reasons.push('Different location detected.');
    }
    if (hour >= 22 || hour <= 5) {
      score += 10;
      reasons.push('Odd login time.');
    }
    if (behavior >= 60) {
      score += 15;
      reasons.push('Behavior anomaly detected.');
    }
    if (loginForm.requestedZone === 'admin') {
      score += 8;
      reasons.push('Privileged zone requested.');
    }

    return {
      score,
      reasons: reasons.length > 0 ? reasons : ['Known device, expected network, and normal behavior.'],
      trustedDevice,
      level: riskLevel(score),
    };
  }

  function evaluateRouteAccess(zone: ZoneKey, session: Session, loginHour: number) {
    const policy = state.policies.find((item) => item.key === zone) ?? state.policies[0];
    const reasons: string[] = [];

    if (!policy.requiredRole.includes(session.role)) {
      reasons.push(`Role ${session.role} cannot enter ${policy.zone}.`);
    }
    if (session.riskScore >= 70) {
      reasons.push('Risk score is too high.');
    } else if (session.riskScore >= 30 && !session.mfaCompleted) {
      reasons.push('MFA is required before access may continue.');
    }
    if (zone === 'admin') {
      if (!session.location.toLowerCase().includes('bengaluru')) {
        reasons.push('Admin zone is limited to approved geography.');
      }
      if (loginHour >= 22 || loginHour <= 5) {
        reasons.push('Admin access outside approved hours is blocked.');
      }
      if (!session.mfaCompleted) {
        reasons.push('Fresh MFA is required for admin access.');
      }
    }
    if ((zone === 'student' || zone === 'teacher') && !session.deviceTrusted && !session.mfaCompleted) {
      reasons.push('Unknown device requires step-up verification.');
    }

    return {
      allowed: reasons.length === 0,
      reasons: reasons.length > 0 ? reasons : ['Policy requirements satisfied.'],
    };
  }

  function handleLogin() {
    const user = state.users.find((item) => item.email === loginForm.email);
    if (!user || user.password !== loginForm.password) {
      pushEvent({
        id: `evt-${Date.now()}`,
        time: now(),
        kind: 'Invalid login attempt',
        severity: 'high',
        user: loginForm.email || 'Unknown',
        zone: loginForm.requestedZone,
        result: 'blocked',
        detail: 'Credential validation failed.',
      });
      setDecisionStream('Login failed: invalid credentials.');
      return;
    }

    const risk = computeRisk(user);
    const needsMfa = loginForm.zeroTrustEnabled && risk.score >= 30 && risk.score < 70;
    const decision = evaluateRouteAccess(loginForm.requestedZone, {
      id: 'preview',
      userId: user.id,
      userName: user.name,
      role: user.role,
      location: loginForm.location,
      ipAddress: loginForm.ipAddress,
      deviceId: loginForm.deviceId,
      userAgent: loginForm.userAgent,
      requestedZone: loginForm.requestedZone,
      deviceTrusted: risk.trustedDevice,
      riskScore: risk.score,
      riskLevel: risk.level,
      behaviorScore: Number(loginForm.behaviorScore),
      mfaRequired: needsMfa,
      mfaCompleted: false,
      zoneDecision: 'blocked',
      policyReasons: [],
      revoked: false,
    }, Number(loginForm.loginHour));

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
      deviceTrusted: risk.trustedDevice,
      riskScore: risk.score,
      riskLevel: risk.level,
      behaviorScore: Number(loginForm.behaviorScore),
      mfaRequired: needsMfa,
      mfaCompleted: false,
      zoneDecision: risk.score >= 70 ? 'blocked' : needsMfa ? 'challenge' : decision.allowed ? 'allowed' : 'blocked',
      policyReasons: risk.score >= 70 ? ['Risk score too high. Access denied immediately.'] : decision.reasons,
      revoked: false,
    };

    setCurrentSession(session);
    setState((current) => ({
      ...current,
      sessions: [session, ...current.sessions.filter((item) => item.userId !== user.id)].slice(0, 6),
      devices: [
        {
          userId: user.id,
          deviceId: loginForm.deviceId,
          trusted: risk.score < 30,
          lastUsed: now(),
          ipAddress: loginForm.ipAddress,
          location: loginForm.location,
          userAgent: loginForm.userAgent,
        },
        ...current.devices.filter((item) => !(item.userId === user.id && item.deviceId === loginForm.deviceId)),
      ].slice(0, 10),
      metrics: {
        ...current.metrics,
        successfulLogins: current.metrics.successfulLogins + (session.zoneDecision === 'allowed' ? 1 : 0),
        stepUpChallenges: current.metrics.stepUpChallenges + (needsMfa ? 1 : 0),
      },
    }));

    if (risk.score >= 70) {
      pushEvent({
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
      pushEvent({
        id: `evt-${Date.now()}`,
        time: now(),
        kind: 'Adaptive MFA triggered',
        severity: 'medium',
        user: user.name,
        zone: loginForm.requestedZone,
        result: 'challenge',
        detail: risk.reasons.join(' '),
      });
      setDecisionStream(`MFA required. Risk score ${risk.score}. Demo OTP: 482911.`);
      return;
    }

    pushEvent({
      id: `evt-${Date.now()}`,
      time: now(),
      kind: 'Login allowed',
      severity: 'low',
      user: user.name,
      zone: loginForm.requestedZone,
      result: 'allowed',
      detail: decision.reasons.join(' '),
    });
    setDecisionStream(`Access granted. ${decision.reasons.join(' ')}`);
    setRoute(user.role === 'admin' ? '/admin' : '/dashboard');
  }

  function verifyMfa() {
    if (!currentSession) return;
    if (mfaCode !== '482911') {
      pushEvent({
        id: `evt-${Date.now()}`,
        time: now(),
        kind: 'MFA verification failed',
        severity: 'high',
        user: currentSession.userName,
        zone: currentSession.requestedZone,
        result: 'blocked',
        detail: 'Incorrect OTP submitted during adaptive verification.',
      });
      setDecisionStream('Incorrect OTP. Access remains blocked.');
      return;
    }

    const decision = evaluateRouteAccess(currentSession.requestedZone, currentSession, Number(loginForm.loginHour));
    const updated: Session = {
      ...currentSession,
      mfaCompleted: true,
      zoneDecision: decision.allowed ? 'allowed' : 'blocked',
      policyReasons: decision.reasons,
    };
    setCurrentSession(updated);
    setState((current) => ({
      ...current,
      sessions: current.sessions.map((item) => (item.id === updated.id ? updated : item)),
      metrics: {
        ...current.metrics,
        successfulLogins: current.metrics.successfulLogins + (decision.allowed ? 1 : 0),
      },
    }));
    pushEvent({
      id: `evt-${Date.now()}`,
      time: now(),
      kind: decision.allowed ? 'MFA verified' : 'Post-MFA policy block',
      severity: decision.allowed ? 'low' : 'high',
      user: updated.userName,
      zone: updated.requestedZone,
      result: decision.allowed ? 'allowed' : 'blocked',
      detail: decision.reasons.join(' '),
    });
    setDecisionStream(decision.allowed ? 'OTP accepted. Access granted.' : `OTP accepted, but policy blocks access: ${decision.reasons.join(' ')}`);
    if (decision.allowed) {
      setRoute(updated.role === 'admin' ? '/admin' : '/dashboard');
    }
  }

  function testProtectedZone(zone: ZoneKey) {
    if (!currentSession) {
      setProtectedResult('No verified session. Login first.');
      return;
    }
    const decision = evaluateRouteAccess(zone, currentSession, Number(loginForm.loginHour));
    if (!decision.allowed) {
      pushEvent({
        id: `evt-${Date.now()}`,
        time: now(),
        kind: 'Protected resource blocked',
        severity: 'high',
        user: currentSession.userName,
        zone,
        result: 'blocked',
        detail: decision.reasons.join(' '),
      });
      setProtectedResult(`403 Forbidden: ${decision.reasons.join(' ')}`);
      return;
    }

    pushEvent({
      id: `evt-${Date.now()}`,
      time: now(),
      kind: 'Protected resource allowed',
      severity: 'low',
      user: currentSession.userName,
      zone,
      result: 'allowed',
      detail: 'Role, context, and risk policy all passed.',
    });
    setProtectedResult(`200 OK: access granted to ${zone} zone.`);
  }

  function recheckSession(mode: 'stable' | 'ip_shift' | 'behavior_anomaly') {
    if (!currentSession) return;
    let updated = { ...currentSession };
    let message = 'Session remains healthy.';

    if (mode === 'ip_shift') {
      updated.riskScore = Math.min(98, updated.riskScore + 26);
      updated.riskLevel = riskLevel(updated.riskScore);
      updated.zoneDecision = updated.riskScore >= 70 ? 'revoked' : 'challenge';
      updated.revoked = updated.riskScore >= 70;
      message =
        updated.riskScore >= 70
          ? 'Continuous verification revoked the session after an IP shift.'
          : 'Continuous verification paused access and requires re-authentication.';
    } else if (mode === 'behavior_anomaly') {
      updated.riskScore = Math.min(95, updated.riskScore + 18);
      updated.riskLevel = riskLevel(updated.riskScore);
      updated.zoneDecision = 'limited';
      message = 'Behavior anomaly raised risk and restricted access scope.';
    } else {
      updated.riskScore = Math.max(8, updated.riskScore - 4);
      updated.riskLevel = riskLevel(updated.riskScore);
      updated.zoneDecision = updated.mfaCompleted || !updated.mfaRequired ? 'allowed' : updated.zoneDecision;
    }

    setCurrentSession(updated);
    setState((current) => ({
      ...current,
      sessions: current.sessions.map((item) => (item.id === updated.id ? updated : item)),
    }));
    pushEvent({
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

  function runAttack() {
    const result = simulateAttack(selectedAttack, attackMode);
    setAttackResult(result);
    setState((current) => ({
      ...current,
      attacks: [result, ...current.attacks].slice(0, 6),
    }));
    pushEvent({
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
    setDecisionStream('Demo reset. Start from the landing page and walk through the system again.');
    setRoute('/');
  }

  return (
    <div className="shell">
      <div className="aurora aurora-one" />
      <div className="aurora aurora-two" />

      <header className="masthead">
        <div className="brand-block">
          <p className="eyebrow">ZeroTrustX - Zero Trust for College Systems</p>
          <h1>This is now a segmented system, not a single-page concept demo.</h1>
          <p className="hero-copy">
            Public landing page, dedicated login page, protected dashboard, protected admin control plane, attack lab,
            and security logs. The navigation itself now proves Zero Trust segmentation.
          </p>
          <div className="hero-actions">
            <button className="primary-button" onClick={() => navigate('/login')} type="button">
              Start Login Demo
            </button>
            <button className="ghost-button" onClick={() => navigate('/attack-lab')} type="button">
              Open Attack Lab
            </button>
          </div>
        </div>

        <div className="hero-rail">
          <div className="metric-card">
            <span>Current posture</span>
            <strong>{state.metrics.blockedAttempts}</strong>
            <p>Blocked requests, suspicious behavior, and attack outcomes are visible in the system logs.</p>
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
        {[
          { path: '/', label: 'Landing' },
          { path: '/login', label: 'Login' },
          { path: '/dashboard', label: 'Dashboard' },
          { path: '/admin', label: 'Admin' },
          { path: '/attack-lab', label: 'Attack Lab' },
          { path: '/logs', label: 'Logs' },
        ].map((item) => (
          <button
            key={item.path}
            className={route === item.path ? 'tab-chip active' : 'tab-chip'}
            onClick={() => navigate(item.path as RouteKey)}
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
        {route === '/' && (
          <section className="page-grid">
            <div className="panel story-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">System Story</p>
                  <h2>Vulnerable college systems trust too much after login</h2>
                </div>
              </div>
              <div className="pillar-grid">
                {[
                  ['Landing Page', 'Explains the threat model and the need for Zero Trust in a college portal.'],
                  ['Login Page', 'Identity-first access with context-aware risk analysis and MFA.'],
                  ['Dashboard', 'Protected academic workspace for verified users only.'],
                  ['Admin Page', 'Strictly segmented control plane with tighter rules.'],
                  ['Attack Lab', 'Demonstrates attack scenarios with and without Zero Trust enforcement.'],
                  ['Logs Page', 'Shows visibility, alerts, and proof that the system is reacting.'],
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
                  <p className="eyebrow">How To Demo</p>
                  <h2>Best flow for your professor</h2>
                </div>
              </div>
              <div className="feature-list">
                {[
                  '1. Open Login and sign in as admin with normal context.',
                  '2. Show that the Admin page is protected and reachable only after validation.',
                  '3. Change location or device and trigger MFA or a block.',
                  '4. Move to Dashboard and test protected student/admin resource access.',
                  '5. End in Attack Lab and then show the Logs page as proof of enforcement.',
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
                  <p className="eyebrow">Current Narrative</p>
                  <h2>What the system is doing</h2>
                </div>
              </div>
              <div className="status-banner">
                <strong>Decision stream</strong>
                <p>{decisionStream}</p>
              </div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Critical Alerts</p>
                  <h2>Why visibility matters</h2>
                </div>
              </div>
              <div className="alert-stack">
                {highPriorityAlerts.map((event) => (
                  <article className={`alert-card ${event.severity}`} key={event.id}>
                    <div className="alert-top">
                      <strong>{event.kind}</strong>
                      <span>{event.severity}</span>
                    </div>
                    <p>{event.detail}</p>
                  </article>
                ))}
              </div>
            </div>
          </section>
        )}

        {route === '/login' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Demo Presets</p>
                  <h2>Choose a user identity</h2>
                </div>
              </div>
              <div className="credential-row">
                {(['student', 'teacher', 'admin'] as Role[]).map((role) => (
                  <button className="mini-credential" key={role} onClick={() => applyDemoPreset(role)} type="button">
                    {role}
                  </button>
                ))}
              </div>
              <div className="helper-copy">Start with `admin`, then change location or device to prove enforcement.</div>
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Authentication</p>
                  <h2>Risk-aware login flow</h2>
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
                <select className="input" value={loginForm.requestedZone} onChange={(e) => setLoginForm({ ...loginForm, requestedZone: e.target.value as ZoneKey })}>
                  {state.policies.map((policy) => (
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
                  Request access
                </button>
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Access Decision</p>
                  <h2>Show identity, context, and policy enforcement</h2>
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

                  <div className="status-banner">
                    <strong>Decision stream</strong>
                    <p>{decisionStream}</p>
                  </div>
                </div>
              ) : (
                <div className="empty-state">
                  <h3>No active session</h3>
                  <p>Run a login flow first. The result card will explain why access was allowed, challenged, or blocked.</p>
                </div>
              )}
            </div>
          </section>
        )}

        {route === '/dashboard' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Protected Student Zone</p>
                  <h2>Academic dashboard</h2>
                </div>
              </div>
              <div className="feature-list">
                {[
                  'Assignments and coursework',
                  'Attendance records',
                  'Internal student resources',
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
                  <p className="eyebrow">Protected Resource Tests</p>
                  <h2>Prove route and policy enforcement</h2>
                </div>
              </div>
              <div className="inline-actions">
                <button className="ghost-button" onClick={() => testProtectedZone('student')} type="button">
                  Test student resource
                </button>
                <button className="ghost-button" onClick={() => testProtectedZone('admin')} type="button">
                  Try admin resource
                </button>
                <button className="ghost-button" onClick={() => recheckSession('ip_shift')} type="button">
                  Simulate IP shift
                </button>
                <button className="ghost-button" onClick={() => recheckSession('behavior_anomaly')} type="button">
                  Simulate behavior anomaly
                </button>
              </div>
              <div className="status-banner">
                <strong>Response</strong>
                <p>{protectedResult || 'Use the actions above to show policy checks and continuous verification.'}</p>
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Why This Matters</p>
                  <h2>This page is segmented from admin by policy</h2>
                </div>
              </div>
              <div className="roadmap-list">
                {[
                  'Students can use this page after successful validation.',
                  'Teachers may also access student-facing tools when policy allows it.',
                  'Direct access to the admin zone is still separately protected.',
                ].map((item) => (
                  <article className="roadmap-card" key={item}>
                    <strong>{item}</strong>
                  </article>
                ))}
              </div>
            </div>
          </section>
        )}

        {route === '/admin' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Admin Control Plane</p>
                  <h2>Strictly segmented privileged zone</h2>
                </div>
              </div>
              <div className="feature-list">
                {[
                  'Identity configuration',
                  'Token and session controls',
                  'Security analytics and audit settings',
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
                  <p className="eyebrow">Continuous Verification</p>
                  <h2>Change context after login</h2>
                </div>
              </div>
              <div className="inline-actions">
                <button className="ghost-button" onClick={() => recheckSession('stable')} type="button">
                  Healthy recheck
                </button>
                <button className="ghost-button" onClick={() => recheckSession('ip_shift')} type="button">
                  IP shift
                </button>
                <button className="ghost-button" onClick={() => recheckSession('behavior_anomaly')} type="button">
                  Behavior anomaly
                </button>
              </div>
              <div className="status-banner">
                <strong>Live system response</strong>
                <p>{decisionStream}</p>
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Access Explanation</p>
                  <h2>Why this page proves Zero Trust</h2>
                </div>
              </div>
              <div className="roadmap-list">
                {[
                  'This page is not just another section; it is a separate security zone.',
                  'Admin access depends on role, location, risk score, and MFA completion.',
                  'A context change after login can still limit or revoke the session.',
                ].map((item) => (
                  <article className="roadmap-card" key={item}>
                    <strong>{item}</strong>
                  </article>
                ))}
              </div>
            </div>
          </section>
        )}

        {route === '/attack-lab' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Attack Lab</p>
                  <h2>Show failure and protection side by side</h2>
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
                <button className="primary-button" onClick={runAttack} type="button">
                  Run simulation
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
                  <h3>No simulation yet</h3>
                  <p>Run a scenario with Zero Trust ON and OFF to create the strongest contrast.</p>
                </div>
              )}
            </div>

            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Attack Results</p>
                  <h2>Latest comparisons</h2>
                </div>
              </div>
              <div className="comparison-stack">
                {state.attacks.map((item) => (
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

        {route === '/logs' && (
          <section className="page-grid">
            <div className="panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Login Analytics</p>
                  <h2>Successful vs failed access</h2>
                </div>
              </div>
              <div className="bar-chart">
                {loginChart.map((entry) => (
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
                  <h2>Observed session posture</h2>
                </div>
              </div>
              <div className="distribution-list">
                {riskChart.map((entry) => (
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
                  <p className="eyebrow">Device Inventory</p>
                  <h2>Tracked trust state</h2>
                </div>
              </div>
              <div className="device-stack">
                {state.devices.map((device) => (
                  <article className="device-card" key={`${device.userId}-${device.deviceId}`}>
                    <div className="device-top">
                      <strong>{device.deviceId}</strong>
                      <span className={device.trusted ? 'good' : 'bad'}>{device.trusted ? 'Trusted' : 'Unknown'}</span>
                    </div>
                    <p>{device.location}</p>
                    <small>Last used at {readableTime(device.lastUsed)}</small>
                  </article>
                ))}
              </div>
            </div>

            <div className="panel wide-panel">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Security Logs</p>
                  <h2>System visibility and proof of intelligence</h2>
                </div>
              </div>
              <div className="log-table">
                {state.events.map((event) => (
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
      </main>
    </div>
  );
}
