import cors from 'cors';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const port = Number(process.env.PORT || 8788);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distPath = path.resolve(__dirname, '../dist');

const zonePolicies = [
  {
    zone: 'Public Zone',
    key: 'public',
    description: 'Marketing pages and policy documentation.',
    requiredRole: ['guest', 'student', 'teacher', 'admin'],
    rule: 'Low-friction access with telemetry logging only.',
  },
  {
    zone: 'Student Workspace',
    key: 'student',
    description: 'Course files, attendance, and assignment systems.',
    requiredRole: ['student', 'teacher', 'admin'],
    rule: 'Known device or successful step-up MFA required when risk exceeds baseline.',
  },
  {
    zone: 'Faculty Tools',
    key: 'teacher',
    description: 'Academic workflows, grading, and moderation.',
    requiredRole: ['teacher', 'admin'],
    rule: 'Role + trusted device + medium-risk threshold enforcement.',
  },
  {
    zone: 'Admin Control Plane',
    key: 'admin',
    description: 'Identity controls, logs, and sensitive operations.',
    requiredRole: ['admin'],
    rule: 'Restricted to college network during approved hours with fresh MFA.',
  },
];

const baselineUsers = [
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

const securityState = createInitialState();

app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(',') ?? true,
  }),
);
app.use(express.json({ limit: '2mb' }));

app.get('/api/health', (_request, response) => {
  response.json({
    ok: true,
    app: 'zero-trust-access-demo',
    date: new Date().toISOString(),
    mode: 'simulation',
  });
});

app.get('/api/zero-trust/bootstrap', (_request, response) => {
  response.json(buildDashboardPayload());
});

app.post('/api/zero-trust/login', (request, response) => {
  const payload = normalizeLoginPayload(request.body ?? {});
  const user = baselineUsers.find((entry) => entry.email === payload.email);

  if (!user || user.password !== payload.password) {
    recordAttack({
      type: 'Brute force attempt',
      actor: payload.email || 'unknown',
      prevented: payload.zeroTrustEnabled,
      severity: 'high',
      detail: payload.zeroTrustEnabled
        ? 'Repeated invalid credentials were rate-limited and logged.'
        : 'Invalid login attempt would blend into a perimeter-only model.',
    });

    response.status(401).json({
      status: 'denied',
      message: 'Invalid credentials.',
      event: latestEvent(),
      dashboard: buildDashboardPayload(),
    });
    return;
  }

  const risk = scoreRisk(user, payload);
  const requiresMfa = risk.score >= 55 || !risk.deviceTrusted || payload.ipAddress !== `${user.homeIpPrefix}44.18`;
  const sessionId = `session-${Date.now()}`;
  const policyDecision = evaluateZoneAccess({
    requestedZone: payload.requestedZone,
    role: user.role,
    location: payload.location,
    deviceTrusted: risk.deviceTrusted,
    mfaSatisfied: !requiresMfa,
    loginHour: payload.loginHour,
  });

  const session = {
    id: sessionId,
    userId: user.id,
    userName: user.name,
    role: user.role,
    location: payload.location,
    ipAddress: payload.ipAddress,
    deviceId: payload.deviceId,
    deviceTrusted: risk.deviceTrusted,
    riskScore: risk.score,
    riskLevel: risk.level,
    mfaRequired: requiresMfa,
    mfaCompleted: false,
    requestedZone: payload.requestedZone,
    zoneDecision: policyDecision.allowed ? 'pending-mfa' : 'denied',
    policyReasons: policyDecision.reasons,
    createdAt: new Date().toISOString(),
  };

  securityState.sessions.unshift(session);

  recordEvent({
    kind: requiresMfa ? 'Step-up MFA triggered' : 'Session created',
    severity: requiresMfa ? 'medium' : 'low',
    user: user.name,
    zone: payload.requestedZone,
    result: requiresMfa ? 'challenge' : policyDecision.allowed ? 'allowed' : 'blocked',
    detail: risk.summary,
  });

  response.json({
    status: requiresMfa ? 'mfa_required' : policyDecision.allowed ? 'allowed' : 'denied',
    session,
    policyDecision,
    risk,
    mfaCode: requiresMfa ? '482911' : null,
    dashboard: buildDashboardPayload(),
  });
});

app.post('/api/zero-trust/mfa/verify', (request, response) => {
  const sessionId = String(request.body?.sessionId || '').trim();
  const code = String(request.body?.code || '').trim();
  const session = securityState.sessions.find((entry) => entry.id === sessionId);

  if (!session) {
    response.status(404).json({ error: 'Session not found.' });
    return;
  }

  if (code !== '482911') {
    recordEvent({
      kind: 'MFA verification failed',
      severity: 'high',
      user: session.userName,
      zone: session.requestedZone,
      result: 'blocked',
      detail: 'Invalid step-up code submitted for elevated-risk session.',
    });
    response.status(400).json({
      status: 'denied',
      message: 'Invalid OTP.',
      dashboard: buildDashboardPayload(),
    });
    return;
  }

  session.mfaCompleted = true;
  const finalDecision = evaluateZoneAccess({
    requestedZone: session.requestedZone,
    role: session.role,
    location: session.location,
    deviceTrusted: session.deviceTrusted,
    mfaSatisfied: true,
    loginHour: new Date().getHours(),
  });
  session.zoneDecision = finalDecision.allowed ? 'allowed' : 'denied';

  recordEvent({
    kind: finalDecision.allowed ? 'MFA verified' : 'Post-MFA policy block',
    severity: finalDecision.allowed ? 'low' : 'high',
    user: session.userName,
    zone: session.requestedZone,
    result: finalDecision.allowed ? 'allowed' : 'blocked',
    detail: finalDecision.allowed
      ? 'User satisfied step-up authentication and entered the requested zone.'
      : finalDecision.reasons.join(' '),
  });

  response.json({
    status: finalDecision.allowed ? 'allowed' : 'denied',
    session,
    policyDecision: finalDecision,
    dashboard: buildDashboardPayload(),
  });
});

app.post('/api/zero-trust/session/recheck', (request, response) => {
  const sessionId = String(request.body?.sessionId || '').trim();
  const scenario = String(request.body?.scenario || 'stable').trim();
  const session = securityState.sessions.find((entry) => entry.id === sessionId);

  if (!session) {
    response.status(404).json({ error: 'Session not found.' });
    return;
  }

  let outcome;

  if (scenario === 'ip_shift') {
    session.riskScore = Math.min(98, session.riskScore + 26);
    session.riskLevel = classifyRisk(session.riskScore);
    session.zoneDecision = 'step-up';
    outcome = {
      status: 'step_up_required',
      title: 'Suspicious network shift detected',
      message: 'Continuous authentication noticed a sudden IP change and paused privileged access.',
    };
  } else if (scenario === 'behavior_anomaly') {
    session.riskScore = Math.min(95, session.riskScore + 18);
    session.riskLevel = classifyRisk(session.riskScore);
    session.zoneDecision = 'limited';
    outcome = {
      status: 'limited_access',
      title: 'Behavioral anomaly flagged',
      message: 'Unusual navigation speed triggered a policy downgrade and extra monitoring.',
    };
  } else {
    session.riskScore = Math.max(8, session.riskScore - 4);
    session.riskLevel = classifyRisk(session.riskScore);
    outcome = {
      status: 'healthy',
      title: 'Session healthy',
      message: 'Telemetry remains consistent with the trusted baseline.',
    };
  }

  recordEvent({
    kind: 'Continuous authentication check',
    severity: outcome.status === 'healthy' ? 'low' : 'medium',
    user: session.userName,
    zone: session.requestedZone,
    result: outcome.status,
    detail: outcome.message,
  });

  response.json({
    session,
    outcome,
    dashboard: buildDashboardPayload(),
  });
});

app.post('/api/zero-trust/access-check', (request, response) => {
  const decision = evaluateZoneAccess({
    requestedZone: String(request.body?.requestedZone || 'public'),
    role: String(request.body?.role || 'guest'),
    location: String(request.body?.location || 'Remote'),
    deviceTrusted: Boolean(request.body?.deviceTrusted),
    mfaSatisfied: Boolean(request.body?.mfaSatisfied),
    loginHour: Number(request.body?.loginHour ?? 12),
  });

  response.json({ decision });
});

app.post('/api/zero-trust/attacks/simulate', (request, response) => {
  const attackType = String(request.body?.attackType || '').trim();
  const zeroTrustEnabled = Boolean(request.body?.zeroTrustEnabled);
  const result = simulateAttack(attackType, zeroTrustEnabled);
  recordAttack(result);

  response.json({
    result,
    dashboard: buildDashboardPayload(),
  });
});

app.post('/api/zero-trust/reset', (_request, response) => {
  Object.assign(securityState, createInitialState());
  response.json(buildDashboardPayload());
});

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(distPath));
  app.get(/.*/, (_request, response) => {
    response.sendFile(path.join(distPath, 'index.html'));
  });
}

app.listen(port, () => {
  console.log(`Zero Trust demo server running on http://localhost:${port}`);
});

function createInitialState() {
  return {
    sessions: [],
    events: [
      {
        id: 'evt-seed-1',
        time: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
        kind: 'Trusted admin sign-in',
        severity: 'low',
        user: 'Rohan Menon',
        zone: 'admin',
        result: 'allowed',
        detail: 'Known device, campus IP, and fresh MFA allowed access.',
      },
      {
        id: 'evt-seed-2',
        time: new Date(Date.now() - 1000 * 60 * 9).toISOString(),
        kind: 'Impossible travel blocked',
        severity: 'high',
        user: 'Aarav Sharma',
        zone: 'student',
        result: 'blocked',
        detail: 'Login attempt from a new geography was denied pending identity proof.',
      },
      {
        id: 'evt-seed-3',
        time: new Date(Date.now() - 1000 * 60 * 4).toISOString(),
        kind: 'Session re-check',
        severity: 'medium',
        user: 'Prof. Kavya Iyer',
        zone: 'teacher',
        result: 'limited_access',
        detail: 'Abnormal behavior reduced privileges until re-verification.',
      },
    ],
    attacks: [
      simulateAttack('brute_force', true, true),
      simulateAttack('session_hijack', true, true),
      simulateAttack('admin_bypass', false, true),
    ],
  };
}

function buildDashboardPayload() {
  const totals = {
    successfulLogins: securityState.sessions.filter((entry) => entry.zoneDecision === 'allowed').length + 24,
    blockedAttempts:
      securityState.events.filter((entry) => entry.result === 'blocked').length +
      securityState.attacks.filter((entry) => entry.prevented).length,
    stepUpChallenges:
      securityState.sessions.filter((entry) => entry.mfaRequired).length +
      securityState.events.filter((entry) => entry.kind.includes('MFA')).length,
    trustedDevices: new Set(baselineUsers.flatMap((user) => user.knownDevices)).size,
  };

  return {
    users: baselineUsers.map(({ password, ...user }) => user),
    zonePolicies,
    metrics: totals,
    activeSessions: securityState.sessions.slice(0, 5),
    recentEvents: securityState.events.slice(0, 8),
    attackResults: securityState.attacks.slice(0, 6),
    charts: {
      loginActivity: [
        { label: 'Mon', success: 12, failed: 4 },
        { label: 'Tue', success: 14, failed: 5 },
        { label: 'Wed', success: 17, failed: 6 },
        { label: 'Thu', success: 18, failed: 3 },
        { label: 'Fri', success: 16, failed: 7 },
        { label: 'Sat', success: 10, failed: 2 },
      ],
      deviceTrust: [
        { label: 'Trusted', value: 68 },
        { label: 'Unknown', value: 22 },
        { label: 'Quarantined', value: 10 },
      ],
      riskDistribution: [
        { label: 'Low', value: 51 },
        { label: 'Medium', value: 31 },
        { label: 'High', value: 18 },
      ],
    },
    demoCredentials: baselineUsers.map((user) => ({
      email: user.email,
      password: user.password,
      role: user.role,
    })),
  };
}

function normalizeLoginPayload(payload) {
  return {
    email: String(payload.email || '').trim().toLowerCase(),
    password: String(payload.password || '').trim(),
    deviceId: String(payload.deviceId || 'unknown-device').trim(),
    location: String(payload.location || 'Remote').trim(),
    ipAddress: String(payload.ipAddress || '203.0.113.42').trim(),
    loginHour: Number(payload.loginHour ?? 11),
    requestedZone: String(payload.requestedZone || 'student').trim(),
    zeroTrustEnabled: Boolean(payload.zeroTrustEnabled),
  };
}

function scoreRisk(user, payload) {
  let score = 12;
  const reasons = [];
  const deviceTrusted = user.knownDevices.includes(payload.deviceId);
  const familiarLocation = user.typicalLocations.includes(payload.location);
  const campusIp = payload.ipAddress.startsWith(user.homeIpPrefix);

  if (!deviceTrusted) {
    score += 30;
    reasons.push('New device fingerprint detected.');
  }

  if (!familiarLocation) {
    score += 18;
    reasons.push('Location differs from the established pattern.');
  }

  if (!campusIp) {
    score += 16;
    reasons.push('Network origin is outside the expected campus range.');
  }

  if (payload.loginHour >= 22 || payload.loginHour <= 5) {
    score += 14;
    reasons.push('Attempt happened during restricted hours.');
  }

  if (payload.requestedZone === 'admin') {
    score += 12;
    reasons.push('Privileged control-plane access requested.');
  }

  return {
    score,
    level: classifyRisk(score),
    deviceTrusted,
    summary: reasons.length > 0 ? reasons.join(' ') : 'Known device, expected network, and normal behavior.',
  };
}

function classifyRisk(score) {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function evaluateZoneAccess({ requestedZone, role, location, deviceTrusted, mfaSatisfied, loginHour }) {
  const reasons = [];
  const zone = zonePolicies.find((entry) => entry.key === requestedZone) ?? zonePolicies[0];

  if (!zone.requiredRole.includes(role)) {
    reasons.push(`Role ${role} is not permitted inside ${zone.zone}.`);
  }

  if (requestedZone === 'admin') {
    if (!location.toLowerCase().includes('bengaluru')) {
      reasons.push('Admin zone is limited to the college network and approved geography.');
    }
    if (loginHour >= 22 || loginHour <= 5) {
      reasons.push('Admin access outside approved hours is blocked.');
    }
    if (!mfaSatisfied) {
      reasons.push('Fresh MFA is required for the admin zone.');
    }
  }

  if ((requestedZone === 'student' || requestedZone === 'teacher') && !deviceTrusted && !mfaSatisfied) {
    reasons.push('Unknown device must complete step-up authentication before entry.');
  }

  return {
    allowed: reasons.length === 0,
    zone,
    reasons: reasons.length > 0 ? reasons : ['Policy requirements satisfied.'],
  };
}

function simulateAttack(attackType, zeroTrustEnabled, seeded = false) {
  const catalog = {
    brute_force: {
      name: 'Brute force login',
      enabled: {
        prevented: true,
        severity: 'high',
        narrative: 'Rate limits, adaptive MFA, and anomaly tracking throttled repeated credential abuse.',
      },
      disabled: {
        prevented: false,
        severity: 'critical',
        narrative: 'Without adaptive controls, repeated guesses reached the login surface unchecked.',
      },
    },
    session_hijack: {
      name: 'Session hijacking',
      enabled: {
        prevented: true,
        severity: 'critical',
        narrative: 'The stolen session was invalidated after IP drift and device mismatch triggered continuous authentication.',
      },
      disabled: {
        prevented: false,
        severity: 'critical',
        narrative: 'A perimeter-only design would keep the session alive after token theft.',
      },
    },
    admin_bypass: {
      name: 'Unauthorized admin access',
      enabled: {
        prevented: true,
        severity: 'critical',
        narrative: 'Micro-segmentation and role-aware policy enforcement blocked lateral movement instantly.',
      },
      disabled: {
        prevented: false,
        severity: 'critical',
        narrative: 'Once inside the network, weak segmentation would expose the admin plane.',
      },
    },
  };

  const entry = catalog[attackType] ?? catalog.brute_force;
  const mode = zeroTrustEnabled ? entry.enabled : entry.disabled;

  return {
    id: `${attackType}-${Date.now()}-${Math.random().toString(16).slice(2, 7)}`,
    type: entry.name,
    prevented: mode.prevented,
    severity: mode.severity,
    detail: mode.narrative,
    actor: zeroTrustEnabled ? 'Attack simulator' : 'Perimeter-only baseline',
    time: seeded ? new Date(Date.now() - 1000 * 60 * 12).toISOString() : new Date().toISOString(),
  };
}

function recordEvent({ kind, severity, user, zone, result, detail }) {
  securityState.events.unshift({
    id: `evt-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
    time: new Date().toISOString(),
    kind,
    severity,
    user,
    zone,
    result,
    detail,
  });
}

function recordAttack(result) {
  securityState.attacks.unshift(result);
  recordEvent({
    kind: result.type,
    severity: result.severity,
    user: result.actor,
    zone: 'simulation',
    result: result.prevented ? 'blocked' : 'breach',
    detail: result.detail,
  });
}

function latestEvent() {
  return securityState.events[0] ?? null;
}
