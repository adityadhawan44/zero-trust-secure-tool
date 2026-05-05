import bcrypt from 'bcryptjs';
import cors from 'cors';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const port = Number(process.env.PORT || 8788);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distPath = path.resolve(__dirname, '../dist');
const jwtSecret = process.env.JWT_SECRET || 'zero-trust-demo-secret';
const accessTokenTtlSeconds = 15 * 60;
const refreshTokenTtlSeconds = 7 * 24 * 60 * 60;
const demoOtpCode = '482911';

const zonePolicies = [
  {
    zone: 'Public Zone',
    key: 'public',
    description: 'Landing pages, documentation, and policy explainer content.',
    requiredRole: ['guest', 'student', 'teacher', 'admin'],
    rule: 'Observe traffic, log telemetry, and allow low-friction discovery.',
  },
  {
    zone: 'Student Workspace',
    key: 'student',
    description: 'Assignments, attendance, internal documents, and student tooling.',
    requiredRole: ['student', 'teacher', 'admin'],
    rule: 'Unknown devices trigger MFA before access is granted.',
  },
  {
    zone: 'Faculty Tools',
    key: 'teacher',
    description: 'Grading, moderation, and academic workflow systems.',
    requiredRole: ['teacher', 'admin'],
    rule: 'Role, device trust, and medium-risk thresholds are enforced.',
  },
  {
    zone: 'Admin Control Plane',
    key: 'admin',
    description: 'Identity configuration, audit logs, and sensitive control actions.',
    requiredRole: ['admin'],
    rule: 'Campus network, approved hours, valid JWT, and fresh MFA are mandatory.',
  },
];

const seedUsers = [
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

const baselineUsers = await Promise.all(
  seedUsers.map(async (user) => ({
    ...user,
    passwordHash: await bcrypt.hash(user.password, 10),
  })),
);

const securityState = createInitialState();

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }),
);
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(',') ?? true,
  }),
);
app.use(express.json({ limit: '1mb' }));
app.use('/api', rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false }));
app.use(
  '/api/zero-trust/login',
  rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Slow down and try again shortly.' },
  }),
);

app.get('/api/health', (_request, response) => {
  response.json({
    ok: true,
    app: 'ZeroTrustX',
    date: new Date().toISOString(),
    mode: 'simulation-plus-security-primitives',
  });
});

app.get('/api/zero-trust/bootstrap', (_request, response) => {
  response.json(buildDashboardPayload());
});

app.post('/api/zero-trust/register', async (request, response) => {
  const payload = normalizeRegisterPayload(request.body ?? {});

  if (!payload.name || !payload.email || !payload.password) {
    response.status(400).json({ error: 'Name, email, and password are required.' });
    return;
  }

  if (payload.password.length < 8) {
    response.status(400).json({ error: 'Password must be at least 8 characters.' });
    return;
  }

  if (baselineUsers.some((user) => user.email === payload.email)) {
    response.status(409).json({ error: 'A user with that email already exists.' });
    return;
  }

  const newUser = {
    id: `user-${Date.now()}`,
    name: payload.name,
    email: payload.email,
    password: undefined,
    role: payload.role,
    department: payload.department || 'Demo Cohort',
    knownDevices: [],
    typicalLocations: payload.location ? [payload.location] : ['Bengaluru, IN'],
    homeIpPrefix: payload.ipAddress ? payload.ipAddress.split('.').slice(0, 2).join('.') + '.' : '10.20.',
    passwordHash: await bcrypt.hash(payload.password, 10),
  };

  baselineUsers.push(newUser);
  recordEvent({
    kind: 'New user registered',
    severity: 'low',
    user: newUser.name,
    zone: 'identity',
    result: 'allowed',
    detail: 'A new demo identity was added to the ZeroTrustX environment.',
  });

  response.status(201).json({
    item: sanitizeUser(newUser),
    dashboard: buildDashboardPayload(),
  });
});

app.post('/api/zero-trust/login', async (request, response) => {
  const payload = normalizeLoginPayload(request.body ?? {});
  const user = baselineUsers.find((entry) => entry.email === payload.email);

  if (!user || !(await bcrypt.compare(payload.password, user.passwordHash))) {
    recordAttack({
      type: 'Brute force attempt',
      actor: payload.email || 'unknown',
      prevented: payload.zeroTrustEnabled,
      severity: 'high',
      detail: payload.zeroTrustEnabled
        ? 'Rate limiting, credential checks, and telemetry logging intercepted invalid credentials.'
        : 'Invalid credentials reached the perimeter-only login surface.',
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
  const requiresMfa = risk.score >= 30 && payload.zeroTrustEnabled;
  const shouldBlock = risk.score >= 70 && payload.zeroTrustEnabled;
  const sessionId = `session-${Date.now()}`;
  const policyDecision = evaluateZoneAccess({
    requestedZone: payload.requestedZone,
    role: user.role,
    location: payload.location,
    deviceTrusted: risk.deviceTrusted,
    mfaSatisfied: !requiresMfa,
    loginHour: payload.loginHour,
    riskScore: risk.score,
  });

  const session = {
    id: sessionId,
    userId: user.id,
    userName: user.name,
    role: user.role,
    location: payload.location,
    ipAddress: payload.ipAddress,
    deviceId: payload.deviceId,
    userAgent: payload.userAgent,
    deviceTrusted: risk.deviceTrusted,
    riskScore: risk.score,
    riskLevel: risk.level,
    behaviorScore: payload.behaviorScore,
    mfaRequired: requiresMfa,
    mfaCompleted: false,
    requestedZone: payload.requestedZone,
    zoneDecision: shouldBlock ? 'denied' : policyDecision.allowed ? 'pending-mfa' : 'denied',
    policyReasons: shouldBlock ? ['Risk score exceeded the maximum threshold for automatic block.'] : policyDecision.reasons,
    createdAt: new Date().toISOString(),
    refreshTokenId: null,
    revoked: false,
  };

  upsertDeviceRecord(user, payload, risk);
  securityState.sessions.unshift(session);

  if (shouldBlock) {
    recordEvent({
      kind: 'High-risk login blocked',
      severity: 'high',
      user: user.name,
      zone: payload.requestedZone,
      result: 'blocked',
      detail: risk.summary,
    });
    response.status(403).json({
      status: 'denied',
      message: 'Risk score too high. Access blocked.',
      session,
      risk,
      dashboard: buildDashboardPayload(),
    });
    return;
  }

  if (requiresMfa) {
    recordEvent({
      kind: 'Step-up MFA triggered',
      severity: 'medium',
      user: user.name,
      zone: payload.requestedZone,
      result: 'challenge',
      detail: risk.summary,
    });
    response.json({
      status: 'mfa_required',
      session,
      risk,
      policyDecision,
      mfaCode: demoOtpCode,
      dashboard: buildDashboardPayload(),
    });
    return;
  }

  const tokens = issueTokens(user, sessionId);
  session.mfaCompleted = true;
  session.zoneDecision = policyDecision.allowed ? 'allowed' : 'denied';
  session.refreshTokenId = tokens.refreshTokenId;

  recordEvent({
    kind: 'Session created',
    severity: 'low',
    user: user.name,
    zone: payload.requestedZone,
    result: policyDecision.allowed ? 'allowed' : 'blocked',
    detail: risk.summary,
  });

  response.json({
    status: policyDecision.allowed ? 'allowed' : 'denied',
    session,
    risk,
    policyDecision,
    tokens: tokens.publicTokens,
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

  if (session.revoked) {
    response.status(403).json({ error: 'Session has already been revoked.' });
    return;
  }

  if (code !== demoOtpCode) {
    recordEvent({
      kind: 'MFA verification failed',
      severity: 'high',
      user: session.userName,
      zone: session.requestedZone,
      result: 'blocked',
      detail: 'Invalid OTP submitted for elevated-risk session.',
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
    riskScore: session.riskScore,
  });

  const user = baselineUsers.find((entry) => entry.id === session.userId);
  if (!user) {
    response.status(404).json({ error: 'User not found.' });
    return;
  }

  const tokens = issueTokens(user, session.id);
  session.zoneDecision = finalDecision.allowed ? 'allowed' : 'denied';
  session.refreshTokenId = tokens.refreshTokenId;

  recordEvent({
    kind: finalDecision.allowed ? 'MFA verified' : 'Post-MFA policy block',
    severity: finalDecision.allowed ? 'low' : 'high',
    user: session.userName,
    zone: session.requestedZone,
    result: finalDecision.allowed ? 'allowed' : 'blocked',
    detail: finalDecision.allowed
      ? 'User satisfied step-up authentication and received signed tokens.'
      : finalDecision.reasons.join(' '),
  });

  response.json({
    status: finalDecision.allowed ? 'allowed' : 'denied',
    session,
    policyDecision: finalDecision,
    tokens: tokens.publicTokens,
    dashboard: buildDashboardPayload(),
  });
});

app.post('/api/zero-trust/token/refresh', (request, response) => {
  const refreshToken = String(request.body?.refreshToken || '').trim();
  const tokenRecord = securityState.refreshTokens.find((entry) => entry.token === refreshToken && !entry.revoked);

  if (!tokenRecord) {
    response.status(401).json({ error: 'Refresh token is invalid or revoked.' });
    return;
  }

  try {
    const payload = jwt.verify(refreshToken, jwtSecret);
    const user = baselineUsers.find((entry) => entry.id === payload.sub);
    if (!user) {
      response.status(404).json({ error: 'User not found.' });
      return;
    }

    tokenRecord.revoked = true;
    const tokens = issueTokens(user, tokenRecord.sessionId);
    const session = securityState.sessions.find((entry) => entry.id === tokenRecord.sessionId);
    if (session) {
      session.refreshTokenId = tokens.refreshTokenId;
    }

    recordEvent({
      kind: 'Access token refreshed',
      severity: 'low',
      user: user.name,
      zone: 'identity',
      result: 'allowed',
      detail: 'A refresh token rotated and issued a fresh short-lived access token.',
    });

    response.json({
      tokens: tokens.publicTokens,
      dashboard: buildDashboardPayload(),
    });
  } catch {
    response.status(401).json({ error: 'Refresh token expired.' });
  }
});

app.post('/api/zero-trust/logout', authenticateToken, (request, response) => {
  const auth = request.auth;
  const session = securityState.sessions.find((entry) => entry.id === auth.sessionId);
  if (session) {
    session.revoked = true;
    session.zoneDecision = 'revoked';
  }
  securityState.refreshTokens.forEach((token) => {
    if (token.sessionId === auth.sessionId) {
      token.revoked = true;
    }
  });

  recordEvent({
    kind: 'Session logged out',
    severity: 'low',
    user: auth.name,
    zone: auth.role,
    result: 'allowed',
    detail: 'Access and refresh tokens were invalidated.',
  });

  response.json({
    ok: true,
    dashboard: buildDashboardPayload(),
  });
});

app.get('/api/zero-trust/me', authenticateToken, (request, response) => {
  response.json({
    auth: request.auth,
    dashboard: buildDashboardPayload(),
  });
});

app.get('/api/zero-trust/protected/:zone', authenticateToken, (request, response) => {
  const requestedZone = String(request.params.zone || 'public');
  const session = securityState.sessions.find((entry) => entry.id === request.auth.sessionId);

  if (!session || session.revoked) {
    response.status(401).json({ error: 'Session is not active.' });
    return;
  }

  const decision = evaluateZoneAccess({
    requestedZone,
    role: request.auth.role,
    location: request.auth.location,
    deviceTrusted: session.deviceTrusted,
    mfaSatisfied: session.mfaCompleted,
    loginHour: new Date().getHours(),
    riskScore: session.riskScore,
  });

  if (!decision.allowed || session.riskScore >= 70) {
    recordEvent({
      kind: 'Protected API blocked',
      severity: 'high',
      user: request.auth.name,
      zone: requestedZone,
      result: 'blocked',
      detail: session.riskScore >= 70 ? 'Risk threshold exceeded during protected API enforcement.' : decision.reasons.join(' '),
    });
    response.status(403).json({
      status: 'denied',
      reasons: session.riskScore >= 70 ? ['Risk score above permitted threshold.'] : decision.reasons,
      dashboard: buildDashboardPayload(),
    });
    return;
  }

  recordEvent({
    kind: 'Protected API allowed',
    severity: 'low',
    user: request.auth.name,
    zone: requestedZone,
    result: 'allowed',
    detail: 'JWT validation, role checks, and policy engine all passed.',
  });

  response.json({
    status: 'allowed',
    resource: buildZoneResource(requestedZone, request.auth),
    decision,
    dashboard: buildDashboardPayload(),
  });
});

app.post('/api/zero-trust/session/recheck', authenticateToken, (request, response) => {
  const sessionId = String(request.body?.sessionId || '').trim();
  const scenario = String(request.body?.scenario || 'stable').trim();
  const session = securityState.sessions.find((entry) => entry.id === sessionId);

  if (!session || session.revoked) {
    response.status(404).json({ error: 'Session not found.' });
    return;
  }

  let outcome;

  if (scenario === 'ip_shift') {
    session.riskScore = Math.min(98, session.riskScore + 26);
    session.riskLevel = classifyRisk(session.riskScore);
    session.zoneDecision = session.riskScore >= 70 ? 'revoked' : 'step-up';
    outcome = {
      status: session.riskScore >= 70 ? 'revoked' : 'step_up_required',
      title: 'Suspicious network shift detected',
      message:
        session.riskScore >= 70
          ? 'Continuous authentication revoked the session after a risky IP shift.'
          : 'Continuous authentication paused privileged access and requires step-up verification.',
    };
  } else if (scenario === 'behavior_anomaly') {
    session.riskScore = Math.min(95, session.riskScore + 18);
    session.riskLevel = classifyRisk(session.riskScore);
    session.zoneDecision = 'limited';
    outcome = {
      status: 'limited_access',
      title: 'Behavioral anomaly flagged',
      message: 'Mouse and typing deviation increased risk and narrowed access scope.',
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

  if (session.zoneDecision === 'revoked') {
    session.revoked = true;
    securityState.refreshTokens.forEach((token) => {
      if (token.sessionId === session.id) token.revoked = true;
    });
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
    riskScore: Number(request.body?.riskScore ?? 0),
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
  console.log(`ZeroTrustX server running on http://localhost:${port}`);
});

function createInitialState() {
  return {
    sessions: [],
    refreshTokens: [],
    deviceRecords: seedUsers.flatMap((user) =>
      user.knownDevices.map((deviceId) => ({
        userId: user.id,
        deviceId,
        trusted: true,
        lastUsed: new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString(),
        ipAddress: `${user.homeIpPrefix}44.18`,
        location: 'Bengaluru, IN',
        userAgent: 'Trusted Browser',
      })),
    ),
    events: [
      {
        id: 'evt-seed-1',
        time: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
        kind: 'Trusted admin sign-in',
        severity: 'low',
        user: 'Rohan Menon',
        zone: 'admin',
        result: 'allowed',
        detail: 'Known device, campus IP, JWT validation, and fresh MFA allowed access.',
      },
      {
        id: 'evt-seed-2',
        time: new Date(Date.now() - 1000 * 60 * 9).toISOString(),
        kind: 'Impossible travel blocked',
        severity: 'high',
        user: 'Aarav Sharma',
        zone: 'student',
        result: 'blocked',
        detail: 'A new geography raised the risk score past the safe threshold.',
      },
      {
        id: 'evt-seed-3',
        time: new Date(Date.now() - 1000 * 60 * 4).toISOString(),
        kind: 'Behavior anomaly detected',
        severity: 'medium',
        user: 'Prof. Kavya Iyer',
        zone: 'teacher',
        result: 'limited_access',
        detail: 'Behavior drift reduced privileges until re-verification.',
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
    trustedDevices: securityState.deviceRecords.filter((entry) => entry.trusted).length,
  };

  return {
    users: baselineUsers.map(sanitizeUser),
    zonePolicies,
    metrics: totals,
    activeSessions: securityState.sessions.slice(0, 6),
    recentEvents: securityState.events.slice(0, 10),
    attackResults: securityState.attacks.slice(0, 6),
    deviceRecords: securityState.deviceRecords.slice(0, 8),
    securityFeatures: [
      'bcryptjs password hashing',
      'JWT access tokens',
      'Refresh token rotation',
      'Helmet response hardening',
      'Rate-limited auth endpoints',
      'Policy-enforced protected APIs',
    ],
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
      password: seedUsers.find((entry) => entry.id === user.id)?.password ?? 'demo-password',
      role: user.role,
    })),
  };
}

function normalizeRegisterPayload(payload) {
  return {
    name: String(payload.name || '').trim(),
    email: String(payload.email || '').trim().toLowerCase(),
    password: String(payload.password || '').trim(),
    role: ['student', 'teacher', 'admin'].includes(String(payload.role || 'student')) ? String(payload.role) : 'student',
    department: String(payload.department || '').trim(),
    location: String(payload.location || '').trim(),
    ipAddress: String(payload.ipAddress || '').trim(),
  };
}

function normalizeLoginPayload(payload) {
  return {
    email: String(payload.email || '').trim().toLowerCase(),
    password: String(payload.password || '').trim(),
    deviceId: String(payload.deviceId || 'unknown-device').trim(),
    userAgent: String(payload.userAgent || 'Unknown Browser').trim(),
    location: String(payload.location || 'Remote').trim(),
    ipAddress: String(payload.ipAddress || '203.0.113.42').trim(),
    loginHour: Number(payload.loginHour ?? 11),
    requestedZone: String(payload.requestedZone || 'student').trim(),
    behaviorScore: Math.max(0, Number(payload.behaviorScore ?? 10)),
    zeroTrustEnabled: Boolean(payload.zeroTrustEnabled),
  };
}

function sanitizeUser(user) {
  const { passwordHash, password, ...safeUser } = user;
  return safeUser;
}

function scoreRisk(user, payload) {
  let score = 0;
  const reasons = [];
  const deviceTrusted = user.knownDevices.includes(payload.deviceId);
  const familiarLocation = user.typicalLocations.includes(payload.location);
  const campusIp = payload.ipAddress.startsWith(user.homeIpPrefix);

  if (!deviceTrusted) {
    score += 30;
    reasons.push('New device fingerprint detected.');
  }

  if (!campusIp) {
    score += 20;
    reasons.push('Network origin is outside the expected campus range.');
  }

  if (!familiarLocation) {
    score += 40;
    reasons.push('Location differs from the established pattern.');
  }

  if (payload.loginHour >= 22 || payload.loginHour <= 5) {
    score += 10;
    reasons.push('Attempt happened during restricted hours.');
  }

  if (payload.behaviorScore >= 60) {
    score += 15;
    reasons.push('Behavioral telemetry deviated from baseline.');
  }

  if (payload.requestedZone === 'admin') {
    score += 8;
    reasons.push('Privileged control-plane access requested.');
  }

  if (score === 0) {
    reasons.push('Known device, expected location, and normal behavior.');
  }

  return {
    score,
    level: classifyRisk(score),
    deviceTrusted,
    summary: reasons.join(' '),
  };
}

function classifyRisk(score) {
  if (score >= 70) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

function evaluateZoneAccess({ requestedZone, role, location, deviceTrusted, mfaSatisfied, loginHour, riskScore }) {
  const reasons = [];
  const zone = zonePolicies.find((entry) => entry.key === requestedZone) ?? zonePolicies[0];

  if (!zone.requiredRole.includes(role)) {
    reasons.push(`Role ${role} is not permitted inside ${zone.zone}.`);
  }

  if (riskScore >= 70) {
    reasons.push('Risk score exceeded the maximum policy threshold.');
  } else if (riskScore >= 30 && !mfaSatisfied) {
    reasons.push('Risk score requires MFA before access may continue.');
  }

  if (requestedZone === 'admin') {
    if (!location.toLowerCase().includes('bengaluru')) {
      reasons.push('Admin zone is limited to the approved geography and network.');
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

function issueTokens(user, sessionId) {
  const accessPayload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    name: user.name,
    sessionId,
  };

  const refreshTokenId = `rt-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`;
  const accessToken = jwt.sign(accessPayload, jwtSecret, { expiresIn: accessTokenTtlSeconds });
  const refreshToken = jwt.sign({ sub: user.id, sessionId, tokenId: refreshTokenId }, jwtSecret, {
    expiresIn: refreshTokenTtlSeconds,
  });

  securityState.refreshTokens.unshift({
    id: refreshTokenId,
    token: refreshToken,
    userId: user.id,
    sessionId,
    revoked: false,
    createdAt: new Date().toISOString(),
  });

  return {
    refreshTokenId,
    publicTokens: {
      accessToken,
      refreshToken,
      accessTokenExpiresIn: accessTokenTtlSeconds,
      refreshTokenExpiresIn: refreshTokenTtlSeconds,
    },
  };
}

function authenticateToken(request, response, next) {
  const authHeader = request.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : '';

  if (!token) {
    response.status(401).json({ error: 'Missing bearer token.' });
    return;
  }

  try {
    const payload = jwt.verify(token, jwtSecret);
    const session = securityState.sessions.find((entry) => entry.id === payload.sessionId);
    if (!session || session.revoked) {
      response.status(401).json({ error: 'Session has been revoked or expired.' });
      return;
    }

    request.auth = {
      userId: payload.sub,
      email: payload.email,
      role: payload.role,
      name: payload.name,
      sessionId: payload.sessionId,
      location: session.location,
    };
    next();
  } catch {
    response.status(401).json({ error: 'Token is invalid or expired.' });
  }
}

function upsertDeviceRecord(user, payload, risk) {
  const existingRecord = securityState.deviceRecords.find(
    (entry) => entry.userId === user.id && entry.deviceId === payload.deviceId,
  );

  if (existingRecord) {
    existingRecord.lastUsed = new Date().toISOString();
    existingRecord.ipAddress = payload.ipAddress;
    existingRecord.location = payload.location;
    existingRecord.userAgent = payload.userAgent;
    existingRecord.trusted = risk.score < 70;
    return;
  }

  securityState.deviceRecords.unshift({
    userId: user.id,
    deviceId: payload.deviceId,
    trusted: risk.score < 30,
    lastUsed: new Date().toISOString(),
    ipAddress: payload.ipAddress,
    location: payload.location,
    userAgent: payload.userAgent,
  });
}

function buildZoneResource(zone, auth) {
  const resources = {
    public: ['Policy handbook', 'Threat primer', 'Zero Trust architecture map'],
    student: ['Assignment vault', 'Attendance records', 'Learning workspace'],
    teacher: ['Grading console', 'Course moderation tools', 'Academic reports'],
    admin: ['Identity control plane', 'Token revocation center', 'Security analytics console'],
  };

  return {
    zone,
    owner: auth.name,
    items: resources[zone] ?? resources.public,
  };
}

function simulateAttack(attackType, zeroTrustEnabled, seeded = false) {
  const catalog = {
    brute_force: {
      name: 'Brute force login',
      enabled: {
        prevented: true,
        severity: 'high',
        narrative: 'Rate limiting, adaptive MFA, and failed-login telemetry throttled repeated credential abuse.',
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
        narrative: 'Token reuse was neutralized after IP drift and continuous authentication invalidated the session.',
      },
      disabled: {
        prevented: false,
        severity: 'critical',
        narrative: 'A perimeter-only design would keep the stolen session alive after token theft.',
      },
    },
    admin_bypass: {
      name: 'Unauthorized admin access',
      enabled: {
        prevented: true,
        severity: 'critical',
        narrative: 'Micro-segmentation, JWT validation, and role-aware policy enforcement blocked lateral movement instantly.',
      },
      disabled: {
        prevented: false,
        severity: 'critical',
        narrative: 'Weak segmentation would expose the admin plane after a direct URL attempt.',
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
