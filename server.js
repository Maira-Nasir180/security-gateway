require('dotenv').config();
const express = require('express'), helmet = require('helmet'), cors = require('cors');
const cookieParser = require('cookie-parser'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit'), crypto = require('crypto'), xss = require('xss');

const { ACCESS_SECRET = 'dev-access-secret', REFRESH_SECRET = 'dev-refresh-secret', NODE_ENV } = process.env;
const PROD = NODE_ENV === 'production';
const BASE = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
const ORIGINS = (process.env.ALLOWED_ORIGINS || BASE).split(',');
const ROLES = ['SuperAdmin', 'Manager', 'Employee'];

// ---- In-memory store (swap for Postgres/Mongo in real production) ----
const users = new Map(), refreshStore = new Map(); // jti -> {userId, family, used}
const addUser = (u) => { const user = { id: crypto.randomUUID(), createdAt: new Date().toISOString(), ...u }; users.set(user.id, user); return user; };
const byEmail = (e) => [...users.values()].find((u) => u.email === e);
[['admin@corp.com', 'Admin@12345', 'SuperAdmin', 'Sara Admin'], ['manager@corp.com', 'Manager@12345', 'Manager', 'Mark Manager'],
 ['employee@corp.com', 'Employee@12345', 'Employee', 'Eva Employee']].forEach(([email, pw, role, name]) =>
  addUser({ email, name, role, tenant: 'acme-corp', passwordHash: bcrypt.hashSync(pw, 12), provider: 'local' }));

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", 'https://avatars.githubusercontent.com', 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"] } } }));
app.use(cors({ origin: (o, cb) => (!o || ORIGINS.includes(o) ? cb(null, true) : cb(new Error('CORS blocked'))), credentials: true, methods: ['GET', 'POST', 'DELETE'] }));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// ---- Sanitisation: NoSQL operators ($, .) + XSS on every string ----
const clean = (v) => {
  if (typeof v === 'string') return xss(v).replace(/[<>]/g, '').trim();
  if (Array.isArray(v)) return v.map(clean);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).filter(([k]) => !/^\$|\./.test(k)).map(([k, x]) => [k, clean(x)]));
  return v;
};
app.use((req, _res, next) => { req.body = clean(req.body); for (const k of Object.keys(req.query)) req.query[k] = clean(req.query[k]); next(); });
app.use('/api', rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

// ---- Tokens ----
const signAccess = (u) => jwt.sign({ sub: u.id, role: u.role, tenant: u.tenant }, ACCESS_SECRET, { expiresIn: '15m' });
const cookieOpts = { httpOnly: true, secure: PROD, sameSite: 'strict', path: '/api/v1/auth', maxAge: 7 * 864e5 };
function issueRefresh(res, user, family = crypto.randomUUID()) {
  const jti = crypto.randomUUID();
  refreshStore.set(jti, { userId: user.id, family, used: false });
  res.cookie('refreshToken', jwt.sign({ sub: user.id, jti, family }, REFRESH_SECRET, { expiresIn: '7d' }), cookieOpts);
}
const revokeFamily = (family) => refreshStore.forEach((v, k) => v.family === family && refreshStore.delete(k));
const pub = ({ passwordHash, ...u }) => u;

// ---- Middleware ----
const authenticate = (req, res, next) => {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing bearer token' });
  try { const p = jwt.verify(h.slice(7), ACCESS_SECRET); req.user = users.get(p.sub); if (!req.user) throw 0; next(); }
  catch (e) { res.status(401).json({ error: 'Invalid or expired token', code: e.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID' }); }
};
const checkRole = (roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: `Forbidden: requires ${roles.join(' or ')}`, yourRole: req.user.role });

// ---- Auth ----
const auth = express.Router();
const loginLimiter = rateLimit({ windowMs: 15 * 60_000, max: 5, skipSuccessfulRequests: true, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => 'acct:' + String(req.body?.email || 'unknown').toLowerCase(),
  handler: (_q, res) => res.status(429).json({ error: 'Too many failed attempts. Account locked for 15 minutes.' }) });

auth.post('/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (typeof email !== 'string' || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Valid email required' });
  if (typeof password !== 'string' || !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,72}$/.test(password)) return res.status(400).json({ error: 'Password: 8+ chars with upper, lower and a number' });
  if (byEmail(email.toLowerCase())) return res.status(409).json({ error: 'Email already registered' });
  const u = addUser({ email: email.toLowerCase(), name: name || email.split('@')[0], role: 'Employee', tenant: 'acme-corp', passwordHash: await bcrypt.hash(password, 12), provider: 'local' });
  res.status(201).json({ user: pub(u) });
});
auth.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body, u = typeof email === 'string' && byEmail(email.toLowerCase());
  const ok = u && u.passwordHash && typeof password === 'string' && await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
  issueRefresh(res, u); res.json({ accessToken: signAccess(u), user: pub(u) });
});
auth.post('/refresh', (req, res) => {
  const t = req.cookies.refreshToken;
  if (!t) return res.status(401).json({ error: 'No refresh token' });
  try {
    const p = jwt.verify(t, REFRESH_SECRET), rec = refreshStore.get(p.jti);
    if (!rec || rec.used) { revokeFamily(p.family); res.clearCookie('refreshToken', cookieOpts); return res.status(401).json({ error: 'Refresh token reuse detected. All sessions revoked.' }); }
    rec.used = true; const u = users.get(p.sub); issueRefresh(res, u, p.family);
    res.json({ accessToken: signAccess(u), user: pub(u), rotated: true });
  } catch { res.status(401).json({ error: 'Invalid refresh token' }); }
});
auth.post('/logout', (req, res) => {
  try { revokeFamily(jwt.verify(req.cookies.refreshToken, REFRESH_SECRET).family); } catch {}
  res.clearCookie('refreshToken', cookieOpts); res.json({ message: 'Logged out, refresh token revoked' });
});

// GitHub OAuth 2.0
auth.get('/github', (_req, res) => {
  if (!process.env.GITHUB_CLIENT_ID) return res.redirect('/?oauth=not_configured');
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('oauth_state', state, { httpOnly: true, secure: PROD, sameSite: 'lax', maxAge: 600_000 });
  res.redirect(`https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&scope=read:user%20user:email&state=${state}&redirect_uri=${encodeURIComponent(BASE + '/api/v1/auth/github/callback')}`);
});
auth.get('/github/callback', async (req, res) => {
  try {
    if (!req.query.state || req.query.state !== req.cookies.oauth_state) throw new Error('state');
    const tok = await (await fetch('https://github.com/login/oauth/access_token', { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code: req.query.code }) })).json();
    const H = { Authorization: `Bearer ${tok.access_token}`, 'User-Agent': 'gateway' };
    const gh = await (await fetch('https://api.github.com/user', { headers: H })).json();
    const emails = await (await fetch('https://api.github.com/user/emails', { headers: H })).json();
    const email = (emails.find?.((e) => e.primary && e.verified)?.email || `${gh.login}@users.noreply.github.com`).toLowerCase();
    let u = byEmail(email);
    if (u) Object.assign(u, { name: gh.name || gh.login, avatar: gh.avatar_url }); // sync profile
    else u = addUser({ email, name: gh.name || gh.login, avatar: gh.avatar_url, role: 'Employee', tenant: 'acme-corp', provider: 'github' });
    res.clearCookie('oauth_state'); issueRefresh(res, u); res.redirect('/?oauth=success');
  } catch { res.redirect('/?oauth=failed'); }
});
app.use('/api/v1/auth', auth);

// ---- Protected API (RBAC matrix) ----
const api = express.Router(); api.use(authenticate);
api.get('/employee/profile', checkRole(ROLES), (req, res) => res.json({ profile: pub(req.user) }));
api.post('/payroll/approve', checkRole(['Manager', 'SuperAdmin']), (req, res) =>
  res.json({ message: `Payroll ${req.body.payrollId || 'PR-1001'} approved by ${req.user.name}`, approvedAt: new Date().toISOString() }));
api.get('/users', checkRole(['SuperAdmin']), (_req, res) => res.json({ users: [...users.values()].map(pub) }));
api.delete('/users/:id', checkRole(['SuperAdmin']), (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'You cannot delete yourself' });
  if (!users.delete(req.params.id)) return res.status(404).json({ error: 'User not found' });
  refreshStore.forEach((v, k) => v.userId === req.params.id && refreshStore.delete(k)); res.json({ message: 'User deleted' });
});
app.use('/api/v1', api);

app.use(express.static(__dirname + '/public'));
app.use((err, _req, res, _next) => res.status(err.message === 'CORS blocked' ? 403 : 500).json({ error: err.message === 'CORS blocked' ? 'CORS blocked' : 'Server error' }));
app.listen(process.env.PORT || 3000, () => console.log('Gateway running'));
