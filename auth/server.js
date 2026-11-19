const http = require('http');
const crypto = require('crypto');
const { loadEnv } = require('./env');
const store = require('./store');

loadEnv();

const PORT = Number(process.env.PORT || 4001);
const JWT_SECRET = process.env.AUTH_JWT_SECRET || '';
const SUPER_ADMIN_EMAIL = (process.env.SUPER_ADMIN_EMAIL || '').trim().toLowerCase();
const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD || '';
const RETURN_RESET_TOKEN = process.env.RETURN_RESET_TOKEN === 'true';
const TOKEN_HOURS = 12;
const RESET_MINUTES = 30;

if (!JWT_SECRET || !SUPER_ADMIN_EMAIL || !SUPER_ADMIN_PASSWORD) {
  console.error('Set AUTH_JWT_SECRET, SUPER_ADMIN_EMAIL, and SUPER_ADMIN_PASSWORD in auth/.env before starting.');
  process.exit(1);
}

function send(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(body, null, 2));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 1_000_000) {
        const error = new Error('Request body is too large');
        error.statusCode = 413;
        reject(error);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function cleanText(value, max) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPassword(value) {
  return typeof value === 'string' && value.length >= 8 && value.length <= 72 && /[A-Za-z]/.test(value) && /\d/.test(value);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function checkPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const actual = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function present(user) {
  return {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role
  };
}

function signToken(user) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({
    sub: user.id,
    email: user.email,
    role: user.role,
    iat: now,
    exp: now + TOKEN_HOURS * 60 * 60
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

async function parseJson(req) {
  const raw = await readBody(req);
  if (!raw.length) return {};
  try {
    return JSON.parse(raw.toString('utf8'));
  } catch {
    const error = new Error('Request body must be JSON');
    error.statusCode = 400;
    throw error;
  }
}

function registerUser(data, body) {
  const name = cleanText(body.name, 120);
  const email = cleanText(body.email, 160).toLowerCase();
  const password = body.password;
  if (!name) return { statusCode: 400, body: { success: false, message: 'name is required' } };
  if (!validEmail(email)) return { statusCode: 400, body: { success: false, message: 'email must be a valid email' } };
  if (!validPassword(password)) {
    return { statusCode: 400, body: { success: false, message: 'password must be 8 to 72 characters and include a letter and a number' } };
  }
  if (data.users.some((user) => user.email === email)) {
    return { statusCode: 409, body: { success: false, message: 'An account with this email already exists' } };
  }
  const now = new Date().toISOString();
  const user = {
    id: `usr_${crypto.randomBytes(8).toString('hex')}`,
    name,
    email,
    passwordHash: hashPassword(password),
    role: 'customer',
    createdAt: now,
    updatedAt: now
  };
  data.users.push(user);
  return {
    statusCode: 201,
    body: { success: true, message: 'Account created', user: present(user) }
  };
}

function loginUser(data, body) {
  const email = cleanText(body.email, 160).toLowerCase();
  const password = typeof body.password === 'string' ? body.password : '';
  const user = data.users.find((item) => item.email === email);
  const stored = user ? user.passwordHash : hashPassword('dummy-password');
  const matches = checkPassword(password, stored);
  if (!user || !matches || !password) {
    return { statusCode: 401, body: { success: false, message: 'Email or password is incorrect' } };
  }
  return {
    statusCode: 200,
    body: {
      success: true,
      message: 'Login successful',
      token: signToken(user),
      user: present(user)
    }
  };
}

function startReset(data, email) {
  const user = data.users.find((item) => item.email === email);
  const message = 'If this email is registered, the reset token is ready.';
  if (!user) return { statusCode: 200, body: { success: true, message } };
  const now = Date.now();
  data.resets.forEach((item) => {
    if (item.userId === user.id && !item.usedAt) item.usedAt = new Date(now).toISOString();
  });
  const token = crypto.randomBytes(24).toString('hex');
  data.resets.push({
    id: `rst_${crypto.randomBytes(8).toString('hex')}`,
    userId: user.id,
    tokenHash: hashToken(token),
    expiresAt: new Date(now + RESET_MINUTES * 60 * 1000).toISOString(),
    usedAt: null
  });
  const body = { success: true, message };
  if (RETURN_RESET_TOKEN) body.resetToken = token;
  return { statusCode: 200, body };
}

function completeReset(data, token, newPassword) {
  if (!validPassword(newPassword)) {
    return { statusCode: 400, body: { success: false, message: 'password must be 8 to 72 characters and include a letter and a number' } };
  }
  const reset = data.resets.find((item) => item.tokenHash === hashToken(token) && !item.usedAt);
  if (!reset || new Date(reset.expiresAt).getTime() < Date.now()) {
    return { statusCode: 400, body: { success: false, message: 'Reset token is invalid or expired' } };
  }
  const user = data.users.find((item) => item.id === reset.userId);
  if (!user) return { statusCode: 400, body: { success: false, message: 'Reset token is invalid or expired' } };
  if (checkPassword(newPassword, user.passwordHash)) {
    return { statusCode: 400, body: { success: false, message: 'New password must be different from the current password' } };
  }
  const now = new Date().toISOString();
  user.passwordHash = hashPassword(newPassword);
  user.updatedAt = now;
  reset.usedAt = now;
  return { statusCode: 200, body: { success: true, message: 'Password updated' } };
}

function seedAdmin(data) {
  if (data.users.some((user) => user.email === SUPER_ADMIN_EMAIL)) return;
  const now = new Date().toISOString();
  data.users.push({
    id: `usr_${crypto.randomBytes(8).toString('hex')}`,
    name: 'SurfSync Super Admin',
    email: SUPER_ADMIN_EMAIL,
    passwordHash: hashPassword(SUPER_ADMIN_PASSWORD),
    role: 'super_admin',
    createdAt: now,
    updatedAt: now
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const method = req.method.toUpperCase();

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end();
    return;
  }

  try {
    if (method === 'GET' && path === '/') {
      send(res, 200, {
        service: 'SurfSync Mail Auth',
        status: 'OPERATIONAL',
        endpoints: {
          'POST /auth/register': 'Create a customer account.',
          'POST /auth/login': 'Login for customer, super admin, company admin, or employee.',
          'POST /auth/reset-password': 'Send email to start a reset, or send resetToken and password to set a new password.'
        }
      });
      return;
    }

    if (method === 'POST' && path === '/auth/register') {
      const body = await parseJson(req);
      const result = await store.update((data) => registerUser(data, body));
      send(res, result.statusCode, result.body);
      return;
    }

    if (method === 'POST' && path === '/auth/login') {
      const body = await parseJson(req);
      const result = loginUser(store.read(), body);
      send(res, result.statusCode, result.body);
      return;
    }

    if (method === 'POST' && path === '/auth/reset-password') {
      const body = await parseJson(req);
      const token = cleanText(body.resetToken, 200);
      const password = body.password;
      if (token || password) {
        if (!token || !password) {
          send(res, 400, { success: false, message: 'resetToken and password are both required to set a new password' });
          return;
        }
        const result = await store.update((data) => completeReset(data, token, password));
        send(res, result.statusCode, result.body);
        return;
      }
      const email = cleanText(body.email, 160).toLowerCase();
      if (!validEmail(email)) {
        send(res, 400, { success: false, message: 'email must be a valid email' });
        return;
      }
      const result = await store.update((data) => startReset(data, email));
      send(res, result.statusCode, result.body);
      return;
    }

    send(res, 404, { success: false, message: 'Not found' });
  } catch (error) {
    const statusCode = error.statusCode || 500;
    send(res, statusCode, { success: false, message: statusCode === 500 ? 'Auth service error' : error.message });
  }
});

store.update(seedAdmin).then(() => {
  server.listen(PORT, () => {
    console.log(`SurfSync auth listening on http://localhost:${PORT}`);
  });
});
