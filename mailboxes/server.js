const http = require('http');
const crypto = require('crypto');
const { loadEnv } = require('./env');
const { readUsers, readCompanies, updateShared } = require('./files');

loadEnv();

const PORT = Number(process.env.PORT || 4006);
const JWT_SECRET = process.env.AUTH_JWT_SECRET || '';

if (!JWT_SECRET) {
  console.error('Set AUTH_JWT_SECRET in mailboxes/.env before starting. It must match the auth service.');
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

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function verifyToken(headerValue) {
  const value = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (!value || !value.startsWith('Bearer ')) return null;
  const token = value.slice('Bearer '.length).trim();
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
  if (!safeEqual(expected, signature)) return null;
  try {
    const body = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!body || !body.exp || body.exp < Math.floor(Date.now() / 1000)) return null;
    return body;
  } catch {
    return null;
  }
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function temporaryPassword() {
  return `${crypto.randomBytes(6).toString('base64url')}Aa1`;
}

function parseEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  const at = email.lastIndexOf('@');
  if (at <= 0) return null;
  const localPart = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (!/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/.test(localPart) && localPart.length !== 1) return null;
  if (!/^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$/.test(domain)) return null;
  return { email, localPart, domain };
}

function companyFor(token) {
  if (!token || token.role !== 'company_admin') {
    return { error: { statusCode: 403, body: { success: false, message: 'Only a Company Admin can manage mailboxes' } } };
  }
  const user = readUsers().find((item) => item.email === token.email && item.role === 'company_admin');
  if (!user) return { error: { statusCode: 403, body: { success: false, message: 'Company Admin account was not found' } } };
  const company = readCompanies().find((item) => item.id === user.companyId) || readCompanies().find((item) => item.adminEmail === user.email);
  if (!company) return { error: { statusCode: 404, body: { success: false, message: 'Company was not found' } } };
  if (company.status !== 'active') return { error: { statusCode: 409, body: { success: false, message: 'This company is suspended' } } };
  return { company };
}

function present(mailbox) {
  return {
    email: mailbox.email,
    status: mailbox.status,
    usedGb: mailbox.usedGb,
    storageGb: mailbox.storageGb
  };
}

function mailboxExists(companies, email) {
  return companies.some((company) => (company.mailboxes || []).some((item) => item.email === email));
}

function createMailbox(state, companyId, parsed) {
  const company = state.companies.find((item) => item.id === companyId);
  const limit = company.subscription && company.subscription.mailboxLimit;
  if (!Number.isInteger(limit) || limit <= 0) {
    return { statusCode: 409, body: { success: false, message: 'This company has no mailbox allowance' } };
  }
  const domain = (company.domains || []).find((item) => item.domain === parsed.domain);
  if (!domain || domain.verified !== true) {
    return { statusCode: 409, body: { success: false, message: 'The domain must be verified before a mailbox can be created' } };
  }
  if (mailboxExists(state.companies, parsed.email) || state.users.some((user) => user.email === parsed.email)) {
    return { statusCode: 409, body: { success: false, message: 'This mailbox already exists' } };
  }
  const current = (company.mailboxes || []).length;
  if (current >= limit) {
    return { statusCode: 409, body: { success: false, message: `Mailbox limit reached. This plan allows ${limit}.` } };
  }
  const now = new Date().toISOString();
  const password = temporaryPassword();
  const mailbox = {
    email: parsed.email,
    status: 'active',
    usedGb: 0,
    storageGb: Number.isFinite(Number(company.subscription.storageGb)) && Number(company.subscription.storageGb) > 0
      ? Math.max(1, Math.floor(Number(company.subscription.storageGb) / limit))
      : null,
    createdAt: now
  };
  if (!Array.isArray(company.mailboxes)) company.mailboxes = [];
  company.mailboxes.push(mailbox);
  company.updatedAt = now;
  state.users.push({
    id: `usr_${crypto.randomBytes(8).toString('hex')}`,
    name: parsed.localPart,
    email: parsed.email,
    passwordHash: hashPassword(password),
    role: 'employee',
    companyId: company.id,
    createdAt: now,
    updatedAt: now
  });
  state.passwords[parsed.email] = true;
  return {
    statusCode: 201,
    body: {
      success: true,
      message: 'Mailbox created',
      mailbox: present(mailbox),
      remaining: limit - company.mailboxes.length,
      temporaryPassword: password
    }
  };
}

function deleteMailbox(state, companyId, email) {
  const company = state.companies.find((item) => item.id === companyId);
  const index = (company.mailboxes || []).findIndex((item) => item.email === email);
  if (index === -1) return { statusCode: 404, body: { success: false, message: 'Mailbox was not found for this company' } };
  company.mailboxes.splice(index, 1);
  company.updatedAt = new Date().toISOString();
  const userIndex = state.users.findIndex((item) => item.email === email && item.role === 'employee' && item.companyId === company.id);
  if (userIndex !== -1) state.users.splice(userIndex, 1);
  delete state.passwords[email];
  return { statusCode: 200, body: { success: true, message: 'Mailbox deleted', email } };
}

function resetPassword(state, companyId, email) {
  const company = state.companies.find((item) => item.id === companyId);
  const mailbox = (company.mailboxes || []).find((item) => item.email === email);
  if (!mailbox) return { statusCode: 404, body: { success: false, message: 'Mailbox was not found for this company' } };
  const user = state.users.find((item) => item.email === email && item.role === 'employee' && item.companyId === company.id);
  const password = temporaryPassword();
  const now = new Date().toISOString();
  if (user) {
    user.passwordHash = hashPassword(password);
    user.updatedAt = now;
  } else {
    state.users.push({
      id: `usr_${crypto.randomBytes(8).toString('hex')}`,
      name: email.slice(0, email.indexOf('@')),
      email,
      passwordHash: hashPassword(password),
      role: 'employee',
      companyId: company.id,
      createdAt: now,
      updatedAt: now
    });
  }
  state.passwords[email] = true;
  return {
    statusCode: 200,
    body: { success: true, message: 'Password updated', email, temporaryPassword: password }
  };
}

const server = http.createServer(async (req, res) => {
  const pathName = (new URL(req.url, `http://127.0.0.1:${PORT}`)).pathname.replace(/\/+$/, '') || '/';
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
    if (method === 'GET' && pathName === '/') {
      send(res, 200, {
        service: 'SurfSync Mail Mailboxes',
        status: 'OPERATIONAL',
        endpoints: {
          'POST /mailboxes': 'Create a mailbox on a verified domain, inside the plan limit.',
          'POST /mailboxes/delete': 'Delete one mailbox.',
          'POST /mailboxes/reset-password': 'Set a new employee password.'
        }
      });
      return;
    }

    if (method !== 'POST' || !['/mailboxes', '/mailboxes/delete', '/mailboxes/reset-password'].includes(pathName)) {
      send(res, 404, { success: false, message: 'Not found' });
      return;
    }

    const token = verifyToken(req.headers.authorization);
    if (!token) {
      send(res, 401, { success: false, message: 'A valid login token is required' });
      return;
    }
    const owner = companyFor(token);
    if (owner.error) {
      send(res, owner.error.statusCode, owner.error.body);
      return;
    }

    const raw = await readBody(req);
    let body = {};
    if (raw.length) {
      try {
        body = JSON.parse(raw.toString('utf8'));
      } catch {
        send(res, 400, { success: false, message: 'Request body must be JSON' });
        return;
      }
    }
    const parsed = parseEmail(body.email);
    if (!parsed) {
      send(res, 400, { success: false, message: 'email must be a valid mailbox address' });
      return;
    }

    const result = updateShared((state) => {
      if (pathName === '/mailboxes') return createMailbox(state, owner.company.id, parsed);
      if (pathName === '/mailboxes/delete') return deleteMailbox(state, owner.company.id, parsed.email);
      return resetPassword(state, owner.company.id, parsed.email);
    });
    send(res, result.statusCode, result.body);
  } catch (error) {
    console.error(error);
    const statusCode = error.statusCode || 500;
    send(res, statusCode, { success: false, message: statusCode === 500 ? 'Mailbox service error' : error.message });
  }
});

server.listen(PORT, () => {
  console.log(`SurfSync mailboxes listening on http://localhost:${PORT}`);
});
