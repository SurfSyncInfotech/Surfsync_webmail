const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { loadEnv } = require('./env');

loadEnv();

const PORT = Number(process.env.PORT || 4007);
const JWT_SECRET = process.env.AUTH_JWT_SECRET || '';
const usersFile = path.join(__dirname, '..', 'auth', 'data', 'users.json');
const companiesFile = path.join(__dirname, '..', 'admin', 'data', 'companies.json');

if (!JWT_SECRET) {
  console.error('Set AUTH_JWT_SECRET in dashboard/.env before starting. It must match the auth service.');
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

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
}

function round3(value) {
  return Math.round(value * 1000) / 1000;
}

function companyFor(token) {
  if (!token || token.role !== 'company_admin') {
    return { error: { statusCode: 403, body: { success: false, message: 'Only a Company Admin can view this dashboard' } } };
  }
  const users = readJson(usersFile, { users: [] }).users || [];
  const user = users.find((item) => item.email === token.email && item.role === 'company_admin');
  if (!user) return { error: { statusCode: 403, body: { success: false, message: 'Company Admin account was not found' } } };
  const companies = readJson(companiesFile, { companies: [] }).companies || [];
  const company = companies.find((item) => item.id === user.companyId) || companies.find((item) => item.adminEmail === user.email);
  if (!company) return { error: { statusCode: 404, body: { success: false, message: 'Company was not found' } } };
  return { company };
}

function dashboardFor(company) {
  const mailboxes = company.mailboxes || [];
  const usedBytes = mailboxes.reduce((sum, mailbox) => {
    if (mailbox.usedBytes) return sum + Number(mailbox.usedBytes);
    return sum + Math.round(Number(mailbox.usedGb || 0) * (1024 ** 3));
  }, 0);
  const usedGb = usedBytes / (1024 ** 3);
  const subscription = company.subscription || {};
  return {
    companyName: company.name,
    status: company.status,
    subscription: {
      planName: subscription.planName || null,
      status: subscription.status || null,
      billingCycle: subscription.billingCycle || null,
      renewalDate: subscription.renewalDate || null
    },
    mailboxes: {
      used: mailboxes.length,
      allowed: subscription.mailboxLimit || 0
    },
    storage: {
      usedGb: round3(usedGb),
      usedBytes,
      allowedGb: subscription.storageGb || 0
    },
    domains: (company.domains || []).map((domain) => ({
      domain: domain.domain,
      verified: domain.verified === true
    }))
  };
}

const server = http.createServer((req, res) => {
  const pathName = (new URL(req.url, `http://127.0.0.1:${PORT}`)).pathname.replace(/\/+$/, '') || '/';
  const method = req.method.toUpperCase();

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end();
    return;
  }

  try {
    if (method === 'GET' && pathName === '/') {
      send(res, 200, {
        service: 'SurfSync Mail Company Dashboard',
        status: 'OPERATIONAL',
        endpoints: {
          'GET /company/dashboard': 'Mailboxes used, storage used, subscription, and renewal date.'
        }
      });
      return;
    }

    if (method === 'GET' && pathName === '/company/dashboard') {
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
      send(res, 200, { success: true, dashboard: dashboardFor(owner.company) });
      return;
    }

    send(res, 404, { success: false, message: 'Not found' });
  } catch (error) {
    console.error(error);
    send(res, 500, { success: false, message: 'Dashboard service error' });
  }
});

server.listen(PORT, () => {
  console.log(`SurfSync dashboard listening on http://localhost:${PORT}`);
});
