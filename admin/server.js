const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { loadEnv } = require('./env');
const store = require('./store');

loadEnv();

const PORT = Number(process.env.PORT || 4003);
const JWT_SECRET = process.env.AUTH_JWT_SECRET || '';
const SERVER_STORAGE_GB = Number(process.env.SERVER_STORAGE_GB || 1000);
const STORAGE_ALERT_PERCENT = Number(process.env.STORAGE_ALERT_PERCENT || 80);

if (!JWT_SECRET) {
  console.error('Set AUTH_JWT_SECRET in admin/.env before starting. It must match the auth service.');
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

function cleanText(value, max) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}

function round1(value) {
  return Math.round(value * 10) / 10;
}

function presentCompany(company) {
  return {
    companyId: company.id,
    name: company.name,
    status: company.status,
    adminEmail: company.adminEmail,
    subscription: company.subscription,
    domains: company.domains,
    mailboxes: company.mailboxes
  };
}

function readRevenue() {
  try {
    const file = path.join(__dirname, '..', 'payments', 'data', 'payments.json');
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    const paid = (parsed.payments || []).filter((item) => item.status === 'paid');
    const revenue = paid.reduce((sum, item) => sum + Number(item.amount || 0), 0);
    return {
      revenue: Math.round(revenue * 100) / 100,
      currency: paid[0] ? paid[0].currency : 'INR'
    };
  } catch {
    return { revenue: 0, currency: 'INR' };
  }
}

function dashboard(companies) {
  const activeCompanies = companies.filter((company) => company.status === 'active');
  const suspendedCompanies = companies.filter((company) => company.status === 'suspended');
  const activeSubscriptions = activeCompanies.filter((company) => company.subscription && company.subscription.status === 'active');
  const allocatedGb = companies.reduce((sum, company) => sum + Number(company.subscription.storageGb || 0), 0);
  const usedGb = companies.reduce((sum, company) => {
    return sum + company.mailboxes.reduce((inner, mailbox) => inner + Number(mailbox.usedGb || 0), 0);
  }, 0);
  const usedPercent = SERVER_STORAGE_GB > 0 ? round1((usedGb / SERVER_STORAGE_GB) * 100) : 0;
  const money = readRevenue();
  return {
    totalCompanies: companies.length,
    activeCompanies: activeCompanies.length,
    suspendedCompanies: suspendedCompanies.length,
    activeSubscriptions: activeSubscriptions.length,
    revenue: money.revenue,
    currency: money.currency,
    storage: {
      allocatedGb,
      usedGb: round1(usedGb),
      serverGb: SERVER_STORAGE_GB,
      usedPercent,
      alert: usedPercent >= STORAGE_ALERT_PERCENT
    }
  };
}

function setCompanyStatus(data, body) {
  const companyId = cleanText(body.companyId, 80);
  const status = cleanText(body.status, 20).toLowerCase();
  if (status !== 'active' && status !== 'suspended') {
    return { statusCode: 400, body: { success: false, message: 'status must be active or suspended' } };
  }
  const company = data.companies.find((item) => item.id === companyId);
  if (!company) return { statusCode: 404, body: { success: false, message: 'Company not found' } };
  company.status = status;
  company.updatedAt = new Date().toISOString();
  company.mailboxes.forEach((mailbox) => {
    mailbox.status = status;
  });
  const message = status === 'suspended' ? 'Company suspended' : 'Company reactivated';
  return { statusCode: 200, body: { success: true, message, company: presentCompany(company) } };
}

function seedCompanies(data) {
  if (data.companies.length) return;
  const now = new Date().toISOString();
  const renewal = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  data.companies.push(
    {
      id: `cmp_${crypto.randomBytes(8).toString('hex')}`,
      name: 'ABC Company',
      status: 'active',
      adminEmail: 'admin@abccompany.com',
      subscription: {
        planName: 'Business',
        status: 'active',
        billingCycle: 'monthly',
        mailboxLimit: 5,
        storageGb: 50,
        renewalDate: renewal
      },
      domains: [{ domain: 'abccompany.com', verified: true }],
      mailboxes: [
        { email: 'info@abccompany.com', status: 'active', usedGb: 4.2 },
        { email: 'sales@abccompany.com', status: 'active', usedGb: 6.5 }
      ],
      createdAt: now,
      updatedAt: now
    },
    {
      id: `cmp_${crypto.randomBytes(8).toString('hex')}`,
      name: 'Northwind',
      status: 'active',
      adminEmail: 'admin@northwind.com',
      subscription: {
        planName: 'Starter',
        status: 'active',
        billingCycle: 'annual',
        mailboxLimit: 2,
        storageGb: 10,
        renewalDate: renewal
      },
      domains: [{ domain: 'northwind.com', verified: true }],
      mailboxes: [
        { email: 'hello@northwind.com', status: 'active', usedGb: 1.1 }
      ],
      createdAt: now,
      updatedAt: now
    }
  );
}

function requireAdmin(req, res) {
  const token = verifyToken(req.headers.authorization);
  if (!token) {
    send(res, 401, { success: false, message: 'A valid login token is required' });
    return null;
  }
  if (token.role !== 'super_admin') {
    send(res, 403, { success: false, message: 'Only a Super Admin can view this' });
    return null;
  }
  return token;
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
        service: 'SurfSync Mail Super Admin',
        status: 'OPERATIONAL',
        endpoints: {
          'GET /admin/dashboard': 'Companies, active subscriptions, revenue, and storage.',
          'GET /admin/companies': 'Companies with domains and mailboxes.',
          'POST /admin/companies/status': 'Suspend or reactivate a company.'
        }
      });
      return;
    }

    if (method === 'GET' && pathName === '/admin/dashboard') {
      if (!requireAdmin(req, res)) return;
      const companies = store.read().companies;
      send(res, 200, { success: true, dashboard: dashboard(companies) });
      return;
    }

    if (method === 'GET' && pathName === '/admin/companies') {
      if (!requireAdmin(req, res)) return;
      const companies = store.read().companies
        .slice()
        .sort((a, b) => a.name.localeCompare(b.name))
        .map(presentCompany);
      send(res, 200, { success: true, count: companies.length, companies });
      return;
    }

    if (method === 'POST' && pathName === '/admin/companies/status') {
      if (!requireAdmin(req, res)) return;
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
      const result = await store.update((data) => setCompanyStatus(data, body));
      send(res, result.statusCode, result.body);
      return;
    }

    send(res, 404, { success: false, message: 'Not found' });
  } catch (error) {
    console.error(error);
    const statusCode = error.statusCode || 500;
    send(res, statusCode, { success: false, message: statusCode === 500 ? 'Admin service error' : error.message });
  }
});

store.update(seedCompanies).then(() => {
  server.listen(PORT, () => {
    console.log(`SurfSync admin listening on http://localhost:${PORT}`);
  });
});
