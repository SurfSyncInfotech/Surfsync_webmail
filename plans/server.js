const http = require('http');
const crypto = require('crypto');
const { loadEnv } = require('./env');
const store = require('./store');

loadEnv();

const PORT = Number(process.env.PORT || 4002);
const JWT_SECRET = process.env.AUTH_JWT_SECRET || '';

if (!JWT_SECRET) {
  console.error('Set AUTH_JWT_SECRET in plans/.env before starting. It must match the auth service.');
  process.exit(1);
}

const SEED = [
  {
    name: 'Starter',
    monthlyPrice: 499,
    annualPrice: 4990,
    currency: 'INR',
    mailboxLimit: 2,
    storageGb: 10,
    features: ['Webmail', 'Spam filtering']
  },
  {
    name: 'Business',
    monthlyPrice: 999,
    annualPrice: 9990,
    currency: 'INR',
    mailboxLimit: 5,
    storageGb: 50,
    features: ['Webmail', 'Spam filtering', 'Admin panel']
  }
];

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

function parseAmount(value) {
  const amount = typeof value === 'string' ? Number(value.trim()) : Number(value);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 10_000_000) return null;
  const paise = Math.round(amount * 100);
  if (Math.abs(amount * 100 - paise) > 1e-6) return null;
  return paise / 100;
}

function parseLimit(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number <= 0 || number > 100000) return null;
  return number;
}

function parseFeatures(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 20) return null;
  const features = [];
  for (const item of value) {
    const text = cleanText(item, 80);
    if (!text) return null;
    features.push(text);
  }
  return features;
}

function present(plan) {
  return {
    planId: plan.id,
    name: plan.name,
    monthlyPrice: plan.monthlyPrice,
    annualPrice: plan.annualPrice,
    currency: plan.currency,
    mailboxLimit: plan.mailboxLimit,
    storageGb: plan.storageGb,
    features: plan.features,
    status: plan.status
  };
}

function publicPlan(plan) {
  const view = present(plan);
  delete view.status;
  return view;
}

function buildPlan(body, existing) {
  const name = cleanText(body.name, 120) || (existing ? existing.name : '');
  const currency = (cleanText(body.currency, 3) || (existing ? existing.currency : 'INR')).toUpperCase();
  const monthlyPrice = body.monthlyPrice === undefined && existing ? existing.monthlyPrice : parseAmount(body.monthlyPrice);
  const annualPrice = body.annualPrice === undefined && existing ? existing.annualPrice : parseAmount(body.annualPrice);
  const mailboxLimit = body.mailboxLimit === undefined && existing ? existing.mailboxLimit : parseLimit(body.mailboxLimit);
  const storageGb = body.storageGb === undefined && existing ? existing.storageGb : parseLimit(body.storageGb);
  const features = body.features === undefined && existing ? existing.features : parseFeatures(body.features);
  if (!name) return { error: 'name is required' };
  if (!/^[A-Z]{3}$/.test(currency)) return { error: 'currency must be a 3-letter code' };
  if (monthlyPrice === null || annualPrice === null) return { error: 'monthlyPrice and annualPrice must be positive numbers' };
  if (mailboxLimit === null || storageGb === null) return { error: 'mailboxLimit and storageGb must be positive whole numbers' };
  if (features === null) return { error: 'features must be a list of short text items' };
  return { name, currency, monthlyPrice, annualPrice, mailboxLimit, storageGb, features };
}

function sameName(data, name, exceptId) {
  return data.plans.some((plan) => plan.id !== exceptId && plan.name.toLowerCase() === name.toLowerCase());
}

function applyPlan(data, body) {
  const action = cleanText(body.action, 20).toLowerCase();
  if (action === 'create') {
    const fields = buildPlan(body);
    if (fields.error) return { statusCode: 400, body: { success: false, message: fields.error } };
    if (sameName(data, fields.name)) {
      return { statusCode: 409, body: { success: false, message: 'A plan with this name already exists' } };
    }
    const now = new Date().toISOString();
    const plan = {
      id: `plan_${crypto.randomBytes(8).toString('hex')}`,
      ...fields,
      status: 'active',
      createdAt: now,
      updatedAt: now
    };
    data.plans.push(plan);
    return { statusCode: 201, body: { success: true, message: 'Plan created', plan: present(plan) } };
  }

  const planId = cleanText(body.planId, 80);
  const plan = data.plans.find((item) => item.id === planId);
  if (!plan) return { statusCode: 404, body: { success: false, message: 'Plan not found' } };

  if (action === 'deactivate') {
    plan.status = 'inactive';
    plan.updatedAt = new Date().toISOString();
    return { statusCode: 200, body: { success: true, message: 'Plan deactivated', plan: present(plan) } };
  }

  if (action === 'update') {
    const fields = buildPlan(body, plan);
    if (fields.error) return { statusCode: 400, body: { success: false, message: fields.error } };
    if (sameName(data, fields.name, plan.id)) {
      return { statusCode: 409, body: { success: false, message: 'A plan with this name already exists' } };
    }
    Object.assign(plan, fields, { updatedAt: new Date().toISOString() });
    return { statusCode: 200, body: { success: true, message: 'Plan updated', plan: present(plan) } };
  }

  return { statusCode: 400, body: { success: false, message: 'action must be create, update, or deactivate' } };
}

function seedPlans(data) {
  if (data.plans.length) return;
  const now = new Date().toISOString();
  SEED.forEach((item) => {
    data.plans.push({
      id: `plan_${crypto.randomBytes(8).toString('hex')}`,
      ...item,
      status: 'active',
      createdAt: now,
      updatedAt: now
    });
  });
}

const server = http.createServer(async (req, res) => {
  const path = (new URL(req.url, `http://127.0.0.1:${PORT}`)).pathname.replace(/\/+$/, '') || '/';
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
        service: 'SurfSync Mail Plans',
        status: 'OPERATIONAL',
        endpoints: {
          'GET /plans': 'Active plans with price, mailbox limit, and storage limit.',
          'POST /admin/plans': 'Super Admin creates, updates, or deactivates a plan.'
        }
      });
      return;
    }

    if (method === 'GET' && path === '/plans') {
      const plans = store.read().plans
        .filter((plan) => plan.status === 'active')
        .sort((a, b) => a.monthlyPrice - b.monthlyPrice)
        .map(publicPlan);
      send(res, 200, { success: true, count: plans.length, plans });
      return;
    }

    if (method === 'POST' && path === '/admin/plans') {
      const token = verifyToken(req.headers.authorization);
      if (!token) {
        send(res, 401, { success: false, message: 'A valid login token is required' });
        return;
      }
      if (token.role !== 'super_admin') {
        send(res, 403, { success: false, message: 'Only a Super Admin can change plans' });
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
      const result = await store.update((data) => applyPlan(data, body));
      send(res, result.statusCode, result.body);
      return;
    }

    send(res, 404, { success: false, message: 'Not found' });
  } catch (error) {
    console.error(error);
    const statusCode = error.statusCode || 500;
    send(res, statusCode, { success: false, message: statusCode === 500 ? 'Plans service error' : error.message });
  }
});

store.update(seedPlans).then(() => {
  server.listen(PORT, () => {
    console.log(`SurfSync plans listening on http://localhost:${PORT}`);
  });
});
