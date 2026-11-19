const http = require('http');
const crypto = require('crypto');
const { loadEnv } = require('./env');
const { readPayments, readRecords, updateShared } = require('./files');

loadEnv();

const PORT = Number(process.env.PORT || 4004);
const API_KEY = process.env.ONBOARDING_API_KEY || '';

if (!API_KEY) {
  console.error('Set ONBOARDING_API_KEY in onboarding/.env before starting.');
  process.exit(1);
}

function send(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-api-key'
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

function authorized(req) {
  const header = req.headers['x-api-key'];
  const value = Array.isArray(header) ? header[0] : header;
  return safeEqual(API_KEY, value || '');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function temporaryPassword() {
  return `${crypto.randomBytes(6).toString('base64url')}Aa1`;
}

function renewalDate(paidAt, cycle) {
  const date = new Date(paidAt || Date.now());
  if (Number.isNaN(date.getTime())) return null;
  if (cycle === 'annual') date.setUTCFullYear(date.getUTCFullYear() + 1);
  else date.setUTCMonth(date.getUTCMonth() + 1);
  return date.toISOString().slice(0, 10);
}

function presentCompany(company) {
  return {
    companyId: company.id,
    name: company.name,
    status: company.status,
    adminEmail: company.adminEmail,
    subscription: company.subscription
  };
}

function findPayment(paymentId) {
  return readPayments().find((item) => item.id === paymentId) || null;
}

function validatePayment(payment) {
  if (!payment) return { statusCode: 404, body: { success: false, message: 'Payment not found' } };
  if (payment.status !== 'paid') {
    return { statusCode: 409, body: { success: false, message: 'Payment is not paid. A success redirect cannot start onboarding.' } };
  }
  if (payment.type === 'renewal') {
    return { statusCode: 409, body: { success: false, message: 'A renewal does not create a new company' } };
  }
  if (!Number.isInteger(payment.mailboxLimit) || !Number.isInteger(payment.storageGb)) {
    return { statusCode: 409, body: { success: false, message: 'Paid payment is missing mailbox or storage limits' } };
  }
  if (!payment.companyName || !payment.adminEmail || !payment.planName) {
    return { statusCode: 409, body: { success: false, message: 'Paid payment is missing company details' } };
  }
  return null;
}

function subscriptionFrom(payment) {
  return {
    planId: payment.planId,
    planName: payment.planName,
    status: 'active',
    billingCycle: payment.billingCycle,
    mailboxLimit: payment.mailboxLimit,
    storageGb: payment.storageGb,
    amount: payment.amount,
    currency: payment.currency,
    renewalDate: renewalDate(payment.paidAt, payment.billingCycle),
    paymentId: payment.id
  };
}

function welcomeFor(payment, password) {
  return {
    to: payment.adminEmail,
    subject: 'Your SurfSync Mail workspace is ready',
    temporaryPassword: password,
    message: `Your company workspace for ${payment.companyName} is ready. Sign in as ${payment.adminEmail} and open the Company Admin dashboard.`
  };
}

function alreadyDone(records, companies, paymentId) {
  const record = records.find((item) => item.paymentId === paymentId);
  if (!record) return null;
  const company = companies.find((item) => item.id === record.companyId);
  return {
    statusCode: 200,
    body: {
      success: true,
      message: 'Company workspace already created',
      company: company ? presentCompany(company) : { companyId: record.companyId },
      admin: { email: record.adminEmail, role: 'company_admin' },
      welcomeSent: false
    }
  };
}

function complete(state, payment) {
  const done = alreadyDone(state.records, state.companies, payment.id);
  if (done) return done;

  const existingUser = state.users.find((user) => user.email === payment.adminEmail);
  if (existingUser && existingUser.role !== 'company_admin') {
    return { statusCode: 409, body: { success: false, message: 'This email already belongs to another account' } };
  }

  const now = new Date().toISOString();
  let company = state.companies.find((item) => item.onboardingPaymentId === payment.id)
    || state.companies.find((item) => item.adminEmail === payment.adminEmail);
  if (!company) {
    company = {
      id: `cmp_${crypto.randomBytes(8).toString('hex')}`,
      name: payment.companyName,
      status: 'active',
      adminEmail: payment.adminEmail,
      domains: [],
      mailboxes: [],
      createdAt: now
    };
    state.companies.push(company);
  }
  company.onboardingPaymentId = payment.id;
  company.subscription = subscriptionFrom(payment);
  company.updatedAt = now;

  let password = null;
  if (!existingUser) {
    password = temporaryPassword();
    state.users.push({
      id: `usr_${crypto.randomBytes(8).toString('hex')}`,
      name: `${payment.companyName} Admin`,
      email: payment.adminEmail,
      passwordHash: hashPassword(password),
      role: 'company_admin',
      companyId: company.id,
      createdAt: now,
      updatedAt: now
    });
  }

  state.records.push({
    paymentId: payment.id,
    companyId: company.id,
    adminEmail: payment.adminEmail,
    createdAt: now
  });

  const body = {
    success: true,
    message: 'Company workspace created',
    company: presentCompany(company),
    admin: { email: payment.adminEmail, role: 'company_admin' },
    welcome: welcomeFor(payment, password)
  };
  if (!password) delete body.welcome.temporaryPassword;
  return { statusCode: 201, body };
}

function statusFor(paymentId) {
  const payment = findPayment(paymentId);
  if (!payment) return { statusCode: 404, body: { success: false, message: 'Payment not found' } };
  const record = readRecords().find((item) => item.paymentId === paymentId);
  return {
    statusCode: 200,
    body: {
      success: true,
      paymentId,
      paymentStatus: payment.status,
      onboarding: record ? 'completed' : 'not_started',
      companyId: record ? record.companyId : null,
      adminEmail: record ? record.adminEmail : payment.adminEmail
    }
  };
}

const server = http.createServer(async (req, res) => {
  const pathName = (new URL(req.url, `http://127.0.0.1:${PORT}`)).pathname.replace(/\/+$/, '') || '/';
  const method = req.method.toUpperCase();

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-api-key'
    });
    res.end();
    return;
  }

  try {
    if (method === 'GET' && pathName === '/') {
      send(res, 200, {
        service: 'SurfSync Mail Onboarding',
        status: 'OPERATIONAL',
        endpoints: {
          'POST /onboarding/complete': 'Create the company and company admin after a paid payment.',
          'GET /onboarding/:paymentId': 'Read whether onboarding is completed.'
        }
      });
      return;
    }

    if (!authorized(req)) {
      send(res, 401, { success: false, message: 'A valid x-api-key header is required' });
      return;
    }

    if (method === 'GET' && pathName.startsWith('/onboarding/')) {
      const paymentId = decodeURIComponent(pathName.slice('/onboarding/'.length));
      if (!paymentId || paymentId === 'complete') {
        send(res, 404, { success: false, message: 'Not found' });
        return;
      }
      const result = statusFor(paymentId);
      send(res, result.statusCode, result.body);
      return;
    }

    if (method === 'POST' && pathName === '/onboarding/complete') {
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
      const paymentId = typeof body.paymentId === 'string' ? body.paymentId.trim() : '';
      if (!paymentId) {
        send(res, 400, { success: false, message: 'paymentId is required' });
        return;
      }
      const payment = findPayment(paymentId);
      const invalid = validatePayment(payment);
      if (invalid) {
        send(res, invalid.statusCode, invalid.body);
        return;
      }
      const result = updateShared((state) => complete(state, payment));
      send(res, result.statusCode, result.body);
      return;
    }

    send(res, 404, { success: false, message: 'Not found' });
  } catch (error) {
    console.error(error);
    const statusCode = error.statusCode || 500;
    send(res, statusCode, { success: false, message: statusCode === 500 ? 'Onboarding service error' : error.message });
  }
});

server.listen(PORT, () => {
  console.log(`SurfSync onboarding listening on http://localhost:${PORT}`);
});
