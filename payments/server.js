const http = require('http');
const crypto = require('crypto');
const { loadEnv } = require('./env');
const { safeEqual, verify } = require('./signature');
const store = require('./store');

loadEnv();

const PORT = Number(process.env.PORT || 4000);
const API_KEY = process.env.PAYMENT_API_KEY || '';
const WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET || '';
const CAPTURED = 'payment.captured';
const FAILED = 'payment.failed';
const RENEWED = 'subscription.renewed';
const RENEWAL_FAILED = 'subscription.payment_failed';

if (!API_KEY || !WEBHOOK_SECRET) {
  console.error('Set PAYMENT_API_KEY and PAYMENT_WEBHOOK_SECRET in payments/.env before starting.');
  process.exit(1);
}

function send(res, statusCode, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-api-key, X-Payment-Signature'
  });
  res.end(payload);
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

function authorized(req) {
  return safeEqual(API_KEY, req.headers['x-api-key'] || '');
}

function parseAmount(value) {
  const amount = typeof value === 'string' ? Number(value.trim()) : Number(value);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 10_000_000) return null;
  const paise = Math.round(amount * 100);
  if (Math.abs(amount * 100 - paise) > 1e-6) return null;
  return paise / 100;
}

function sameMoney(left, right) {
  return Math.round(Number(left) * 100) === Math.round(Number(right) * 100);
}

function cleanText(value, max) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function optionalLimit(value) {
  if (value === undefined || value === null || value === '') return null;
  const number = Number(value);
  if (!Number.isInteger(number) || number <= 0 || number > 100000) return undefined;
  return number;
}

function present(payment) {
  return {
    paymentId: payment.id,
    status: payment.status,
    type: payment.type,
    planId: payment.planId,
    planName: payment.planName,
    billingCycle: payment.billingCycle,
    amount: payment.amount,
    currency: payment.currency,
    companyName: payment.companyName,
    adminEmail: payment.adminEmail,
    mailboxLimit: payment.mailboxLimit,
    storageGb: payment.storageGb,
    gatewayPaymentId: payment.gatewayPaymentId,
    parentPaymentId: payment.parentPaymentId,
    createdAt: payment.createdAt,
    paidAt: payment.paidAt,
    failedAt: payment.failedAt
  };
}

function onboarding(payment) {
  return {
    ready: payment.status === 'paid',
    paymentId: payment.id,
    planId: payment.planId,
    planName: payment.planName,
    billingCycle: payment.billingCycle,
    amount: payment.amount,
    currency: payment.currency,
    companyName: payment.companyName,
    adminEmail: payment.adminEmail,
    mailboxLimit: payment.mailboxLimit,
    storageGb: payment.storageGb
  };
}

function createPayment(body) {
  const planId = cleanText(body.planId, 80);
  const planName = cleanText(body.planName, 120);
  const billingCycle = cleanText(body.billingCycle, 20).toLowerCase();
  const companyName = cleanText(body.companyName, 160);
  const adminEmail = cleanText(body.adminEmail, 160).toLowerCase();
  const currency = (cleanText(body.currency, 3) || 'INR').toUpperCase();
  const amount = parseAmount(body.amount);
  const mailboxLimit = optionalLimit(body.mailboxLimit);
  const storageGb = optionalLimit(body.storageGb);

  if (!planId || !planName) return { error: 'planId and planName are required' };
  if (billingCycle !== 'monthly' && billingCycle !== 'annual') {
    return { error: 'billingCycle must be monthly or annual' };
  }
  if (amount === null) return { error: 'amount must be a positive number with up to 2 decimals' };
  if (!/^[A-Z]{3}$/.test(currency)) return { error: 'currency must be a 3-letter code' };
  if (!companyName) return { error: 'companyName is required' };
  if (!validEmail(adminEmail)) return { error: 'adminEmail must be a valid email' };
  if (mailboxLimit === undefined || storageGb === undefined) {
    return { error: 'mailboxLimit and storageGb must be positive whole numbers when sent' };
  }

  const now = new Date().toISOString();
  const id = `pay_${crypto.randomBytes(8).toString('hex')}`;
  return {
    payment: {
      id,
      status: 'pending',
      type: 'checkout',
      planId,
      planName,
      billingCycle,
      amount,
      currency,
      companyName,
      adminEmail,
      mailboxLimit,
      storageGb,
      gatewayPaymentId: null,
      parentPaymentId: null,
      createdAt: now,
      updatedAt: now,
      paidAt: null,
      failedAt: null,
      failureReason: null
    }
  };
}

function applyWebhook(data, event) {
  const known = data.events.find((item) => item.eventId === event.eventId);
  if (known) {
    if (known.paymentId !== event.paymentId || known.event !== event.event) {
      return { statusCode: 409, body: { success: false, message: 'eventId was already used for a different payment' } };
    }
    return { statusCode: 200, body: known.response };
  }

  const payment = data.payments.find((item) => item.id === event.paymentId);
  if (!payment) {
    return { statusCode: 404, body: { success: false, message: 'Payment not found' } };
  }
  if (!sameMoney(payment.amount, event.amount) || payment.currency !== event.currency) {
    return { statusCode: 409, body: { success: false, message: 'Webhook amount does not match this payment' } };
  }

  const now = new Date().toISOString();
  let target = payment;
  let message = '';

  if (event.event === CAPTURED) {
    if (payment.status === 'failed') {
      return { statusCode: 409, body: { success: false, message: 'A failed payment cannot be marked paid' } };
    }
    if (payment.status === 'pending') {
      payment.status = 'paid';
      payment.paidAt = now;
      payment.updatedAt = now;
      payment.gatewayPaymentId = event.gatewayPaymentId;
      message = 'Payment marked paid';
    } else {
      message = 'Payment already paid';
    }
  } else if (event.event === FAILED) {
    if (payment.status === 'paid') {
      return { statusCode: 409, body: { success: false, message: 'A paid payment cannot be marked failed' } };
    }
    if (payment.status === 'pending') {
      payment.status = 'failed';
      payment.failedAt = now;
      payment.updatedAt = now;
      payment.gatewayPaymentId = event.gatewayPaymentId;
      payment.failureReason = event.reason || 'Payment failed';
      message = 'Payment marked failed';
    } else {
      message = 'Payment already failed';
    }
  } else if (event.event === RENEWED || event.event === RENEWAL_FAILED) {
    if (payment.status !== 'paid') {
      return { statusCode: 409, body: { success: false, message: 'Renewal requires a paid payment' } };
    }
    const renewal = {
      ...payment,
      id: `pay_${crypto.randomBytes(8).toString('hex')}`,
      type: 'renewal',
      parentPaymentId: payment.id,
      status: event.event === RENEWED ? 'paid' : 'failed',
      gatewayPaymentId: event.gatewayPaymentId,
      createdAt: now,
      updatedAt: now,
      paidAt: event.event === RENEWED ? now : null,
      failedAt: event.event === RENEWED ? null : now,
      failureReason: event.event === RENEWED ? null : (event.reason || 'Renewal payment failed')
    };
    data.payments.push(renewal);
    target = renewal;
    message = event.event === RENEWED ? 'Renewal marked paid' : 'Renewal marked failed';
  } else {
    return { statusCode: 400, body: { success: false, message: 'Unsupported payment event' } };
  }

  const response = {
    success: true,
    message,
    payment: present(target),
    onboarding: onboarding(target)
  };
  data.events.push({
    eventId: event.eventId,
    event: event.event,
    paymentId: event.paymentId,
    response
  });
  return { statusCode: 200, body: response };
}

function parseWebhook(raw, payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { error: 'Webhook body must be a JSON object' };
  }
  const eventId = cleanText(payload.eventId, 80);
  const event = cleanText(payload.event, 80);
  const paymentId = cleanText(payload.paymentId, 80);
  const currency = cleanText(payload.currency, 3).toUpperCase();
  const gatewayPaymentId = cleanText(payload.gatewayPaymentId, 120) || null;
  const reason = cleanText(payload.reason, 240) || null;
  const amount = parseAmount(payload.amount);
  const allowed = [CAPTURED, FAILED, RENEWED, RENEWAL_FAILED];
  if (!eventId || !paymentId) return { error: 'eventId and paymentId are required' };
  if (!allowed.includes(event)) return { error: `event must be one of ${allowed.join(', ')}` };
  if (amount === null) return { error: 'amount must match the created payment' };
  if (!/^[A-Z]{3}$/.test(currency)) return { error: 'currency must be a 3-letter code' };
  return { event: { eventId, event, paymentId, amount, currency, gatewayPaymentId, reason, raw } };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const method = req.method.toUpperCase();

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-api-key, X-Payment-Signature'
    });
    res.end();
    return;
  }

  try {
    if (method === 'GET' && path === '/') {
      send(res, 200, {
        service: 'SurfSync Mail Payments',
        status: 'OPERATIONAL',
        endpoints: {
          'POST /payments/create': 'Start a monthly or annual payment. Status stays pending.',
          'GET /payments/status/:paymentId': 'Read pending, paid, or failed. This never marks a payment paid.',
          'POST /payments/webhook': 'Gateway only. A valid signature marks the payment paid or failed.',
          'GET /payments': 'Payment history.'
        }
      });
      return;
    }

    const isWebhook = method === 'POST' && path === '/payments/webhook';
    if (!isWebhook && !authorized(req)) {
      send(res, 401, { success: false, message: 'A valid x-api-key header is required' });
      return;
    }

    if (method === 'POST' && path === '/payments/create') {
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
      const created = createPayment(body);
      if (created.error) {
        send(res, 400, { success: false, message: created.error });
        return;
      }
      await store.update((data) => {
        data.payments.push(created.payment);
      });
      send(res, 201, {
        success: true,
        message: 'Payment created',
        payment: present(created.payment)
      });
      return;
    }

    if (method === 'GET' && path.startsWith('/payments/status/')) {
      const paymentId = decodeURIComponent(path.slice('/payments/status/'.length));
      const payment = store.read().payments.find((item) => item.id === paymentId);
      if (!payment) {
        send(res, 404, { success: false, message: 'Payment not found' });
        return;
      }
      send(res, 200, { success: true, payment: present(payment) });
      return;
    }

    if (method === 'GET' && path === '/payments') {
      const email = (url.searchParams.get('adminEmail') || '').trim().toLowerCase();
      const status = (url.searchParams.get('status') || '').trim().toLowerCase();
      let payments = store.read().payments.slice();
      if (email) payments = payments.filter((item) => item.adminEmail === email);
      if (status) payments = payments.filter((item) => item.status === status);
      payments.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
      send(res, 200, {
        success: true,
        count: payments.length,
        payments: payments.map(present)
      });
      return;
    }

    if (isWebhook) {
      const raw = await readBody(req);
      const signature = req.headers['x-payment-signature'];
      if (!verify(WEBHOOK_SECRET, raw, Array.isArray(signature) ? signature[0] : signature)) {
        send(res, 401, { success: false, message: 'Webhook signature is invalid' });
        return;
      }
      let payload;
      try {
        payload = JSON.parse(raw.toString('utf8'));
      } catch {
        send(res, 400, { success: false, message: 'Webhook body must be JSON' });
        return;
      }
      const parsed = parseWebhook(raw, payload);
      if (parsed.error) {
        send(res, 400, { success: false, message: parsed.error });
        return;
      }
      const result = await store.update((data) => applyWebhook(data, parsed.event));
      send(res, result.statusCode, result.body);
      return;
    }

    send(res, 404, { success: false, message: 'Not found' });
  } catch (error) {
    const statusCode = error.statusCode || 500;
    send(res, statusCode, { success: false, message: statusCode === 500 ? 'Payment service error' : error.message });
  }
});

server.listen(PORT, () => {
  console.log(`SurfSync payments listening on http://localhost:${PORT}`);
});
