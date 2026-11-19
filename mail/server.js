const http = require('http');
const crypto = require('crypto');
const { loadEnv } = require('./env');
const { readUsers, readCompanies, readMessages, updateMail } = require('./files');

loadEnv();

const PORT = Number(process.env.PORT || 4008);
const JWT_SECRET = process.env.AUTH_JWT_SECRET || '';
const FOLDERS = ['inbox', 'sent', 'drafts', 'trash', 'spam'];
const sends = new Map();

if (!JWT_SECRET) {
  console.error('Set AUTH_JWT_SECRET in mail/.env before starting. It must match the auth service.');
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

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function employeeMailbox(token) {
  if (!token || token.role !== 'employee') {
    return { error: { statusCode: 403, body: { success: false, message: 'Only an employee can use this mailbox' } } };
  }
  const user = readUsers().find((item) => item.email === token.email && item.role === 'employee');
  if (!user) return { error: { statusCode: 403, body: { success: false, message: 'Employee account was not found' } } };
  const companies = readCompanies();
  const company = companies.find((item) => item.id === user.companyId);
  const mailbox = company && (company.mailboxes || []).find((item) => item.email === user.email);
  if (!company || !mailbox) return { error: { statusCode: 404, body: { success: false, message: 'Mailbox was not found' } } };
  return { user, company, mailbox };
}

function findMailbox(companies, email) {
  for (const company of companies) {
    const mailbox = (company.mailboxes || []).find((item) => item.email === email);
    if (mailbox) return { company, mailbox };
  }
  return null;
}

function usedGb(company) {
  return (company.mailboxes || []).reduce((sum, mailbox) => sum + Number(mailbox.usedGb || 0), 0);
}

function addUsage(mailbox, bytes) {
  const current = Number(mailbox.usedBytes || 0) || Math.round(Number(mailbox.usedGb || 0) * (1024 ** 3));
  mailbox.usedBytes = current + bytes;
  mailbox.usedGb = Math.round((mailbox.usedBytes / (1024 ** 3)) * 1000000) / 1000000;
}

function withinRate(email) {
  const now = Date.now();
  const recent = (sends.get(email) || []).filter((time) => now - time < 60 * 1000);
  if (recent.length >= 30) return false;
  recent.push(now);
  sends.set(email, recent);
  return true;
}

function present(message, includeBody) {
  const view = {
    messageId: message.id,
    folder: message.folder,
    from: message.from,
    to: message.to,
    subject: message.subject,
    createdAt: message.createdAt
  };
  if (includeBody) view.body = message.body;
  return view;
}

function deliver(state, fromCompany, fromMailbox, input) {
  if (fromCompany.status !== 'active' || fromMailbox.status !== 'active') {
    return { statusCode: 409, body: { success: false, message: 'This mailbox cannot send while it is suspended' } };
  }
  if (!withinRate(fromMailbox.email)) {
    return { statusCode: 429, body: { success: false, message: 'Sending limit reached. Try again in a minute.' } };
  }
  const bytes = Buffer.byteLength(`${input.subject}\n${input.body}`);
  const gb = bytes / (1024 ** 3);
  const cap = fromMailbox.storageGb || fromCompany.subscription.storageGb;
  if (Number(fromMailbox.usedGb || 0) + gb > cap || usedGb(fromCompany) + gb > fromCompany.subscription.storageGb) {
    return { statusCode: 409, body: { success: false, message: 'Mailbox storage limit reached' } };
  }
  const now = new Date().toISOString();
  const local = findMailbox(state.companies, input.to);
  const sent = {
    id: `msg_${crypto.randomBytes(8).toString('hex')}`,
    mailbox: fromMailbox.email,
    folder: 'sent',
    from: fromMailbox.email,
    to: input.to,
    subject: input.subject,
    body: input.body,
    createdAt: now
  };
  state.messages.push(sent);
  addUsage(fromMailbox, bytes);
  let inboxId = null;
  if (local && local.mailbox.email !== fromMailbox.email) {
    const localCap = local.mailbox.storageGb || local.company.subscription.storageGb;
    const canStore = Number(local.mailbox.usedGb || 0) + gb <= localCap && usedGb(local.company) + gb <= local.company.subscription.storageGb;
    if (canStore && local.company.status === 'active' && local.mailbox.status === 'active') {
      const inbox = { ...sent, id: `msg_${crypto.randomBytes(8).toString('hex')}`, mailbox: local.mailbox.email, folder: 'inbox' };
      state.messages.push(inbox);
      addUsage(local.mailbox, bytes);
      inboxId = inbox.id;
    }
  } else if (local && local.mailbox.email === fromMailbox.email) {
    const inbox = { ...sent, id: `msg_${crypto.randomBytes(8).toString('hex')}`, folder: 'inbox' };
    state.messages.push(inbox);
    inboxId = inbox.id;
  }
  fromCompany.updatedAt = now;
  return {
    statusCode: 201,
    body: {
      success: true,
      message: local ? 'Message sent' : 'Message saved in Sent. External delivery waits for the mail server.',
      sent: present(sent, false),
      delivered: Boolean(local),
      inboxMessageId: inboxId
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
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end();
    return;
  }

  try {
    if (method === 'GET' && pathName === '/') {
      send(res, 200, {
        service: 'SurfSync Mail Employee Mail',
        status: 'OPERATIONAL',
        endpoints: {
          'POST /mail/list': 'List inbox, sent, drafts, trash, or spam for the signed-in employee.',
          'POST /mail/read': 'Read one message from that employee mailbox.',
          'POST /mail/send': 'Send a message from that employee mailbox.'
        }
      });
      return;
    }

    if (method !== 'POST' || !['/mail/list', '/mail/read', '/mail/send'].includes(pathName)) {
      send(res, 404, { success: false, message: 'Not found' });
      return;
    }

    const token = verifyToken(req.headers.authorization);
    if (!token) {
      send(res, 401, { success: false, message: 'A valid login token is required' });
      return;
    }
    const owner = employeeMailbox(token);
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

    if (pathName === '/mail/list') {
      const folder = cleanText(body.folder, 20).toLowerCase() || 'inbox';
      if (!FOLDERS.includes(folder)) {
        send(res, 400, { success: false, message: 'folder must be inbox, sent, drafts, trash, or spam' });
        return;
      }
      const messages = readMessages()
        .filter((item) => item.mailbox === owner.mailbox.email && item.folder === folder)
        .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
        .map((item) => present(item, false));
      send(res, 200, { success: true, folder, count: messages.length, messages });
      return;
    }

    if (pathName === '/mail/read') {
      const messageId = cleanText(body.messageId, 80);
      const message = readMessages().find((item) => item.id === messageId && item.mailbox === owner.mailbox.email);
      if (!message) {
        send(res, 404, { success: false, message: 'Message was not found in this mailbox' });
        return;
      }
      send(res, 200, { success: true, message: present(message, true) });
      return;
    }

    const to = cleanText(body.to, 160).toLowerCase();
    const subject = cleanText(body.subject, 200);
    const text = cleanText(body.body, 100000);
    if (!validEmail(to) || !subject || !text) {
      send(res, 400, { success: false, message: 'to, subject, and body are required' });
      return;
    }
    const result = updateMail((state) => deliver(state, 
      state.companies.find((item) => item.id === owner.company.id),
      state.companies.find((item) => item.id === owner.company.id).mailboxes.find((item) => item.email === owner.mailbox.email),
      { to, subject, body: text }
    ));
    send(res, result.statusCode, result.body);
  } catch (error) {
    console.error(error);
    send(res, 500, { success: false, message: 'Mail service error' });
  }
});

server.listen(PORT, () => {
  console.log(`SurfSync mail listening on http://localhost:${PORT}`);
});
