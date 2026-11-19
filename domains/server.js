const http = require('http');
const crypto = require('crypto');
const dns = require('dns').promises;
const { loadEnv } = require('./env');
const { readUsers, readCompanies, updateCompanies, savePrivateKey } = require('./files');

loadEnv();

const PORT = Number(process.env.PORT || 4005);
const JWT_SECRET = process.env.AUTH_JWT_SECRET || '';
const MAIL_MX_HOST = (process.env.MAIL_MX_HOST || 'mx.surfsync.test').toLowerCase();
const SPF_INCLUDE = (process.env.SPF_INCLUDE || 'spf.surfsync.test').toLowerCase();

if (!JWT_SECRET) {
  console.error('Set AUTH_JWT_SECRET in domains/.env before starting. It must match the auth service.');
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

function normalizeDomain(value) {
  if (typeof value !== 'string') return '';
  let domain = value.trim().toLowerCase().replace(/\.$/, '');
  domain = domain.replace(/^https?:\/\//, '').split('/')[0];
  if (!/^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$/.test(domain)) return '';
  if (domain.includes('..') || domain.split('.').some((label) => label.startsWith('-') || label.endsWith('-'))) return '';
  return domain;
}

function companyFor(token) {
  if (!token || token.role !== 'company_admin') return { error: { statusCode: 403, body: { success: false, message: 'Only a Company Admin can manage domains' } } };
  const user = readUsers().find((item) => item.email === token.email && item.role === 'company_admin');
  if (!user) return { error: { statusCode: 403, body: { success: false, message: 'Company Admin account was not found' } } };
  const company = readCompanies().find((item) => item.id === user.companyId) || readCompanies().find((item) => item.adminEmail === user.email);
  if (!company) return { error: { statusCode: 404, body: { success: false, message: 'Company was not found' } } };
  if (company.status !== 'active') return { error: { statusCode: 409, body: { success: false, message: 'This company is suspended' } } };
  return { user, company };
}

function publicKeyText(publicKey) {
  const pem = publicKey.export({ type: 'pkcs1', format: 'pem' });
  return pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

function buildRecords(domain) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const dkim = `v=DKIM1; k=rsa; p=${publicKeyText(publicKey)}`;
  return {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    dns: {
      mx: { type: 'MX', host: domain, value: `10 ${MAIL_MX_HOST}` },
      spf: { type: 'TXT', host: domain, value: `v=spf1 mx include:${SPF_INCLUDE} -all` },
      dkim: { type: 'TXT', host: `surfsync._domainkey.${domain}`, value: dkim },
      dmarc: { type: 'TXT', host: `_dmarc.${domain}`, value: `v=DMARC1; p=none; rua=mailto:dmarc@${domain}` }
    }
  };
}

function present(entry) {
  return {
    domain: entry.domain,
    verified: entry.verified === true,
    records: [entry.dns.mx, entry.dns.spf, entry.dns.dkim, entry.dns.dmarc]
  };
}

function txtValues(rows) {
  return rows.map((parts) => parts.join('').replace(/\s+/g, ''));
}

async function lookupDns(entry) {
  const checks = { mx: false, spf: false, dkim: false, dmarc: false };
  const domain = entry.domain;
  try {
    const mx = await dns.resolveMx(domain);
    checks.mx = mx.some((row) => row.priority === 10 && row.exchange.replace(/\.$/, '').toLowerCase() === MAIL_MX_HOST);
  } catch (error) {
    if (error.code !== 'ENOTFOUND' && error.code !== 'ENODATA' && error.code !== 'ESERVFAIL' && error.code !== 'ETIMEOUT') throw error;
  }
  try {
    const txt = txtValues(await dns.resolveTxt(domain));
    checks.spf = txt.includes(entry.dns.spf.value.replace(/\s+/g, ''));
  } catch (error) {
    if (error.code !== 'ENOTFOUND' && error.code !== 'ENODATA' && error.code !== 'ESERVFAIL' && error.code !== 'ETIMEOUT') throw error;
  }
  try {
    const dkimHost = entry.dns.dkim.host;
    const txt = txtValues(await dns.resolveTxt(dkimHost));
    checks.dkim = txt.includes(entry.dns.dkim.value.replace(/\s+/g, ''));
  } catch (error) {
    if (error.code !== 'ENOTFOUND' && error.code !== 'ENODATA' && error.code !== 'ESERVFAIL' && error.code !== 'ETIMEOUT') throw error;
  }
  try {
    const txt = txtValues(await dns.resolveTxt(`_dmarc.${domain}`));
    checks.dmarc = txt.includes(entry.dns.dmarc.value.replace(/\s+/g, ''));
  } catch (error) {
    if (error.code !== 'ENOTFOUND' && error.code !== 'ENODATA' && error.code !== 'ESERVFAIL' && error.code !== 'ETIMEOUT') throw error;
  }
  return checks;
}

async function checkRecords(entry) {
  if (entry.domain.endsWith('.test')) {
    return { mx: true, spf: true, dkim: true, dmarc: true };
  }
  return lookupDns(entry);
}

function addDomain(companies, companyId, domain) {
  if (companies.some((company) => (company.domains || []).some((item) => item.domain === domain))) {
    return { statusCode: 409, body: { success: false, message: 'This domain is already added' } };
  }
  const company = companies.find((item) => item.id === companyId);
  const records = buildRecords(domain);
  const entry = {
    domain,
    verified: false,
    verifiedAt: null,
    dns: records.dns,
    createdAt: new Date().toISOString()
  };
  if (!Array.isArray(company.domains)) company.domains = [];
  company.domains.push(entry);
  company.updatedAt = new Date().toISOString();
  savePrivateKey(companyId, domain, records.privateKey);
  return { statusCode: 201, body: { success: true, message: 'Domain added', ...present(entry) } };
}

function markVerified(companies, companyId, domain, checks) {
  const company = companies.find((item) => item.id === companyId);
  const entry = company && (company.domains || []).find((item) => item.domain === domain);
  if (!entry || !entry.dns) return { statusCode: 404, body: { success: false, message: 'Domain was not found for this company' } };
  const verified = checks.mx && checks.spf && checks.dkim && checks.dmarc;
  entry.verified = verified;
  entry.verifiedAt = verified ? new Date().toISOString() : null;
  company.updatedAt = new Date().toISOString();
  return {
    statusCode: 200,
    body: {
      success: true,
      domain,
      verified,
      checks,
      message: verified ? 'Domain verified' : 'DNS records do not match yet'
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
        service: 'SurfSync Mail Domains',
        status: 'OPERATIONAL',
        endpoints: {
          'POST /domains': 'Company Admin adds a domain and receives MX, SPF, DKIM, and DMARC records.',
          'POST /domains/verify': 'Check those DNS records. A .test domain can be verified locally.'
        }
      });
      return;
    }

    if (method !== 'POST' || (pathName !== '/domains' && pathName !== '/domains/verify')) {
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
    const domain = normalizeDomain(body.domain);
    if (!domain) {
      send(res, 400, { success: false, message: 'domain must be a valid domain name' });
      return;
    }

    if (pathName === '/domains') {
      const result = updateCompanies((companies) => addDomain(companies, owner.company.id, domain));
      send(res, result.statusCode, result.body);
      return;
    }

    const snapshot = readCompanies().find((item) => item.id === owner.company.id);
    const entry = snapshot && (snapshot.domains || []).find((item) => item.domain === domain);
    if (!entry || !entry.dns) {
      send(res, 404, { success: false, message: 'Domain was not found for this company' });
      return;
    }
    const checks = await checkRecords(entry);
    const result = updateCompanies((companies) => markVerified(companies, owner.company.id, domain, checks));
    send(res, result.statusCode, result.body);
  } catch (error) {
    console.error(error);
    const statusCode = error.statusCode || 500;
    send(res, statusCode, { success: false, message: statusCode === 500 ? 'Domain service error' : error.message });
  }
});

server.listen(PORT, () => {
  console.log(`SurfSync domains listening on http://localhost:${PORT}`);
});
