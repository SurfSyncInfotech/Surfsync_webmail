const crypto = require('crypto');

function sign(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function verify(secret, rawBody, headerValue) {
  if (!headerValue || typeof headerValue !== 'string') return false;
  return safeEqual(sign(secret, rawBody), headerValue.trim());
}

module.exports = { sign, safeEqual, verify };
