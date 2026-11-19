const fs = require('fs');
const path = require('path');

const usersFile = path.join(__dirname, '..', 'auth', 'data', 'users.json');
const companiesFile = path.join(__dirname, '..', 'admin', 'data', 'companies.json');
const paymentsFile = path.join(__dirname, '..', 'payments', 'data', 'payments.json');
const recordsFile = path.join(__dirname, 'data', 'onboarding.json');

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
}

function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  let lastError;
  for (let attempt = 0; attempt < 6; attempt += 1) {
    try {
      fs.renameSync(tmp, file);
      return;
    } catch (error) {
      lastError = error;
      if (error.code !== 'EPERM' && error.code !== 'EBUSY') throw error;
      sleep(40 * (attempt + 1));
    }
  }
  throw lastError;
}

function withLock(file, work) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const lockFile = `${file}.lock`;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    let fd;
    try {
      fd = fs.openSync(lockFile, 'wx');
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      try {
        const stat = fs.statSync(lockFile);
        if (Date.now() - stat.mtimeMs > 10000) fs.unlinkSync(lockFile);
      } catch (statError) {
        if (statError.code !== 'ENOENT') throw statError;
      }
      sleep(25);
      continue;
    }
    try {
      return work();
    } finally {
      fs.closeSync(fd);
      fs.unlinkSync(lockFile);
    }
  }
  throw new Error('Could not lock the data file');
}

function readPayments() {
  const data = readJson(paymentsFile, { payments: [] });
  return Array.isArray(data.payments) ? data.payments : [];
}

function readRecords() {
  const data = readJson(recordsFile, { records: [] });
  return Array.isArray(data.records) ? data.records : [];
}

function updateShared(mutator) {
  return withLock(companiesFile, () => withLock(usersFile, () => {
    const companies = readJson(companiesFile, { companies: [] });
    const users = readJson(usersFile, { users: [], resets: [] });
    const records = readRecords();
    if (!Array.isArray(companies.companies)) companies.companies = [];
    if (!Array.isArray(users.users)) users.users = [];
    if (!Array.isArray(users.resets)) users.resets = [];
    const result = mutator({ companies: companies.companies, users: users.users, records });
    writeJson(companiesFile, companies);
    writeJson(usersFile, users);
    writeJson(recordsFile, { records });
    return result;
  }));
}

module.exports = { readPayments, readRecords, updateShared };
