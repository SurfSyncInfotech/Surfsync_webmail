const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, 'data', 'companies.json');
let chain = Promise.resolve();

function empty() {
  return { companies: [] };
}

function read() {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!parsed || !Array.isArray(parsed.companies)) return empty();
    return parsed;
  } catch (error) {
    if (error.code === 'ENOENT') return empty();
    throw error;
  }
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function write(data) {
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

function update(mutator) {
  const run = chain.then(() => {
    const data = read();
    const result = mutator(data);
    write(data);
    return result;
  });
  chain = run.then(() => undefined, () => undefined);
  return run;
}

module.exports = { read, update };
