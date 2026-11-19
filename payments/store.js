const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, 'data', 'payments.json');
let chain = Promise.resolve();

function read() {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!parsed || !Array.isArray(parsed.payments) || !Array.isArray(parsed.events)) {
      return { payments: [], events: [] };
    }
    return parsed;
  } catch (error) {
    if (error.code === 'ENOENT') return { payments: [], events: [] };
    throw error;
  }
}

function write(data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
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
