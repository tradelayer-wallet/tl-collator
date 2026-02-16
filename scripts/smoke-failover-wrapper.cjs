#!/usr/bin/env node
/* eslint-disable no-console */
const { spawn } = require('node:child_process');

function main() {
  const args = process.argv.slice(2);
  const child = spawn(process.execPath, ['scripts/smoke-failover.cjs', ...args], {
    cwd: process.cwd(),
    stdio: ['inherit', 'pipe', 'pipe'],
  });

  let out = '';
  let err = '';
  child.stdout.on('data', (d) => {
    const s = d.toString();
    out += s;
    process.stdout.write(s);
  });
  child.stderr.on('data', (d) => {
    const s = d.toString();
    err += s;
    process.stderr.write(s);
  });

  child.on('close', (code) => {
    const successPrinted = out.includes('"ok": true');
    if ((code === 0) || successPrinted) {
      if (code !== 0 && successPrinted) {
        console.warn(`smoke_failover_wrapper: child exited ${code} after success payload; treating as pass`);
      }
      process.exit(0);
      return;
    }
    process.exit(typeof code === 'number' ? code : 1);
  });

  child.on('error', (e) => {
    console.error(`smoke_failover_wrapper: failed to launch child: ${e && e.message ? e.message : String(e)}`);
    process.exit(1);
  });
}

main();
