#!/usr/bin/env node
'use strict';

const { run } = require('../lib/runner.cjs');

run(process.argv.slice(2)).catch((error) => {
  const message = error && error.bootstrapFailure === true && typeof error.message === 'string'
    ? error.message
    : 'Hilo could not verify or start its native command. Reinstall or explicitly repair the package.';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
