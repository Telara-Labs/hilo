'use strict';

const { prefetch } = require('./lib/runner.cjs');

prefetch().catch((error) => {
  const message = error && error.bootstrapFailure === true && typeof error.message === 'string'
    ? error.message
    : 'Hilo could not verify or prefetch its native command. Reinstall or explicitly repair the package.';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
