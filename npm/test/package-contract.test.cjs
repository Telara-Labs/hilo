'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

test('private npm package has no lifecycle scripts and stages only reviewed files', () => {
  assert.equal(Object.hasOwn(pkg, 'scripts'), false);
  assert.equal(Object.hasOwn(pkg, 'version'), false);
  assert.equal(pkg.private, true);
  assert.deepEqual([...pkg.files].sort(), [
    'LICENSE',
    'README.md',
    'bin/hilo.cjs',
    'lib/release-auth.cjs',
    'lib/runner.cjs',
    'release-spec.json',
    'release/BUILD.json',
    'release/RELEASE.sig',
    'release/SHA256SUMS',
    'release/release-key.pub'
  ]);
  assert.equal(fs.existsSync(path.join(root, 'postinstall.cjs')), true);
  assert.equal(pkg.files.includes('postinstall.cjs'), false);
});

test('README places authenticated prefetch on explicit command invocation', () => {
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.match(readme, /does not run lifecycle scripts or download a native executable/i);
  assert.match(readme, /first explicit invocation of `hilo`, the launcher authenticates and prefetches/i);
});
