'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { createHash } = require('node:crypto');

const root = path.join(__dirname, '..');
const production = require('../lib/release-auth.cjs');
const source = fs.readFileSync(path.join(root, 'lib/release-auth.cjs'), 'utf8');
const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/go-release-auth-v1.json'), 'utf8'));
const pinned = /^const PINNED_PUBLIC_KEY = ('[^\n]*');$/m.exec(source);
assert.ok(pinned);
const sandbox = { module: { exports: {} }, require, Buffer };
// Test-only key substitution in an isolated source copy reuses the immutable
// Go oracle corpus. The installed production module accepts no runtime key.
vm.runInNewContext(source.replace(pinned[0], `const PINNED_PUBLIC_KEY = ${JSON.stringify(corpus.publicKeyPEM)};`), sandbox);
const oracleAuth = sandbox.module.exports;
const metadata = fixture => Object.fromEntries(['build', 'sums', 'signature'].map(key => [key, Buffer.from(fixture[key], 'base64')]));
const refuse = fn => assert.throws(fn, /release_verification_failed/);

test('Hilo package exposes one command and scopes its release repository', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.name, '@telaralabs/hilo');
  assert.deepEqual(pkg.bin, { hilo: 'bin/hilo.cjs' });
  const runner = fs.readFileSync(path.join(root, 'lib/runner.cjs'), 'utf8');
  assert.match(runner, /^const REPOSITORY = 'Telara-Labs\/hilo';$/m);
  assert.match(source, /Buffer\.from\('telara-memory-release-v1\\0', 'ascii'\)/);
  assert.deepEqual(Object.keys(production).sort(), ['authenticateMetadata', 'selectTarget', 'verifyArtifactBytes']);
});

test('Hilo and historical metadata remain authenticated and cannot alias artifact families', () => {
  const good = corpus.fixtures.filter(f => f.nodeAccept);
  assert.equal(good.length, 2);
  for (const fixture of good) {
    const bytes = metadata(fixture);
    const expected = { version: fixture.version, family: fixture.family };
    // Neither family gets a trust exception in the real pinned module.
    refuse(() => production.authenticateMetadata(bytes, expected));
    const authenticated = oracleAuth.authenticateMetadata(bytes, expected);
    const other = fixture.family === 'hilo' ? 'legacy' : 'hilo';
    refuse(() => oracleAuth.authenticateMetadata(bytes, { ...expected, family: other }));
    const target = oracleAuth.selectTarget(authenticated, 'linux', 'x64');
    const artifact = Buffer.from(fixture.artifacts[target.filename], 'base64');
    assert.equal(oracleAuth.verifyArtifactBytes(target, artifact), true);
    const foreign = good.find(f => f.family === other);
    assert.ok(foreign);
    const foreignName = `${other === 'hilo' ? 'hilo-' : 'telara-memory-'}linux-amd64`;
    const foreignBytes = Buffer.from(foreign.artifacts[foreignName], 'base64');
    // Families may authenticate the same binary digest. Such bytes are valid;
    // the family boundary is the signed metadata/selected filename above.
    if (foreignBytes.equals(artifact)) assert.equal(oracleAuth.verifyArtifactBytes(target, foreignBytes), true);
    else refuse(() => oracleAuth.verifyArtifactBytes(target, foreignBytes));
    const altered = Buffer.concat([artifact, Buffer.from('tamper')]);
    refuse(() => oracleAuth.verifyArtifactBytes(target, altered));
    // Caller mutation cannot retarget an authenticated manifest or replace
    // target identity with an identically shaped fabricated object.
    bytes.sums.fill(0);
    assert.equal(oracleAuth.selectTarget(authenticated, 'linux', 'x64').filename, target.filename);
    refuse(() => oracleAuth.verifyArtifactBytes({ ...target }, artifact));
    assert.equal(createHash('sha256').update(artifact).digest('hex'), target.sha256);
  }
});
