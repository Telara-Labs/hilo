'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { createHash, createPrivateKey, createPublicKey, sign, verify } = require('node:crypto');

const root = path.join(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'lib/release-auth.cjs'), 'utf8');
const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/go-release-auth-v1.json'), 'utf8'));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const syntheticKey = recipe => createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), createHash('sha256').update(recipe, 'ascii').digest()]),
  type: 'pkcs8', format: 'der'
});
const old = syntheticKey('telara-memory npm fixture TEST ONLY v1; NEVER RELEASE');
const active = syntheticKey('unit-only-new-hardware-signing-pin');
const pem = key => createPublicKey(key).export({ type: 'spki', format: 'pem' }).toString();
assert.equal(pem(old), corpus.publicKeyPEM);
const payload = bytes => Buffer.concat([Buffer.from('telara-memory-release-v1\0', 'ascii'), bytes.build, Buffer.from([0]), bytes.sums]);
const metadata = fixture => Object.fromEntries(['build','sums','signature'].map(k => [k, Buffer.from(fixture[k], 'base64')]));
const good = corpus.fixtures.filter(f => f.nodeAccept);
const history = [{ publicKey: pem(old), manifests: good.map(f => {
  const bytes = metadata(f); return { build: hash(bytes.build), sums: hash(bytes.sums) };
}) }];

// The only key substitution occurs in an isolated test source copy. Production
// remains the unchanged compiled active pin with an empty historical list.
function fixtureVerifier(policy) {
  const pin = /^const PINNED_PUBLIC_KEY = ('[^\n]*');$/m.exec(source);
  assert.ok(pin);
  assert.equal((source.match(/const HISTORICAL_POLICY = Object\.freeze\(\[\]\);/g) || []).length, 1);
  const copy = source.replace(pin[0], `const PINNED_PUBLIC_KEY = ${JSON.stringify(pem(active))};`)
    .replace('const HISTORICAL_POLICY = Object.freeze([]);', `const HISTORICAL_POLICY = Object.freeze(${JSON.stringify(policy)});`);
  const sandbox = { module: { exports: {} }, require, Buffer };
  vm.runInNewContext(copy, sandbox);
  return sandbox.module.exports;
}

test('historical exact manifests survive a synthetic pin transition without granting old-key future authority', () => {
  assert.equal(good.length, 2);
  const auth = fixtureVerifier(history);
  for (const fixture of good) {
    const bytes = metadata(fixture);
    const expected = { version: fixture.version, family: fixture.family };
    const authenticated = auth.authenticateMetadata(bytes, expected);
    const target = auth.selectTarget(authenticated, 'linux', 'x64');
    const artifact = Buffer.from(fixture.artifacts[target.filename], 'base64');
    assert.equal(auth.verifyArtifactBytes(target, artifact), true);

    const future = { ...bytes, build: Buffer.from('{\n  "format": 1,\n  "source": "v9999.0.0",\n  "toolchain": "go1.26.1",\n  "verification": "clean-tag-export-signed",\n  "signed": true\n}\n') };
    const oldSignature = sign(null, payload(future), old);
    assert.equal(verify(null, payload(future), createPublicKey(old), oldSignature), true);
    future.signature = Buffer.from(oldSignature.toString('base64') + '\n');
    assert.throws(() => auth.authenticateMetadata(future, { ...expected, version: '9999.0.0' }), /release_verification_failed/);
    future.signature = Buffer.from(sign(null, payload(future), active).toString('base64') + '\n');
    assert.equal(auth.authenticateMetadata(future, { ...expected, version: '9999.0.0' }).version, '9999.0.0');

    const sums = Buffer.from(bytes.sums);
    sums[0] = sums[0] === 48 ? 49 : 48;
    const altered = { ...bytes, sums };
    altered.signature = Buffer.from(sign(null, payload(altered), old).toString('base64') + '\n');
    assert.throws(() => auth.authenticateMetadata(altered, expected), /release_verification_failed/);
  }
});

test('compiled historical policy rejects ambiguous and excessive authority while original pin stays unchanged', () => {
  assert.match(source, /const HISTORICAL_POLICY = Object\.freeze\(\[\]\);/);
  const pair = history[0].manifests[0];
  const other = syntheticKey('unit-only-another-historical-key');
  for (const policy of [
    [{ publicKey: pem(active), manifests: [pair] }],
    [history[0], history[0]],
    [{ publicKey: pem(old), manifests: [pair, pair] }],
    [history[0], { publicKey: pem(other), manifests: [pair] }],
    [{ publicKey: pem(old), manifests: [{ build: 'invalid', sums: pair.sums }] }],
    [{ publicKey: pem(old), manifests: [] }],
    Array(5).fill(history[0]),
    [{ publicKey: pem(old), manifests: Array(257).fill(pair) }]
  ]) assert.throws(() => fixtureVerifier(policy), /release_verification_failed/);
  const excessive = [256,256,1].map((count, group) => ({
    publicKey: pem(syntheticKey(`unit-only-history-group-${group}`)),
    manifests: Array.from({ length: count }, (_, i) => ({ build: hash(Buffer.from(`${group}/${i}`)), sums: hash(Buffer.from('exact sums')) }))
  }));
  assert.throws(() => fixtureVerifier(excessive), /release_verification_failed/);
  const production = require('../lib/release-auth.cjs');
  for (const fixture of good) assert.throws(() => production.authenticateMetadata(metadata(fixture), { version: fixture.version, family: fixture.family }), /release_verification_failed/);
});
