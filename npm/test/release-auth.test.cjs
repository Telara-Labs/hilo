'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');
const production = require('../lib/release-auth.cjs');

// No JS signing oracle. Missing Go-generated fixed bytes is an explicit failure,
// never a skip or an invitation to generate signatures with this implementation.
const fixturePath = path.join(__dirname, 'fixtures/go-release-auth-v1.json');
assert.ok(fs.existsSync(fixturePath), 'Go fixture corpus pending. Run the admitted Go oracle and retain its receipt before Node tests.');
const corpus = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
assert.equal(corpus.schema, 'telara.npm.releaseauth.go-fixtures.v1');
assert.match(corpus.testOnlySeedRecipe, /TEST ONLY/);
const sourcePath = path.join(__dirname, '../lib/release-auth.cjs');
const source = fs.readFileSync(sourcePath, 'utf8');
const pinnedMatch = /^const PINNED_PUBLIC_KEY = ('[^\n]*');$/m.exec(source);
assert.ok(pinnedMatch, 'test harness must identify exactly one fixed production key literal');
const pinnedPEM = vm.runInNewContext(pinnedMatch[1]);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(hash(Buffer.from(pinnedPEM)), corpus.productionKeySha256);
assert.notEqual(corpus.publicKeyPEM, pinnedPEM);

// Key substitution exists only in this test file and in an isolated VM copy.
// The actual production module has no key parameter/export or test mode.
const sandbox = { module: { exports: {} }, require, Buffer };
const testSource = source.replace(pinnedMatch[0], `const PINNED_PUBLIC_KEY = ${JSON.stringify(corpus.publicKeyPEM)};`);
vm.runInNewContext(testSource, sandbox, { filename: 'TEST-ONLY-release-auth.cjs' });
const fixtureAuth = sandbox.module.exports;
const raw = fixture => Object.fromEntries(['build', 'sums', 'signature'].map(name => [name, Buffer.from(fixture[name], 'base64')]));
const expected = fixture => ({ version: fixture.version, family: fixture.family });
const refused = fn => assert.throws(fn, /release_verification_failed/);
const good = corpus.fixtures.filter(fixture => fixture.nodeAccept);

test('production API is pinned and rejects every TEST-ONLY fixture key', () => {
  assert.deepEqual(Object.keys(production).sort(), ['authenticateMetadata', 'selectTarget', 'verifyArtifactBytes']);
  assert.ok(Object.isFrozen(production));
  assert.equal(good.length, 2);
  for (const fixture of good) refused(() => production.authenticateMetadata(raw(fixture), expected(fixture)));
});

test('fixed independently Go-verified corpus covers both families and signed negative metadata', () => {
  assert.ok(corpus.fixtures.length >= 40);
  for (const fixture of corpus.fixtures) {
    const metadata = raw(fixture);
    for (const name of ['build', 'sums', 'signature']) assert.equal(hash(metadata[name]), fixture.hashes[name], fixture.name);
    if (fixture.nodeAccept) {
      assert.equal(fixture.goAccept, true, fixture.name);
      const manifest = fixtureAuth.authenticateMetadata(metadata, expected(fixture));
      assert.equal(manifest.tag, `v${fixture.version}`);
      assert.equal(manifest.family, fixture.family);
      assert.ok(Object.isFrozen(manifest));
      assert.ok(Object.isFrozen(manifest.artifacts));
      assert.equal(Object.getPrototypeOf(manifest.artifacts), null);
    } else {
      refused(() => fixtureAuth.authenticateMetadata(metadata, expected(fixture)));
    }
  }
  for (const suffix of ['noncanonical-json', 'duplicate-json', 'case-json', 'base64-whitespace', 'base64-pad-bits']) {
    const fixtures = corpus.fixtures.filter(fixture => fixture.name.endsWith(suffix));
    assert.equal(fixtures.length, 2);
    for (const fixture of fixtures) assert.equal(fixture.goAccept, true, fixture.name);
  }
});

test('every selected target binds family, platform, version and independently hashed Go artifact', () => {
  for (const fixture of good) {
    const manifest = fixtureAuth.authenticateMetadata(raw(fixture), expected(fixture));
    for (const [nodePlatform, platform] of [['darwin', 'darwin'], ['linux', 'linux'], ['win32', 'windows']]) {
      for (const [nodeArch, arch] of [['x64', 'amd64'], ['arm64', 'arm64']]) {
        const selected = fixtureAuth.selectTarget(manifest, nodePlatform, nodeArch);
        const prefix = fixture.family === 'hilo' ? 'hilo-' : 'telara-memory-';
        assert.equal(selected.filename, `${prefix}${platform}-${arch}${platform === 'windows' ? '.exe' : ''}`);
        assert.equal(selected.platform, platform);
        assert.equal(selected.arch, arch);
        assert.equal(selected.tag, 'v1.2.3');
        assert.equal(selected.version, '1.2.3');
        assert.equal(selected.family, fixture.family);
        assert.ok(Object.isFrozen(selected));
        const body = Buffer.from(fixture.artifacts[selected.filename], 'base64');
        assert.equal(selected.sha256, hash(body));
        assert.equal(fixtureAuth.verifyArtifactBytes(selected, body), true);
        const changed = Buffer.from(body);
        changed[0] ^= 1;
        refused(() => fixtureAuth.verifyArtifactBytes(selected, changed));
        refused(() => fixtureAuth.verifyArtifactBytes({ ...selected }, body));
      }
    }
    for (const [os, arch] of [['windows', 'x64'], ['win32', 'ia32'], ['linux', 'arm'], ['freebsd', 'x64'], ['__proto__', 'x64'], ['darwin', 'toString']]) {
      refused(() => fixtureAuth.selectTarget(manifest, os, arch));
    }
    refused(() => fixtureAuth.selectTarget({ ...manifest }, 'linux', 'x64'));
    refused(() => production.selectTarget(manifest, 'linux', 'x64'));
  }
});

test('one-byte mutations of raw metadata never pass and authenticated results own their values', () => {
  for (const fixture of good) {
    for (const name of ['build', 'sums', 'signature']) {
      const metadata = raw(fixture);
      metadata[name][0] ^= 1;
      refused(() => fixtureAuth.authenticateMetadata(metadata, expected(fixture)));
    }
    const metadata = raw(fixture);
    const manifest = fixtureAuth.authenticateMetadata(metadata, expected(fixture));
    const selected = fixtureAuth.selectTarget(manifest, 'linux', 'x64');
    for (const name of ['build', 'sums', 'signature']) metadata[name].fill(0);
    assert.equal(fixtureAuth.verifyArtifactBytes(selected, Buffer.from(fixture.artifacts[selected.filename], 'base64')), true);
  }
});

test('metadata bounds, exact caller contract, version, family and signature encoding fail closed', () => {
  const fixture = good[0];
  for (const [name, max] of [['build', 16384], ['sums', 4096], ['signature', 256]]) {
    for (const value of [null, '', Buffer.alloc(0), Buffer.alloc(max + 1)]) {
      refused(() => fixtureAuth.authenticateMetadata({ ...raw(fixture), [name]: value }, expected(fixture)));
    }
  }
  for (const version of ['', 'v1.2.3', '1.2.3\n', '1.2.3+build', '9.9.9', null]) {
    refused(() => fixtureAuth.authenticateMetadata(raw(fixture), { version, family: fixture.family }));
  }
  for (const family of ['', 'other', 'hilo', '__proto__', null]) {
    refused(() => fixtureAuth.authenticateMetadata(raw(fixture), { version: '1.2.3', family }));
  }
  refused(() => fixtureAuth.authenticateMetadata({ ...raw(fixture), publicKey: corpus.publicKeyPEM }, expected(fixture)));
  refused(() => fixtureAuth.authenticateMetadata(raw(fixture), { ...expected(fixture), key: corpus.publicKeyPEM }));
  for (const signature of [Buffer.from('!'.repeat(88)), Buffer.from(raw(fixture).signature.toString().trimEnd() + '\n\n'), Buffer.from('A'.repeat(88))]) {
    refused(() => fixtureAuth.authenticateMetadata({ ...raw(fixture), signature }, expected(fixture)));
  }
});
