'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { createHash } = require('node:crypto');

const source = fs.readFileSync(path.join(__dirname, '../lib/runner.cjs'), 'utf8');
const authSource = fs.readFileSync(path.join(__dirname, '../lib/release-auth.cjs'), 'utf8');
const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/go-release-auth-v1.json')));
const pinned = /^const PINNED_PUBLIC_KEY = ('[^\n]*');$/m.exec(authSource);
assert.ok(pinned);
const productionKey = vm.runInNewContext(pinned[1]);
assert.equal(createHash('sha256').update(productionKey).digest('hex'), corpus.productionKeySha256);
// Test-key substitution is restricted to this VM copy of the verifier. Runner
// source has no public key, filesystem, platform, URL or transport override API.
const authSandbox = { module: { exports: {} }, require, Buffer };
vm.runInNewContext(authSource.replace(pinned[0], `const PINNED_PUBLIC_KEY = ${JSON.stringify(corpus.publicKeyPEM)};`), authSandbox);
const fixtureAuth = authSandbox.module.exports;

function harness(t, options = {}) {
  const fixture = corpus.fixtures.find(f => f.nodeAccept && f.family === (options.family || 'hilo'));
  assert.ok(fixture);
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hilo-runner-test-')));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'release'), { mode: 0o700 });
  const write = (name, bytes, mode = 0o600) => fs.writeFileSync(path.join(root, name), bytes, { mode });
  write('package.json', JSON.stringify({ name: '@telaralabs/hilo', version: fixture.version }));
  const spec = { version: fixture.version, family: fixture.family, tag: `v${fixture.version}`, repository: 'Telara-Labs/telara-memory' };
  write('release-spec.json', JSON.stringify(spec, null, 2) + '\n');
  for (const [name, key] of [['BUILD.json', 'build'], ['SHA256SUMS', 'sums'], ['RELEASE.sig', 'signature']]) {
    write(`release/${name}`, Buffer.from(fixture[key], 'base64'));
  }
  write('release/release-key.pub', productionKey);
  const platform = options.platform || 'linux', arch = options.arch || 'x64';
  const manifest = fixtureAuth.authenticateMetadata(Object.fromEntries(['build', 'sums', 'signature'].map(k => [k, Buffer.from(fixture[k], 'base64')])),
    { version: fixture.version, family: fixture.family });
  const target = fixtureAuth.selectTarget(manifest, platform, arch);
  const body = Buffer.from(fixture.artifacts[target.filename], 'base64');
  const selected = path.join(root, '.cache', target.tag, `${target.platform}-${target.arch}`, target.sha256, target.filename);
  const lock = path.join(path.dirname(selected), 'download.lock');
  const requests = [], spawns = [], signals = [];
  const proc = new EventEmitter();
  Object.assign(proc, { platform: options.runnerPlatform || platform, arch: options.runnerArch || arch,
    argv: ['node', 'hilo', 'original'], pid: 12345, exitCode: undefined,
    kill: (pid, signal) => { signals.push({ pid, signal }); } });
  const responses = options.responses ? [...options.responses] : [{ body }];
  const transport = {
    get(url, requestOptions, callback) {
      requests.push({ url: url.href, options: requestOptions });
      const req = new EventEmitter();
      req.destroy = () => { req.closed = true; };
      req.setTimeout = (ms, handler) => { req.idle = { ms, handler }; };
      setImmediate(() => {
        if (req.closed) return;
        const plan = responses.shift();
        if (!plan) { req.emit('error', new Error('unexpected network call')); return; }
        if (plan.error) { req.emit('error', new Error('controlled transport failure')); return; }
        if (plan.idle) { req.idle.handler(); return; }
        const res = new EventEmitter();
        Object.assign(res, { statusCode: plan.status || 200, headers: plan.headers || {}, complete: false,
          destroy: () => { res.closed = true; } });
        callback(res);
        if (res.closed) return;
        if (plan.beforeData) plan.beforeData({ root, selected, lock, req, res });
        if (plan.abort) { res.emit('aborted'); return; }
        for (const chunk of plan.chunks || [plan.body || Buffer.alloc(0)]) {
          if (res.closed) return;
          res.emit('data', chunk);
        }
        if (res.closed) return;
        res.complete = plan.complete !== false;
        res.emit('end');
      });
      return req;
    }
  };
  const native = {
    spawn(filename, argv, spawnOptions) {
      const child = new EventEmitter();
      child.kill = signal => { signals.push({ child: true, signal }); return true; };
      spawns.push({ filename, argv, options: spawnOptions, child });
      setImmediate(() => {
        if (options.childError) child.emit('error', new Error('controlled spawn failure'));
        else {
          if (options.forwardSignal) proc.emit(options.forwardSignal);
          child.emit('exit', options.childSignal ? null : (options.exitCode === undefined ? 0 : options.exitCode), options.childSignal || null);
        }
      });
      return child;
    }
  };
  const filesystem = options.fsProxy ? options.fsProxy(fs, { root, selected, lock }) : fs;
  let monotonic = 0;
  const sandbox = {
    module: { exports: {} }, Buffer, URL, __dirname: path.join(root, 'lib'), process: proc,
    require: name => {
      if (name === './release-auth.cjs') return fixtureAuth;
      if (name === 'node:https') return transport;
      if (name === 'node:child_process') return native;
      if (name === 'node:fs') return filesystem;
      return require(name);
    },
    setTimeout: options.totalTimeout ? (fn, ms) => ms === 120000 ? setImmediate(fn) : setTimeout(fn, ms) : setTimeout,
    clearTimeout: timer => { clearTimeout(timer); clearImmediate(timer); },
    Date: options.expireLock ? class extends Date { static now() { monotonic += 5001; return monotonic; } } : Date
  };
  // The small byte ceiling exists only in a private test VM to exercise actual
  // streamed-byte accounting without allocating a 512 MiB fixture.
  let testSource = source;
  if (options.smallLimit) {
    assert.match(source, /const MAX_ARTIFACT = 512 \* 1024 \* 1024;/);
    testSource = testSource.replace('const MAX_ARTIFACT = 512 * 1024 * 1024;', 'const MAX_ARTIFACT = 64;');
  }
  vm.runInNewContext(testSource, sandbox, { filename: 'TEST-ONLY-runner.cjs' });
  const cache = (bytes = body) => {
    fs.mkdirSync(path.dirname(selected), { recursive: true, mode: 0o700 });
    fs.writeFileSync(selected, bytes, { mode: 0o555 });
  };
  return { runner: sandbox.module.exports, root, write, spec, target, body, selected, lock, cache, requests, spawns, signals, proc };
}

const noDownloadOrChild = h => { assert.equal(h.requests.length, 0); assert.equal(h.spawns.length, 0); };

test('runner API has only run and prefetch and authenticates before network or execution', async t => {
  const h = harness(t);
  assert.deepEqual(Object.keys(h.runner).sort(), ['prefetch', 'run']);
  assert.ok(Object.isFrozen(h.runner));
  h.write('release/BUILD.json', Buffer.from('untrusted changed build'));
  await assert.rejects(h.runner.run([]), /release_verification_failed/);
  noDownloadOrChild(h);
});

test('runner bundled metadata is reauthenticated even when a verified cache is present', async t => {
  const h = harness(t);
  h.cache();
  assert.equal(await h.runner.prefetch(), h.selected);
  h.write('release/RELEASE.sig', Buffer.from('A'.repeat(88)));
  await assert.rejects(h.runner.run([]), /release_verification_failed/);
  noDownloadOrChild(h);
});

test('runner fixed spec, package version and pinned public key failures cannot download or launch', async t => {
  for (const kind of ['repository', 'tag', 'extra', 'duplicate', 'version', 'key', 'missing-key', 'missing-build', 'family']) {
    await t.test(kind, async t => {
      const h = harness(t);
      if (kind === 'key') h.write('release/release-key.pub', corpus.publicKeyPEM);
      else if (kind === 'missing-key') fs.unlinkSync(path.join(h.root, 'release/release-key.pub'));
      else if (kind === 'missing-build') fs.unlinkSync(path.join(h.root, 'release/BUILD.json'));
      else if (kind === 'version') h.write('package.json', JSON.stringify({ version: '9.9.9' }));
      else {
        const spec = { ...h.spec };
        if (kind === 'repository') spec.repository = 'attacker/repository';
        if (kind === 'tag') spec.tag = 'latest';
        if (kind === 'extra') spec.url = 'https://attacker.invalid/native';
        if (kind === 'family') spec.family = 'legacy';
        const raw = JSON.stringify(spec, null, 2) + '\n';
        h.write('release-spec.json', kind === 'duplicate' ? raw.replace('"tag":', '"version": "1.2.3",\n  "tag":') : raw);
      }
      await assert.rejects(h.runner.run([]));
      noDownloadOrChild(h);
    });
  }
});

test('runner both signed families select one exact target and publish immutable verified cache', async t => {
  for (const family of ['legacy', 'hilo']) {
    await t.test(family, async t => {
      const h = harness(t, { family });
      assert.equal(await h.runner.prefetch(), h.selected);
      assert.equal(h.spawns.length, 0);
      assert.deepEqual(fs.readFileSync(h.selected), h.body);
      const st = fs.lstatSync(h.selected);
      assert.equal(st.nlink, 1);
      assert.equal(st.mode & 0o7777, 0o555);
      assert.equal(fs.existsSync(h.lock), false);
      assert.deepEqual(fs.readdirSync(path.dirname(h.selected)), [h.target.filename]);
      assert.equal(h.requests[0].url, `https://github.com/Telara-Labs/telara-memory/releases/download/v1.2.3/${h.target.filename}`);
      assert.equal(h.requests[0].options.agent, false);
      assert.equal(h.requests[0].options.rejectUnauthorized, true);
    });
  }
});

test('runner offline cache is reverified on every use and corrupt existing bytes never trigger fallback', async t => {
  const h = harness(t);
  h.cache();
  assert.equal(await h.runner.prefetch(), h.selected);
  noDownloadOrChild(h);
  fs.chmodSync(h.selected, 0o600);
  fs.writeFileSync(h.selected, Buffer.from('corrupt existing executable'));
  fs.chmodSync(h.selected, 0o555);
  await assert.rejects(h.runner.run([]), /release_verification_failed/);
  noDownloadOrChild(h);
  assert.equal(fs.readFileSync(h.selected, 'utf8'), 'corrupt existing executable');
});

test('runner refuses cache symlink hardlink types unsafe modes and changed parent without execution', async t => {
  for (const kind of ['symlink', 'hardlink', 'directory', 'mode', 'setuid', 'parent']) {
    await t.test(kind, async t => {
      const h = harness(t);
      h.cache();
      if (kind === 'symlink') {
        const original = h.selected + '.original';
        fs.renameSync(h.selected, original);
        fs.symlinkSync(original, h.selected);
      }
      if (kind === 'hardlink') fs.linkSync(h.selected, h.selected + '.extra');
      if (kind === 'directory') { fs.unlinkSync(h.selected); fs.mkdirSync(h.selected, { mode: 0o700 }); }
      if (kind === 'mode') fs.chmodSync(h.selected, 0o577);
      if (kind === 'setuid') fs.chmodSync(h.selected, 0o4555);
      if (kind === 'parent') fs.chmodSync(path.dirname(h.selected), 0o777);
      await assert.rejects(h.runner.run([]));
      noDownloadOrChild(h);
    });
  }
});

test('runner HTTPS redirects stay on explicit hosts and never carry auth or credentials', async t => {
  const h = harness(t, { responses: [
    { status: 302, headers: { location: 'https://release-assets.githubusercontent.com/owned-asset?token=opaque' } },
    { status: 307, headers: { location: 'https://objects.githubusercontent.com/owned-asset' } },
    // Exact fixture bytes, not an external artifact.
    { body: Buffer.from(corpus.fixtures.find(f => f.name === 'hilo-valid').artifacts['hilo-linux-amd64'], 'base64') }
  ] });
  await h.runner.prefetch();
  assert.equal(h.requests.length, 3);
  for (const request of h.requests) {
    assert.equal(new URL(request.url).protocol, 'https:');
    assert.equal(new URL(request.url).username, '');
    assert.equal(new URL(request.url).password, '');
    assert.equal(request.options.auth, undefined);
    assert.equal(request.options.headers.Authorization, undefined);
    assert.equal(request.options.headers.authorization, undefined);
    assert.equal(request.options.agent, false);
  }
});

test('runner refuses downgrade unknown credentialed port fragment and excessive redirects', async t => {
  for (const destination of ['http://github.com/a', 'https://attacker.invalid/a', 'https://user:pass@github.com/a',
    'https://github.com:8443/a', 'https://github.com/a#fragment', 'https://github.com./a']) {
    await t.test(destination, async t => {
      const h = harness(t, { responses: [{ status: 302, headers: { location: destination } }] });
      await assert.rejects(h.runner.run([]), /release_redirect_refused/);
      assert.equal(h.requests.length, 1);
      assert.equal(h.spawns.length, 0);
      assert.equal(fs.existsSync(h.selected), false);
      assert.equal(fs.existsSync(h.lock), false);
    });
  }
  const h = harness(t, { responses: Array.from({ length: 4 }, () => ({ status: 302, headers: { location: 'https://github.com/loop' } })) });
  await assert.rejects(h.runner.prefetch(), /release_redirect_refused/);
  assert.equal(h.requests.length, 4);
});

test('runner bounds status size streamed bytes truncation idle total deadline and transport failure', async t => {
  const cases = [
    ['status', { responses: [{ status: 404 }] }],
    ['encoding', { responses: [{ headers: { 'content-encoding': 'gzip' } }] }],
    ['header-size', { responses: [{ headers: { 'content-length': '536870913' } }] }],
    ['actual-size', { smallLimit: true, responses: [{ chunks: [Buffer.alloc(40), Buffer.alloc(40)] }] }],
    ['truncated-header', { responses: [{ headers: { 'content-length': '9' }, body: Buffer.from('short') }] }],
    ['truncated-stream', { responses: [{ body: Buffer.from('short'), complete: false }] }],
    ['aborted', { responses: [{ abort: true }] }],
    ['idle', { responses: [{ idle: true }] }],
    ['total', { totalTimeout: true }],
    ['transport', { responses: [{ error: true }] }],
    ['hash', { responses: [{ body: Buffer.from('wrong artifact') }] }]
  ];
  for (const [name, options] of cases) {
    await t.test(name, async t => {
      const h = harness(t, options);
      await assert.rejects(h.runner.run([]));
      assert.equal(h.spawns.length, 0);
      assert.equal(fs.existsSync(h.selected), false);
      assert.equal(fs.existsSync(h.lock), false);
      assert.deepEqual(fs.readdirSync(path.dirname(h.selected)), []);
    });
  }
});

test('runner preserves other locks and uses a verified concurrent winner without overwriting it', async t => {
  for (const winner of ['good', 'corrupt']) {
    await t.test(winner, async t => {
      let linked = false;
      const h = harness(t, { fsProxy: (actual, state) => new Proxy(actual, {
        get(object, prop) {
          if (prop !== 'linkSync') return object[prop];
          return (from, to) => {
            assert.equal(linked, false);
            linked = true;
            actual.writeFileSync(to, winner === 'good' ? fs.readFileSync(from) : Buffer.from('foreign corrupt winner'), { mode: 0o555 });
            return actual.linkSync(from, to);
          };
        }
      }) });
      if (winner === 'good') assert.equal(await h.runner.prefetch(), h.selected);
      else await assert.rejects(h.runner.prefetch(), /release_verification_failed/);
      assert.equal(h.spawns.length, 0);
      assert.equal(fs.existsSync(h.lock), false);
      assert.equal(fs.lstatSync(h.selected).nlink, 1);
      if (winner === 'corrupt') assert.equal(fs.readFileSync(h.selected, 'utf8'), 'foreign corrupt winner');
    });
  }
  const h = harness(t, { expireLock: true });
  fs.mkdirSync(h.lock, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(h.lock, 'other-attempt'), 'must remain');
  await assert.rejects(h.runner.prefetch(), /package_cache_busy/);
  assert.equal(fs.readFileSync(path.join(h.lock, 'other-attempt'), 'utf8'), 'must remain');
  noDownloadOrChild(h);
});

test('runner rejects cache parent replacement during download and retains another attempt artifacts', async t => {
  let moved;
  const h = harness(t, { responses: [{
    body: Buffer.from(corpus.fixtures.find(f => f.name === 'hilo-valid').artifacts['hilo-linux-amd64'], 'base64'),
    beforeData: ({ root }) => {
      moved = path.join(root, '.cache-old');
      fs.renameSync(path.join(root, '.cache'), moved);
      fs.mkdirSync(path.join(root, '.cache'), { mode: 0o700 });
      fs.writeFileSync(path.join(root, '.cache', 'foreign'), 'must remain');
    }
  }] });
  await assert.rejects(h.runner.run([]), /package_tree_changed/);
  assert.equal(h.spawns.length, 0);
  assert.equal(fs.existsSync(h.selected), false);
  assert.equal(fs.readFileSync(path.join(h.root, '.cache', 'foreign'), 'utf8'), 'must remain');
  assert.equal(fs.existsSync(moved), true);
});

test('runner lock permission mutation refuses publication and leaves ambiguous attempt untouched', async t => {
  const h = harness(t, { responses: [{
    body: Buffer.from(corpus.fixtures.find(f => f.name === 'hilo-valid').artifacts['hilo-linux-amd64'], 'base64'),
    beforeData: ({ lock }) => fs.chmodSync(lock, 0o777)
  }] });
  await assert.rejects(h.runner.run([]), /package_cache_changed/);
  assert.equal(h.spawns.length, 0);
  assert.equal(fs.existsSync(h.selected), false);
  assert.equal(fs.lstatSync(h.lock).mode & 0o7777, 0o777);
  assert.equal(fs.readdirSync(h.lock).length, 1);
});

test('runner missing readonly cache fails visibly without writable global or temp fallback', async t => {
  const h = harness(t, { fsProxy: (actual, state) => new Proxy(actual, {
    get(object, prop) {
      if (prop !== 'mkdirSync') return object[prop];
      return (pathname, options) => {
        if (pathname === path.join(state.root, '.cache')) throw Object.assign(new Error('controlled readonly package'), { code: 'EACCES' });
        return object.mkdirSync(pathname, options);
      };
    }
  }) });
  await assert.rejects(h.runner.run([]), /package_cache_unwritable_prefetch_required/);
  noDownloadOrChild(h);
  assert.equal(fs.existsSync(path.join(h.root, '.cache')), false);
});

test('runner explicit Windows gate prevents download cache mutation and native execution', async t => {
  const h = harness(t, { platform: 'win32', arch: 'arm64' });
  await assert.rejects(h.runner.run([]), /windows_cache_acl_unverified/);
  noDownloadOrChild(h);
  assert.equal(fs.existsSync(path.join(h.root, '.cache')), false);
});

test('runner unsupported OS or CPU has no emulation or PATH fallback', async t => {
  for (const options of [{ runnerPlatform: 'freebsd' }, { runnerArch: 'ia32' }, { runnerArch: 'arm' }]) {
    const h = harness(t, options);
    await assert.rejects(h.runner.run([]), /release_verification_failed/);
    noDownloadOrChild(h);
    assert.equal(fs.existsSync(path.join(h.root, '.cache')), false);
  }
});

test('runner unchanged argv inherited stdio no shell and exact status reach either alias caller', async t => {
  const h = harness(t, { exitCode: 17 });
  h.cache();
  const args = ['task', '--text', 'spaces ; $HOME `command`', '', '--json'];
  const result = await h.runner.run(args);
  assert.equal(result.code, 17);
  assert.equal(h.proc.exitCode, 17);
  assert.equal(h.spawns.length, 1);
  assert.equal(h.spawns[0].filename, h.selected);
  assert.equal(h.spawns[0].argv, args);
  assert.deepEqual({ ...h.spawns[0].options }, { shell: false, stdio: 'inherit' });
  assert.equal(h.requests.length, 0);
  assert.equal(h.proc.listenerCount('SIGINT'), 0);
  // The future hilo and telara-memory bin entries import this identical module.
  await h.runner.run(['--version']);
  assert.equal(h.spawns[1].filename, h.selected);
});

test('runner forwards signals then preserves native terminating signal and clears handlers', async t => {
  const h = harness(t, { forwardSignal: 'SIGTERM', childSignal: 'SIGTERM' });
  h.cache();
  await h.runner.run([]);
  assert.deepEqual(h.signals, [{ child: true, signal: 'SIGTERM' }, { pid: 12345, signal: 'SIGTERM' }]);
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) assert.equal(h.proc.listenerCount(signal), 0);
});

test('runner spawn errors and invalid argv fail without shell fallback or signal leaks', async t => {
  const h = harness(t, { childError: true });
  h.cache();
  await assert.rejects(h.runner.run([null]), /launcher_arguments_invalid/);
  assert.equal(h.spawns.length, 0);
  await assert.rejects(h.runner.run([]), /native_launch_failed/);
  assert.equal(h.spawns.length, 1);
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) assert.equal(h.proc.listenerCount(signal), 0);
});
