'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const entrypoints = {
  launcher: {
    file: path.join(__dirname, '..', 'bin', 'hilo.cjs'),
    runnerPath: '../lib/runner.cjs',
    method: 'run',
    fallback: 'Hilo could not verify or start its native command. Reinstall or explicitly repair the package.'
  },
  postinstall: {
    file: path.join(__dirname, '..', 'postinstall.cjs'),
    runnerPath: './lib/runner.cjs',
    method: 'prefetch',
    fallback: 'Hilo could not verify or prefetch its native command. Reinstall or explicitly repair the package.'
  }
};

async function invoke(entrypoint, result, argv = ['status', '--json']) {
  const source = fs.readFileSync(entrypoint.file, 'utf8');
  const output = [];
  const calls = [];
  const processStub = {
    argv: ['node', entrypoint.file, ...argv],
    stderr: { write: value => output.push(value) }
  };
  const runner = {
    run: (...args) => { calls.push(['run', ...args]); return result; },
    prefetch: (...args) => { calls.push(['prefetch', ...args]); return result; }
  };
  vm.runInNewContext(source, {
    require(specifier) {
      assert.equal(specifier, entrypoint.runnerPath);
      return runner;
    },
    process: processStub
  }, { filename: entrypoint.file });
  await new Promise(resolve => setImmediate(resolve));
  return { output: output.join(''), calls, processStub };
}

for (const [name, entrypoint] of Object.entries(entrypoints)) {
  test(`${name} calls only ${entrypoint.method} and emits nothing on success`, async () => {
    const result = await invoke(entrypoint, Promise.resolve({ code: 0 }));
    assert.equal(result.output, '');
    assert.deepEqual(result.calls.map(call => call[0]), [entrypoint.method]);
    assert.equal(result.processStub.exitCode, undefined);
  });

  test(`${name} preserves a trusted fixed runner bootstrap message`, async () => {
    const message = name === 'launcher'
      ? 'windows_cache_acl_unverified. Windows download and execution require native package/cache ACL acceptance.'
      : 'package_cache_unwritable_prefetch_required. Reinstall or explicitly repair the package.';
    const error = Object.assign(new Error(message), { bootstrapFailure: true });
    const result = await invoke(entrypoint, Promise.reject(error));
    assert.equal(result.output, `${message}\n`);
    assert.deepEqual(result.calls.map(call => call[0]), [entrypoint.method]);
    assert.equal(result.processStub.exitCode, 1);
  });

  test(`${name} hides unknown error messages and stacks behind fixed repair guidance`, async () => {
    const error = new Error('synthetic-secret-token-value');
    const result = await invoke(entrypoint, Promise.reject(error));
    assert.equal(result.output, `${entrypoint.fallback}\n`);
    assert.equal(result.output.includes('synthetic-secret-token-value'), false);
    assert.equal(result.output.includes(error.stack), false);
    assert.deepEqual(result.calls.map(call => call[0]), [entrypoint.method]);
    assert.equal(result.processStub.exitCode, 1);
  });
}

test('launcher forwards the argument array unchanged and does not call postinstall behavior', async () => {
  const args = ['install', '--release-dir', '/tmp/release bundle', '--json'];
  const result = await invoke(entrypoints.launcher, Promise.resolve({ code: 0 }), args);
  assert.deepEqual(result.calls, [['run', args]]);
  assert.deepEqual(Array.from(result.calls[0][1]), args);
  assert.equal(result.output, '');
});

test('postinstall invokes only prefetch and does not run CLI or lifecycle actions', async () => {
  const result = await invoke(entrypoints.postinstall, Promise.resolve('/cache/image'), []);
  assert.deepEqual(result.calls, [['prefetch']]);
  assert.equal(result.output, '');
  assert.equal(result.processStub.exitCode, undefined);
});
