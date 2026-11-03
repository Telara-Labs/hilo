'use strict';

const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { spawn } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const auth = require('./release-auth.cjs');

const PACKAGE_ROOT = path.resolve(__dirname, '..');
const REPOSITORY = 'Telara-Labs/hilo';
const PUBLIC_KEY_SHA256 = '8f56b2313dfb0ce37156cec349393b230d4055bc01501fb2adfa1f3cd6c5f492';
const MAX_ARTIFACT = 512 * 1024 * 1024;
const MAX_REDIRECTS = 3;
const TOTAL_TIMEOUT_MS = 120000;
const IDLE_TIMEOUT_MS = 15000;
const LOCK_WAIT_MS = 5000;
const RELEASE_HOSTS = new Set(['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com']);
const C = fs.constants;
const READ_FLAGS = C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK;

function failure(code) {
  const message = code === 'windows_cache_acl_unverified'
    ? 'windows_cache_acl_unverified. Windows download and execution require native package/cache ACL acceptance.'
    : `${code}. Reinstall or explicitly repair the package.`;
  const err = new Error(message);
  err.bootstrapFailure = true;
  return err;
}
function reported(err) {
  if (err && err.bootstrapFailure) return err;
  if (err && err.message === 'release_verification_failed') return failure('release_verification_failed');
  return failure('package_bootstrap_failed');
}
function same(a, b) { return a.dev === b.dev && a.ino === b.ino; }
function missing(err) { return err && err.code === 'ENOENT'; }
function safeMode(st) { return (st.mode & 0o022) === 0; }
function stat(pathname) { return fs.lstatSync(pathname); }
function ownedFile(st, owner, executable) {
  return st.isFile() && st.nlink === 1 && st.uid === owner && safeMode(st) &&
    (st.mode & 0o7000) === 0 && (!executable || (st.mode & 0o111) === 0o111);
}
function ownedLock(st, owner) {
  return st.isDirectory() && st.uid === owner && (st.mode & 0o7777) === 0o700;
}
function exactFields(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(k => !Object.hasOwn(value, k))) {
    throw failure('release_spec_invalid');
  }
}

// The npm source tree is already the bootstrap trust boundary. Refuse mutable
// ancestors owned by another principal and require package/cache components to
// have the package owner. Root-owned global installs remain readable by users.
function packageGuard() {
  const rootStat = stat(PACKAGE_ROOT);
  const owner = rootStat.uid;
  if (!rootStat.isDirectory() || !safeMode(rootStat) || (rootStat.mode & 0o7000) !== 0) throw failure('package_tree_unsafe');
  const snapshots = [];
  let current = path.parse(PACKAGE_ROOT).root;
  const paths = [current];
  for (const part of PACKAGE_ROOT.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    paths.push(current);
  }
  for (const pathname of paths) {
    const st = stat(pathname);
    const stickyRoot = st.uid === 0 && (st.mode & 0o1000) !== 0 && pathname !== PACKAGE_ROOT;
    if (!st.isDirectory() || ![0, owner].includes(st.uid) || (!safeMode(st) && !stickyRoot)) throw failure('package_tree_unsafe');
    snapshots.push({ pathname, st, ancestor: pathname !== PACKAGE_ROOT });
  }
  function check() {
    for (const item of snapshots) {
      const now = stat(item.pathname);
      const stickyRoot = item.ancestor && now.uid === 0 && (now.mode & 0o1000) !== 0;
      if (!same(item.st, now) || !now.isDirectory() || now.uid !== item.st.uid ||
          (!safeMode(now) && !stickyRoot) || (!item.ancestor && (now.mode & 0o7000) !== 0)) throw failure('package_tree_changed');
    }
  }
  function directory(pathname, create) {
    check();
    let st;
    try { st = stat(pathname); }
    catch (err) {
      if (!missing(err) || !create) throw err;
      try { fs.mkdirSync(pathname, { mode: 0o700 }); }
      catch (mkdirError) { if (mkdirError.code !== 'EEXIST') throw failure('package_cache_unwritable_prefetch_required'); }
      st = stat(pathname);
    }
    if (!st.isDirectory() || st.uid !== owner || !safeMode(st) || (st.mode & 0o7000) !== 0) throw failure('package_cache_unsafe');
    snapshots.push({ pathname, st, ancestor: false });
    return st;
  }
  return { owner, check, directory };
}

function readOwned(guard, pathname, limit, executable = false) {
  guard.check();
  const before = stat(pathname);
  if (!ownedFile(before, guard.owner, executable) || before.size > limit || before.size < 0) throw failure('package_file_unsafe');
  const fd = fs.openSync(pathname, READ_FLAGS);
  try {
    const opened = fs.fstatSync(fd);
    if (!same(before, opened) || !ownedFile(opened, guard.owner, executable) || opened.size !== before.size) throw failure('package_file_changed');
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw failure('package_file_changed');
      offset += count;
    }
    const after = fs.fstatSync(fd);
    if (!same(opened, after) || !ownedFile(after, guard.owner, executable) || after.size !== opened.size ||
        after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs || !same(after, stat(pathname))) throw failure('package_file_changed');
    guard.check();
    return bytes;
  } finally { fs.closeSync(fd); }
}

function selection(guard) {
  const pkg = JSON.parse(readOwned(guard, path.join(PACKAGE_ROOT, 'package.json'), 65536).toString('utf8'));
  const raw = readOwned(guard, path.join(PACKAGE_ROOT, 'release-spec.json'), 4096);
  const spec = JSON.parse(raw.toString('utf8'));
  exactFields(spec, ['version', 'family', 'tag', 'repository']);
  const canonical = JSON.stringify({ version: spec.version, family: spec.family, tag: spec.tag, repository: spec.repository }, null, 2) + '\n';
  if (!raw.equals(Buffer.from(canonical)) || typeof pkg.version !== 'string' || pkg.version !== spec.version ||
      spec.tag !== `v${spec.version}` || spec.repository !== REPOSITORY) throw failure('release_spec_invalid');
  const release = path.join(PACKAGE_ROOT, 'release');
  guard.directory(release, false);
  // This package file is checked for staging mistakes or substitution only.
  // release-auth's embedded key remains the sole verification authority.
  const key = readOwned(guard, path.join(release, 'release-key.pub'), 1024);
  if (createHash('sha256').update(key).digest('hex') !== PUBLIC_KEY_SHA256) throw failure('release_key_mismatch');
  const manifest = auth.authenticateMetadata({
    build: readOwned(guard, path.join(release, 'BUILD.json'), 16384),
    sums: readOwned(guard, path.join(release, 'SHA256SUMS'), 4096),
    signature: readOwned(guard, path.join(release, 'RELEASE.sig'), 256)
  }, { version: spec.version, family: spec.family });
  return auth.selectTarget(manifest, process.platform, process.arch);
}

function allowedURL(url) {
  if (url.protocol !== 'https:' || url.username || url.password || url.hash ||
      (url.port && url.port !== '443') || !RELEASE_HOSTS.has(url.hostname) || url.href.length > 8192) throw failure('release_transport_refused');
}

// No caller URL, proxy configuration, credentials, global agent or Authorization
// header is accepted. Signed metadata chooses only the immutable tag and asset.
function download(target, fd) {
  const initial = new URL(`https://github.com/${REPOSITORY}/releases/download/${encodeURIComponent(target.tag)}/${encodeURIComponent(target.filename)}`);
  return new Promise((resolve, reject) => {
    let activeRequest, activeResponse, settled = false;
    const timer = setTimeout(() => finish(failure('release_download_timeout')), TOTAL_TIMEOUT_MS);
    function finish(err, result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (activeResponse) activeResponse.destroy();
      if (activeRequest) activeRequest.destroy();
      if (err) reject(err); else resolve(result);
    }
    function visit(url, redirects) {
      try { allowedURL(url); } catch (err) { finish(err); return; }
      let req;
      try {
        req = https.get(url, { agent: false, rejectUnauthorized: true,
          headers: { 'User-Agent': 'hilo-npm-bootstrap', Accept: 'application/octet-stream' } }, res => {
          if (settled) { res.destroy(); return; }
          activeResponse = res;
          if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
            const location = res.headers.location;
            if (redirects >= MAX_REDIRECTS || typeof location !== 'string' || location.length > 8192) {
              finish(failure('release_redirect_refused')); return;
            }
            let next;
            try { next = new URL(location, url); allowedURL(next); }
            catch (err) { finish(failure('release_redirect_refused')); return; }
            activeRequest = activeResponse = undefined;
            res.destroy();
            req.destroy();
            visit(next, redirects + 1);
            return;
          }
          if (res.statusCode !== 200 || (res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity')) {
            finish(failure('release_download_status')); return;
          }
          const length = res.headers['content-length'];
          let expected;
          if (length !== undefined) {
            if (typeof length !== 'string' || !/^(0|[1-9][0-9]{0,9})$/.test(length) || Number(length) > MAX_ARTIFACT) {
              finish(failure('release_download_size')); return;
            }
            expected = Number(length);
          }
          let received = 0;
          const hash = createHash('sha256');
          res.on('error', () => finish(failure('release_download_failed')));
          res.on('aborted', () => finish(failure('release_download_truncated')));
          res.on('close', () => { if (!settled && !res.complete) finish(failure('release_download_truncated')); });
          res.on('data', chunk => {
            if (settled) return;
            if (!Buffer.isBuffer(chunk) || received + chunk.length > MAX_ARTIFACT ||
                (expected !== undefined && received + chunk.length > expected)) {
              finish(failure('release_download_size')); return;
            }
            try {
              let offset = 0;
              while (offset < chunk.length) {
                const count = fs.writeSync(fd, chunk, offset, chunk.length - offset);
                if (count <= 0) throw failure('release_download_write');
                offset += count;
              }
              hash.update(chunk);
              received += chunk.length;
            } catch (err) { finish(failure('release_download_write')); }
          });
          res.on('end', () => {
            if (settled) return;
            if (!res.complete || (expected !== undefined && received !== expected)) {
              finish(failure('release_download_truncated')); return;
            }
            if (hash.digest('hex') !== target.sha256) { finish(failure('release_artifact_mismatch')); return; }
            finish(null, received);
          });
        });
      } catch (err) { finish(failure('release_download_failed')); return; }
      activeRequest = req;
      req.setTimeout(IDLE_TIMEOUT_MS, () => finish(failure('release_download_timeout')));
      req.on('error', () => { if (activeRequest === req) finish(failure('release_download_failed')); });
    }
    visit(initial, 0);
  });
}

function verifiedCache(guard, filename, target) {
  let bytes;
  try { bytes = readOwned(guard, filename, MAX_ARTIFACT, true); }
  catch (err) {
    // Absence is the sole download admission. A removed/replaced parent or
    // another unsafe component is not an absent selected file.
    if (missing(err)) {
      guard.check();
      try { stat(filename); } catch (again) { if (missing(again)) return false; throw again; }
    }
    throw err;
  }
  auth.verifyArtifactBytes(target, bytes);
  return true;
}
function syncDirectory(pathname) {
  const fd = fs.openSync(pathname, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

async function executable() {
  if (process.platform === 'win32') throw failure('windows_cache_acl_unverified');
  const guard = packageGuard();
  const target = selection(guard);
  let directory = PACKAGE_ROOT;
  for (const segment of ['.cache', target.tag, `${target.platform}-${target.arch}`, target.sha256]) {
    directory = path.join(directory, segment);
    guard.directory(directory, true);
  }
  const filename = path.join(directory, target.filename);
  if (verifiedCache(guard, filename, target)) return { filename, guard, target };
  const lock = path.join(directory, 'download.lock');
  const deadline = Date.now() + LOCK_WAIT_MS;
  let lockStat;
  for (;;) {
    guard.check();
    try { fs.mkdirSync(lock, { mode: 0o700 }); lockStat = stat(lock); break; }
    catch (err) {
      if (err.code !== 'EEXIST') throw failure('package_cache_unwritable_prefetch_required');
      const held = stat(lock);
      if (!ownedLock(held, guard.owner)) throw failure('package_cache_lock_unsafe');
      if (verifiedCache(guard, filename, target)) return { filename, guard, target };
      if (Date.now() >= deadline) throw failure('package_cache_busy');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }
  function checkLock() {
    guard.check();
    const now = stat(lock);
    if (!same(lockStat, now) || !ownedLock(now, guard.owner)) throw failure('package_cache_changed');
  }
  let temporary, temporaryStat, fd;
  try {
    checkLock();
    if (verifiedCache(guard, filename, target)) return { filename, guard, target };
    temporary = path.join(lock, `download-${randomBytes(16).toString('hex')}`);
    fd = fs.openSync(temporary, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
    temporaryStat = fs.fstatSync(fd);
    if (!ownedFile(temporaryStat, guard.owner, false)) throw failure('package_cache_temp_unsafe');
    const size = await download(target, fd);
    checkLock();
    if (!same(temporaryStat, stat(temporary))) throw failure('package_cache_changed');
    const written = fs.fstatSync(fd);
    if (!same(temporaryStat, written) || !ownedFile(written, guard.owner, false) || written.size !== size) throw failure('package_cache_changed');
    fs.fchmodSync(fd, 0o555);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    const bytes = readOwned(guard, temporary, MAX_ARTIFACT, true);
    auth.verifyArtifactBytes(target, bytes);
    checkLock();
    if (!same(temporaryStat, stat(temporary))) throw failure('package_cache_changed');
    try { fs.linkSync(temporary, filename); }
    catch (err) { if (err.code !== 'EEXIST') throw failure('package_cache_publish_failed'); }
    // link is atomic no-overwrite publication. Remove only our own second link
    // before validating the final single-link winner, including an EEXIST race.
    checkLock();
    if (!same(temporaryStat, stat(temporary))) throw failure('package_cache_changed');
    fs.unlinkSync(temporary);
    temporary = undefined;
    syncDirectory(directory);
    if (!verifiedCache(guard, filename, target)) throw failure('package_cache_publish_failed');
    return { filename, guard, target };
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    // Never reclaim another attempt's lock or its temporary file, even when
    // this attempt failed or an existing lock appears old.
    let stillOwned = false;
    try {
      guard.check();
      const now = stat(lock);
      stillOwned = same(lockStat, now) && ownedLock(now, guard.owner);
    } catch (err) { if (!missing(err) && !err.bootstrapFailure) throw err; }
    if (stillOwned) {
      if (temporary && temporaryStat) {
        try { if (same(temporaryStat, stat(temporary))) fs.unlinkSync(temporary); }
        catch (err) { if (!missing(err)) throw err; }
      }
      fs.rmdirSync(lock);
    }
  }
}

async function prefetch() {
  try {
    const { filename } = await executable();
    return filename;
  } catch (err) { throw reported(err); }
}
async function run(argv = process.argv.slice(2)) {
  if (!Array.isArray(argv) || argv.some(arg => typeof arg !== 'string')) throw failure('launcher_arguments_invalid');
  let selected;
  try { selected = await executable(); }
  catch (err) { throw reported(err); }
  // Rehash at the execution boundary. Node has no portable execute-by-open-fd
  // primitive, so this inherits the trusted package tree's principal boundary.
  try {
    if (!verifiedCache(selected.guard, selected.filename, selected.target)) throw failure('package_cache_changed');
  } catch (err) { throw reported(err); }
  return new Promise((resolve, reject) => {
    let child;
    try { child = spawn(selected.filename, argv, { shell: false, stdio: 'inherit' }); }
    catch (err) { reject(failure('native_launch_failed')); return; }
    const handlers = new Map();
    const clear = () => { for (const [signal, handler] of handlers) process.removeListener(signal, handler); };
    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
      const handler = () => { child.kill(signal); };
      handlers.set(signal, handler);
      process.on(signal, handler);
    }
    child.once('error', () => { clear(); reject(failure('native_launch_failed')); });
    child.once('exit', (code, signal) => {
      clear();
      if (signal) process.kill(process.pid, signal);
      else process.exitCode = code;
      resolve({ code, signal });
    });
  });
}

module.exports = Object.freeze({ run, prefetch });
