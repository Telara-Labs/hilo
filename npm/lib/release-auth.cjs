'use strict';

const { createPublicKey, verify, createHash } = require('node:crypto');

// Kept byte-for-byte equal to contract/releaseauth/release-key.pub. There is no
// runtime key argument, downloaded key, or unsigned verification mode.
const PINNED_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1wXK9aXEAqss35V5/vqINRX0MGZM1wEP/fmctFGiOi4=\n-----END PUBLIC KEY-----\n';
const KEY = createPublicKey(PINNED_PUBLIC_KEY);
const DOMAIN = Buffer.from('telara-memory-release-v1\0', 'ascii');
const MAX_ARTIFACT = 512 * 1024 * 1024;
const manifests = new WeakSet();
const targets = new WeakSet();
const PREFIXES = Object.freeze({ legacy: 'telara-memory-', hilo: 'hilo-' });
const PLATFORMS = Object.freeze({ darwin: 'darwin', linux: 'linux', win32: 'windows' });
const ARCHES = Object.freeze({ x64: 'amd64', arm64: 'arm64' });

function invalid() {
  throw new Error('release_verification_failed');
}

function exactKeys(value, names) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== names.length || names.some(name => !Object.hasOwn(value, name))) invalid();
}

function raw(value, limit) {
  if (!Buffer.isBuffer(value) || value.length === 0 || value.length > limit) invalid();
  // Take ownership of the bytes before authentication; later caller mutation
  // cannot alter the authenticated filename/digest/version association.
  return Buffer.from(value);
}

function artifactName(prefix, platform, arch) {
  return `${prefix}${platform}-${arch}${platform === 'windows' ? '.exe' : ''}`;
}

function canonicalBuild(tag) {
  return Buffer.from(`{\n  "format": 1,\n  "source": "${tag}",\n  "toolchain": "go1.26.1",\n  "verification": "clean-tag-export-signed",\n  "signed": true\n}\n`, 'ascii');
}

// The npm profile intentionally admits the exact five-field Go signer encoding,
// a subset of the general Go verifier's JSON and base64 whitespace acceptance.
function authenticateMetadata(metadata, expected) {
  exactKeys(metadata, ['build', 'sums', 'signature']);
  exactKeys(expected, ['version', 'family']);
  const { version, family } = expected;
  if (typeof version !== 'string' || version.length > 1024 ||
      !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$/.test(version) || version.trim() !== version ||
      typeof family !== 'string' || !Object.hasOwn(PREFIXES, family)) invalid();
  const build = raw(metadata.build, 16384);
  const sums = raw(metadata.sums, 4096);
  const signature = raw(metadata.signature, 256);
  const encoded = signature.toString('ascii');
  if (!/^[A-Za-z0-9+/]{86}==\n?$/.test(encoded) ||
      !signature.equals(Buffer.from(encoded, 'ascii'))) invalid();
  const base64 = encoded.endsWith('\n') ? encoded.slice(0, -1) : encoded;
  const sig = Buffer.from(base64, 'base64');
  if (sig.length !== 64 || sig.toString('base64') !== base64) invalid();
  const payload = Buffer.concat([DOMAIN, build, Buffer.from([0]), sums]);
  if (!verify(null, payload, KEY, sig)) invalid();
  const tag = `v${version}`;
  if (!build.equals(canonicalBuild(tag))) invalid();

  const prefix = PREFIXES[family];
  const allowed = new Set();
  for (const platform of ['darwin', 'linux', 'windows']) {
    for (const arch of ['amd64', 'arm64']) allowed.add(artifactName(prefix, platform, arch));
  }
  const text = sums.toString('ascii');
  if (!sums.equals(Buffer.from(text, 'ascii'))) invalid();
  const lines = (text.endsWith('\n') ? text.slice(0, -1) : text).split('\n');
  if (lines.length !== 6) invalid();
  const artifacts = Object.create(null);
  for (const line of lines) {
    const match = /^([0-9a-f]{64})  ([A-Za-z0-9.-]+)$/.exec(line);
    if (!match || !allowed.has(match[2]) || Object.hasOwn(artifacts, match[2])) invalid();
    artifacts[match[2]] = match[1];
  }
  if (Object.keys(artifacts).length !== allowed.size) invalid();
  const manifest = Object.freeze({ tag, version, family, toolchain: 'go1.26.1', artifacts: Object.freeze(artifacts) });
  manifests.add(manifest);
  return manifest;
}

function selectTarget(manifest, nodePlatform, nodeArch) {
  if (!manifests.has(manifest) || typeof nodePlatform !== 'string' || typeof nodeArch !== 'string' ||
      !Object.hasOwn(PLATFORMS, nodePlatform) || !Object.hasOwn(ARCHES, nodeArch)) invalid();
  const platform = PLATFORMS[nodePlatform];
  const arch = ARCHES[nodeArch];
  const filename = artifactName(PREFIXES[manifest.family], platform, arch);
  if (!Object.hasOwn(manifest.artifacts, filename)) invalid();
  const target = Object.freeze({ filename, sha256: manifest.artifacts[filename], tag: manifest.tag,
    version: manifest.version, family: manifest.family, platform, arch });
  targets.add(target);
  return target;
}

function verifyArtifactBytes(target, bytes) {
  if (!targets.has(target) || !Buffer.isBuffer(bytes) || bytes.length > MAX_ARTIFACT) invalid();
  if (createHash('sha256').update(bytes).digest('hex') !== target.sha256) invalid();
  return true;
}

module.exports = Object.freeze({ authenticateMetadata, selectTarget, verifyArtifactBytes });
