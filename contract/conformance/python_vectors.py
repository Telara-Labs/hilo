#!/usr/bin/env python3
"""Independent V1-V7 reference runner. No Go or service subprocesses.

V6 (key operations, possession bootstrap, deterministic key state) and V7
(validity across rotation and revocation) reimplement contract sections
4.3-4.6 from the signed bytes in v06-v07-keyring.json and compare against the
committed expected document. --results writes the canonical result bytes.
The possession-bootstrap vector in testdata/v06-possession-bootstrap.json is
checked with the same keyring: every case status and every arrival order of
the bootstrap ops.
"""
import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
parser = argparse.ArgumentParser()
parser.add_argument('--deps', help='Optional isolated pip --target directory')
parser.add_argument('--results', help='Write the canonical V6/V7 result document to this path')
args = parser.parse_args()
if args.deps:
    sys.path.insert(0, args.deps)
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
ROOT = Path(__file__).resolve().parents[1] / 'testdata'
def load(name):
    return json.loads((ROOT / name).read_text())
def canon(value):
    return rfc8785.dumps(value)
def digest(raw):
    return hashlib.sha256(raw).hexdigest()
def H(tag, *parts):
    return digest(canon(['mnc1', tag, *parts]))
def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')
def strict(raw):
    text = raw.decode('utf8', errors='strict')
    def pairs(values):
        out = {}
        for key, value in values:
            if key in out:
                raise ValueError('duplicate_key')
            out[key] = value
        return out
    value = json.loads(text, object_pairs_hook=pairs)
    def check(v):
        if isinstance(v, str):
            for c in v:
                n = ord(c)
                if 0xD800 <= n <= 0xDFFF or 0xFDD0 <= n <= 0xFDEF or n & 0xFFFF in (0xFFFE, 0xFFFF):
                    raise ValueError('invalid Unicode scalar')
        elif isinstance(v, dict):
            for k, x in v.items(): check(k); check(x)
        elif isinstance(v, list):
            for x in v: check(x)
    check(value)
    return value
for case in load('v01-jcs.json'):
    raw = base64.b64decode(case['raw_base64']) if 'raw_base64' in case else case['raw'].encode()
    try:
        result = canon(strict(raw))
    except (ValueError, UnicodeError):
        assert 'error' in case, case['name']
        continue
    assert 'error' not in case, case['name']
    assert result == case['canonical'].encode(), case['name']
    if case.get('noncanonical'): assert result != raw
print('V1 PASS')
f = load('v02-identity.json')
sk = 'sk1:' + H('sk1', 'claude-code', 'local', 'native-7')
assert sk == f['session_global']
assert 'sk1:' + H('sk1', 'claude-code', 'local', f['machine'] + '/native-7') == f['session_local']
assert 'r1:' + digest(b'github.com/acme/api') == f['repo']
anchor = canon({'native_item_id':'item-1', 'inner':2, 'part':0}).decode()
assert 'ev1:' + H('ev1', sk, 'tool_call', anchor) == f['event_inner2']
assert H('test', 'one', 'two') == f['h']
print('V2 PASS')
for f in load('v03-records.json'):
    header, body = f['HeaderJCS'].encode(), f['BodyJCS'].encode()
    assert canon(strict(header)) == header and canon(strict(body)) == body
    assert digest(header) == f['ID'] and digest(body) == f['Digest']
    h = json.loads(header)
    assert h['v'] == 3
    assert h['body']['digest'] == f['Digest'] and h['body']['size'] == len(body)
    assert 'subj' in h and 'trust' in h and 'epoch' in h['red'] and 'findings' in h['red']
print('V3 PASS')
f = load('v04-salt.json')
assert b64(bytes.fromhex(f['test_entropy_hex'])) == f['salt']
assert len(bytes.fromhex(f['test_entropy_hex'])) == 16
# These are explicitly public independent TEST-ONLY byte inputs, never a
# production key/id/content-based salt-generation recipe.
ef = load('v04-events.json')
event = ef['event']
assert b64(bytes.fromhex(ef['test_nonce_hex'])) == event['salt']
revision_input = {k:v for k,v in event.items() if k != 'revision'}
assert H('event-rev', event['id'], canon(revision_input).decode()) == event['revision']
if event.get('text', {}).get('digest'):
    text = event['text']
    key = base64.urlsafe_b64decode(event['salt'] + '==')
    assert hmac.new(key, canon(['mnc3-event-text', text['body']]), hashlib.sha256).hexdigest() == text['digest']
kf = load('v04-keyed-text.json')
event = kf['event']
key = bytes.fromhex(kf['test_entropy_hex'])
assert b64(key) == event['salt']
assert hmac.new(key, canon(['mnc3-event-text', kf['full_redacted_text']]), hashlib.sha256).hexdigest() == event['text']['digest']
assert H('event-rev', event['id'], canon({k:v for k,v in event.items() if k != 'revision'}).decode()) == event['revision']
print('V4 PASS')
f = load('v05-signature.json')
header = f['header_jcs'].encode()
h = json.loads(header)
assert canon(h) == header and h['v'] == 3
assert hashlib.sha256(header).hexdigest() == f['record_id']
assert h['author']['key_id'] == f['signature']['key_id']
body = f['body_jcs'].encode()
assert canon(json.loads(body)) == body
assert hashlib.sha256(body).hexdigest() == h['body']['digest'] and len(body) == h['body']['size']
msg = b'mnc/v1/record\x00' + bytes.fromhex(f['record_id'])
assert msg.hex() == f['message_hex']
signature = base64.urlsafe_b64decode(f['signature']['value'] + '==')
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(f['pub_hex']))
assert hashlib.sha256(bytes.fromhex(f['pub_hex'])).hexdigest()[:32] == f['signature']['key_id']
assert f['signature']['alg'] == 'ed25519' and f['signature']['ctx'] == 'mnc/v1/record'
pub.verify(signature, msg)
try:
    pub.verify(signature, b'mnc/v1/bundle\x00' + bytes.fromhex(f['record_id']))
except InvalidSignature:
    pass
else:
    raise AssertionError('cross-context signature accepted')
bad=bytearray(signature); bad[63] |= 0x80
try:
    pub.verify(bytes(bad), msg)
except InvalidSignature:
    pass
else:
    raise AssertionError('malleated signature accepted')
print('V5 PASS')

worked = load('v03-worked-example.json')
assert digest(worked['header_jcs'].encode()) == worked['id']
assert digest(worked['body_jcs'].encode()) == worked['digest']
assert len(worked['body_jcs'].encode()) == worked['size'] == 86
bundle = load('v20-exposures.json')
manifest = strict(bundle['manifest_jcs'].encode())
assert canon(manifest) == bundle['manifest_jcs'].encode()
items = b''.join(line.encode() + b'\n' for line in bundle['facts_jcs'])
assert digest(items) == manifest['items_digest']
unsigned = {k:v for k,v in manifest.items() if k != 'sigs'}
pub.verify(base64.urlsafe_b64decode(manifest['sigs'][0]['value'] + '=='), b'mnc/v1/bundle\x00' + bytes.fromhex(digest(canon(unsigned))))
assert manifest['bundle'] == 'mnc/3'
for line in bundle['facts_jcs']:
    assert canon(strict(line.encode())) == line.encode()
print('Worked examples and signed exposure manifest PASS')
# Historical artifacts retain original byte/hash/signature semantics, while
# strict major-3 admission refuses them. Never relabel these protected major-3.
for old in json.loads((ROOT/'historical-mnc2/v03-records.json').read_text()):
    assert json.loads(old['HeaderJCS'])['v'] == 2
    assert digest(old['HeaderJCS'].encode()) == old['ID']
    assert digest(old['BodyJCS'].encode()) == old['Digest']
print('Historical major-2 integrity PASS')

# ---- V6/V7: keyring and validity (contract sections 4.3-4.6) ----
HEX64 = re.compile(r'^[0-9a-f]{64}$')
HEX32 = re.compile(r'^[0-9a-f]{32}$')
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
UUID4 = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
TOKEN = re.compile(r'^[A-Za-z0-9._:+/-]{1,128}$')
B64URL = re.compile(r'^[A-Za-z0-9_-]*$')
CTX_RECORD, CTX_RECEIPT = 'mnc/v1/record', 'mnc/v1/receipt'
KEY_OPS = {'genesis', 'device_add', 'device_rotate', 'device_revoke', 'tenant_key', 'tenant_key_rotate'}
REVOKE_REASONS = {'compromised', 'lost', 'user_request'}
PROVENANCES = {'pinned-tls-login', 'authenticated-admission'}
MATRIX = {tuple(row) for row in load('v15-matrix.json')['allowed']}
KINDS = {row[2] for row in MATRIX}


class Rejected(Exception):
    """Admission refusal. quarantine marks unsupported-but-retained input."""
    def __init__(self, why, quarantine=False):
        super().__init__(why)
        self.quarantine = quarantine


def b64strict(value, size):
    if not isinstance(value, str) or not B64URL.match(value) or len(value) % 4 == 1:
        return None
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    if len(raw) != size or b64(raw) != value:
        return None
    return raw


def key_id(pub):
    return hashlib.sha256(pub).hexdigest()[:32]


def verify_sig(pub, ctx, msg, s):
    if s.get('alg') != 'ed25519' or s.get('ctx') != ctx or s.get('key_id') != key_id(pub):
        return False
    raw = b64strict(s.get('value'), 64)
    if raw is None:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(raw, msg)
    except InvalidSignature:
        return False
    return True


def record_message(rid):
    if not HEX64.match(rid):
        raise Rejected('record id')
    return CTX_RECORD.encode() + b'\x00' + bytes.fromhex(rid)


def parse_record(header_s, body_s, want_id=''):
    header = header_s.encode()
    try:
        if canon(strict(header)) != header:
            raise Rejected('header not canonical')
    except (ValueError, UnicodeError):
        raise Rejected('header not canonical')
    h = json.loads(header)
    v = h.get('v')
    if not isinstance(v, int) or isinstance(v, bool):
        raise Rejected('header v')
    if v > 3:
        raise Rejected('future major', True)
    if v != 3:
        raise Rejected('unsupported major')
    rid = digest(header)
    if want_id and want_id != rid:
        raise Rejected('advisory id mismatch')
    if h.get('type') not in KINDS:
        raise Rejected('unknown kind', True)
    author = h.get('author', {})
    if not HEX32.match(author.get('key_id', '')) or ('machine_id' in author and not UUID4.match(author['machine_id'])):
        raise Rejected('author')
    if not isinstance(h.get('at'), int) or h['at'] <= 0:
        raise Rejected('at')
    body = None
    if body_s is not None:
        raw = body_s.encode()
        try:
            if canon(strict(raw)) != raw:
                raise Rejected('body not canonical')
        except (ValueError, UnicodeError):
            raise Rejected('body not canonical')
        ref = h.get('body')
        if not ref or ref.get('digest') != digest(raw) or ref.get('size') != len(raw):
            raise Rejected('body reference')
        body = json.loads(raw)
    if h['type'] == 'key_op':
        if body is None or h.get('prov') != 'user':
            raise Rejected('key_op shape')
        check_key_body(body)
        if h.get('lid') != H('key', body['subject']['key_id']):
            raise Rejected('key_op lid')
    return rid, h, body


def check_key_body(b):
    allowed = {'op', 'subject', 'reason', 'previous', 'genesis', 'parents'}
    if not isinstance(b, dict) or set(b) - allowed or 'op' not in b or 'subject' not in b:
        raise Rejected('key_op members')
    for k in ('reason', 'previous', 'genesis', 'parents'):
        if k in b and not b[k]:
            raise Rejected('empty optional member present')
    s = b['subject']
    if not isinstance(s, dict) or set(s) - {'key_id', 'alg', 'pub', 'role', 'machine_id'} or ('machine_id' in s and not s['machine_id']):
        raise Rejected('subject members')
    op, role, parents = b['op'], s.get('role'), b.get('parents', [])
    if op not in KEY_OPS:
        raise Rejected('op')
    pub = b64strict(s.get('pub', ''), 32)
    if s.get('alg') != 'ed25519' or not HEX32.match(s.get('key_id', '')) or pub is None or key_id(pub) != s['key_id']:
        raise Rejected('subject key')
    if role not in ('device', 'service', 'policy'):
        raise Rejected('role')
    if (role == 'device') != ('machine_id' in s) or ('machine_id' in s and not UUID4.match(s['machine_id'])):
        raise Rejected('machine')
    if 'previous' in b and not HEX32.match(b['previous']):
        raise Rejected('previous')
    if len(parents) > 16 or len(set(parents)) != len(parents) or not all(HEX64.match(x) for x in parents):
        raise Rejected('parents')
    if (op in ('genesis', 'tenant_key')) != (len(parents) == 0):
        raise Rejected('root parents')
    genesis = b.get('genesis', '')
    if op in ('genesis', 'device_add', 'device_rotate', 'device_revoke'):
        if role != 'device' or not HEX32.match(genesis) or (op == 'genesis' and genesis != s['key_id']):
            raise Rejected('device genesis')
    else:
        if role == 'device' or not TOKEN.match(genesis):
            raise Rejected('tenant')
    if (op in ('device_rotate', 'tenant_key_rotate')) != ('previous' in b):
        raise Rejected('previous for rotations')
    if (op == 'device_revoke') != ('reason' in b) or ('reason' in b and b['reason'] not in REVOKE_REASONS):
        raise Rejected('reason')


def issuer_valid(i, role):
    return bool(i) and i.get('tenant', '') != '' and i.get('role') == role and i.get('provenance') in PROVENANCES


def binding(role, domain, kid):
    return H('authority', role, domain, kid)


class Op:
    def __init__(self, x):
        self.id, self.h, self.b = parse_record(x['header_jcs'], x['body_jcs'])
        self.sigs = x.get('sigs') or []
        self.from_login = x.get('from_login', False)
        self.issuer = x.get('issuer') or {}
        self.seq = x.get('admitted_seq', 0)
        self.receipt = x.get('receipt')
        self.receipt_issuer = x.get('receipt_issuer') or {}
        self.check_shape()

    def subject(self):
        return self.b['subject']

    def subject_binding(self):
        return binding(self.subject()['role'], self.b.get('genesis', ''), self.subject()['key_id'])

    def sig_by(self, kid):
        for s in self.sigs:
            if s.get('key_id') == kid:
                return s
        return None

    def authorizer(self):
        op = self.b['op']
        if op in ('device_rotate', 'tenant_key_rotate'):
            return self.b['previous']
        if op in ('device_add', 'device_revoke'):
            for s in self.sigs:
                if s.get('key_id') != self.subject()['key_id'] or op == 'device_revoke':
                    return s.get('key_id', '')
        return ''

    def authorizer_binding(self):
        return binding(self.subject()['role'], self.b.get('genesis', ''), self.authorizer())

    def check_shape(self):
        op = self.b['op']
        possession = op in ('genesis', 'device_add', 'device_rotate')
        want = int(possession) + int(op in ('device_add', 'device_rotate', 'device_revoke', 'tenant_key_rotate'))
        if op == 'tenant_key':
            want = 1
        if len(self.sigs) != want:
            raise Rejected('signature count')
        seen = set()
        for s in self.sigs:
            if s.get('alg') != 'ed25519' or s.get('ctx') != CTX_RECORD or s.get('key_id') in seen:
                raise Rejected('signature list')
            seen.add(s.get('key_id'))
        if possession or op == 'tenant_key':
            s = self.sig_by(self.subject()['key_id'])
            pub = b64strict(self.subject()['pub'], 32)
            if s is None or not verify_sig(pub, CTX_RECORD, record_message(self.id), s):
                raise Rejected('possession')


class Key:
    def __init__(self, subject, genesis):
        self.key_id, self.pub = subject['key_id'], b64strict(subject['pub'], 32)
        self.role, self.machine = subject['role'], subject.get('machine_id', '')
        self.genesis = genesis if self.role == 'device' else ''
        self.tenant = genesis if self.role != 'device' else ''
        self.status, self.causes, self.seq, self.reason = 'active', [], 0, ''

    def owner(self):
        if self.role == 'device':
            return self.genesis if HEX32.match(self.genesis) else ''
        if self.role == 'service' and self.tenant:
            return 'tenant:' + self.tenant
        return ''


def fold(ops):
    keys = {}
    ops = sorted(ops, key=lambda o: o.id)
    for o in ops:
        if o.b['op'] in ('genesis', 'device_add', 'device_rotate', 'tenant_key', 'tenant_key_rotate'):
            keys.setdefault(o.subject_binding(), Key(o.subject(), o.b.get('genesis', '')))

    def revoke(bid, cause, seq, reason):
        k = keys.get(bid)
        if k is None:
            return
        if k.status != 'revoked' or reason == 'compromised':
            k.reason = reason
        if seq > 0 and (k.seq == 0 or seq < k.seq):
            k.seq = seq
        if cause not in k.causes:
            k.causes = sorted(k.causes + [cause])
        k.status = 'revoked'

    rotations, edges, todo = {}, {}, []
    for o in ops:
        if o.b['op'] in ('device_add', 'device_rotate', 'tenant_key_rotate'):
            edges.setdefault(o.authorizer_binding(), []).append(o.subject_binding())
        if o.b['op'] in ('device_rotate', 'tenant_key_rotate'):
            rotations.setdefault(binding(o.subject()['role'], o.b['genesis'], o.b['previous']), []).append(o)
    for prev in sorted(rotations):
        if prev in keys:
            keys[prev].status = 'retired'
    for prev in sorted(rotations):
        rs = rotations[prev]
        for loser in rs[1:]:
            seq = max(loser.seq, rs[0].seq)
            revoke(loser.subject_binding(), loser.id, seq, 'conflict')
            todo.append((loser.subject_binding(), loser.id, seq))
    for o in ops:
        if o.b['op'] == 'device_revoke':
            revoke(o.subject_binding(), o.id, o.seq, o.b['reason'])
            if o.b['reason'] == 'compromised':
                todo.append((o.subject_binding(), o.id, o.seq))
    seen = set()
    while todo:
        bid, cause, seq = todo.pop(0)
        if (bid, cause) in seen:
            continue
        seen.add((bid, cause))
        for child in edges.get(bid, []):
            revoke(child, cause, seq, 'cascade')
            todo.append((child, cause, seq))
    return keys


class Keyring:
    def __init__(self, pinned):
        self.pinned, self.ops = pinned, {}

    def add(self, x):
        op = Op(x)  # raises Rejected: the op is invalid and not stored
        if op.id in self.ops:
            raise AssertionError('duplicate operations are not part of these vectors')
        if op.b['op'] == 'genesis' and self.pinned == '':
            self.pinned = op.subject()['key_id']
        self.ops[op.id] = op
        return op

    def authorize(self, op, hist):
        b, h, subj = op.b, op.h, op.subject()
        if subj['role'] != 'device' and (not issuer_valid(op.issuer, subj['role']) or op.issuer.get('tenant') != b.get('genesis')):
            return 'unauthorized'
        existing = hist.get(op.subject_binding())
        if existing is not None and existing.machine != subj.get('machine_id', ''):
            return 'unauthorized'
        author = op.authorizer() or subj['key_id']
        machine = h['author'].get('machine_id', '')
        if h['author']['key_id'] != author:
            return 'invalid'
        if b['op'] == 'genesis':
            if subj['key_id'] != self.pinned:
                return 'unauthorized'
            return 'invalid' if machine != subj.get('machine_id', '') else 'authorized'
        if b['op'] == 'tenant_key':
            if not op.from_login or op.issuer.get('provenance') != 'pinned-tls-login':
                return 'ignored'
            return 'invalid' if machine != '' else 'authorized'
        a = hist.get(op.authorizer_binding())
        if a is None or a.status != 'active':
            return 'unauthorized'
        s = op.sig_by(author)
        if s is None or not verify_sig(a.pub, CTX_RECORD, record_message(op.id), s):
            return 'invalid'
        if (a.role == 'device' and machine != a.machine) or (a.role != 'device' and machine != ''):
            return 'invalid'
        g = b.get('genesis', '')
        if b['op'] in ('device_add', 'device_rotate'):
            if a.role != 'device' or a.genesis != g or g != self.pinned:
                return 'unauthorized'
        elif b['op'] == 'device_revoke':
            target = hist.get(op.subject_binding())
            device_ok = a.role == 'device' and a.genesis == g and g == self.pinned
            if not device_ok or target is None or target.role != 'device' or target.genesis != g:
                return 'unauthorized'
        elif b['op'] == 'tenant_key_rotate':
            if a.role != subj['role'] or a.tenant != g:
                return 'unauthorized'
        return 'authorized'

    def state(self):
        status, authorized, complete, anc = {}, set(), {}, {}

        def is_complete(i, stack):
            if i in complete:
                return complete[i]
            if i not in self.ops or i in stack:
                return False
            stack.add(i)
            res = all([is_complete(p, stack) for p in self.ops[i].b.get('parents', [])])
            stack.discard(i)
            complete[i] = res
            return res

        def ancestors(i):
            if i not in anc:
                a = set()
                for p in self.ops[i].b.get('parents', []):
                    a.add(p)
                    a |= ancestors(p)
                anc[i] = a
            return anc[i]

        def decide(i):
            if i in status:
                return status[i]
            hist = ancestors(i)
            for p in hist:
                decide(p)
            s = self.authorize(self.ops[i], fold([self.ops[p] for p in hist if p in authorized]))
            status[i] = s
            if s == 'authorized':
                authorized.add(i)
            return s

        for i in sorted(self.ops):
            if not is_complete(i, set()):
                status[i] = 'held-parents'
                continue
            decide(i)
        keys = fold([self.ops[i] for i in sorted(self.ops) if i in authorized])
        for i in sorted(self.ops):
            o = self.ops[i]
            if status[i] == 'authorized' and o.b['op'] in ('device_rotate', 'tenant_key_rotate'):
                k = keys.get(o.subject_binding())
                if k is not None and k.reason == 'conflict':
                    status[i] = 'conflict-lost'
        return {'genesis': self.pinned, 'keys': keys, 'status': status, 'ops': dict(self.ops)}


def key_for(st, kid, role, tenant):
    domain = st['genesis'] if role == 'device' else tenant
    if role != 'device' and tenant == '':
        return None
    return st['keys'].get(binding(role, domain, kid))


def receipt_message(r):
    return CTX_RECEIPT.encode() + b'\x00' + hashlib.sha256(canon({k: v for k, v in r.items() if k != 'sig'})).digest()


def verify_receipt(r, st, issuer):
    if not issuer_valid(issuer, 'service') or r.get('tenant') != issuer.get('tenant') or not r.get('sig'):
        return False
    k = key_for(st, r['sig'].get('key_id', ''), 'service', issuer['tenant'])
    if k is None or k.role != 'service' or k.tenant != r['tenant'] or k.status not in ('active', 'retired'):
        return False
    if not HEX64.match(r.get('id', '')) or not HEX64.match(r.get('policy', '')) or r.get('accepted_at', 0) <= 0 or r.get('hseq', 0) <= 0 or not UUID.match(r.get('device_id', '')):
        return False
    return verify_sig(k.pub, CTX_RECEIPT, receipt_message(r), r['sig'])


def before_cutoff(k, r, st):
    if not k.causes:
        return False
    cutoff = None
    for cause in k.causes:
        op = st['ops'].get(cause)
        if op is None or not op.receipt:
            return False
        rc = op.receipt
        if rc.get('id') != cause or rc.get('tenant') != r.get('tenant') or op.receipt_issuer.get('tenant') != r.get('tenant') or not verify_receipt(rc, st, op.receipt_issuer):
            return False
        cutoff = rc['accepted_at'] if cutoff is None else min(cutoff, rc['accepted_at'])
    return r['accepted_at'] < cutoff


def verify_record(x, st):
    try:
        rid, h, _ = parse_record(x['header_jcs'], x['body_jcs'], x['id'])
    except Rejected as e:
        return 'invalid' if e.quarantine else 'rejected'
    if h['type'] == 'key_op':
        return 'invalid'
    sigs = x.get('sigs') or []
    if len(sigs) != 1:
        return 'invalid'
    s = sigs[0]
    if s.get('alg') != 'ed25519' or s.get('ctx') != CTX_RECORD or s.get('key_id') != h['author']['key_id']:
        return 'invalid'
    role = x.get('signer_role') or 'device'
    issuer = x.get('issuer') or {}
    if role != 'device' and not issuer_valid(issuer, role):
        return 'unknown-signer'
    k = key_for(st, s['key_id'], role, issuer.get('tenant', ''))
    if k is None:
        return 'unknown-signer'
    if not verify_sig(k.pub, CTX_RECORD, record_message(rid), s):
        return 'invalid'
    if (k.role, h.get('prov'), h['type']) not in MATRIX:
        return 'invalid'
    machine = h['author'].get('machine_id', '')
    if (k.role == 'device' and k.machine != machine) or (k.role != 'device' and machine != ''):
        return 'invalid'
    if h['type'] == 'task' or (h['type'] == 'conclusion' and h.get('prov') in ('mcp-explicit', 'gateway')):
        owner = k.owner()
        tag = 'task' if h['type'] == 'task' else 'conclusion'
        parts = [owner, h['subj']['task_id']] if tag == 'task' else ['task', owner, h['subj']['task_id']]
        if owner == '' or h.get('lid') != H(tag, *parts):
            return 'invalid'
    elif h['type'] in ('checkpoint', 'pause', 'rollup', 'erasure'):
        raise AssertionError('owner-scoped kind outside these vectors: ' + h['type'])
    if k.status in ('active', 'retired'):
        return 'verified'
    seq = x.get('admitted_seq', 0)
    if seq > 0 and k.seq > 0 and seq < k.seq:
        return 'verified'
    r = x.get('receipt')
    if r and verify_receipt(r, st, x.get('receipt_issuer') or {}) and r.get('id') == rid and (k.role != 'device' or r.get('device_id') == k.machine) and before_cutoff(k, r, st):
        return 'verified'
    return 'signer-revoked'


def state_result(st, names, scenario_ops):
    return {
        'ops': {n: st['status'][names[n]] for n in scenario_ops},
        'keys': {bid: {'status': k.status, 'reason': k.reason, 'causes': sorted(k.causes), 'revoked_seq': k.seq} for bid, k in st['keys'].items()},
    }


kf = json.loads((Path(__file__).resolve().parent / 'v06-v07-keyring.json').read_text())
assert kf['contract'] == 'mnc/3.0'
ops_by_name = {o['name']: o for o in kf['ops']}
names = {}
for o in kf['ops']:
    names[o['name']] = digest(o['header_jcs'].encode())
    assert names[o['name']] == o['id'], o['name']
v6, states = {}, {}
for s in kf['v6']:
    ref = None
    for order in s['orders']:
        kr = Keyring(s['pinned'])
        for n in order:
            kr.add(ops_by_name[n])
        st = kr.state()
        res = canon(state_result(st, names, s['ops']))
        if ref is None:
            ref, states[s['name']], v6[s['name']] = res, st, state_result(st, names, s['ops'])
        assert res == ref, s['name'] + ': arrival order changes key state'
added = {}
for a in kf['v6_add']:
    kr = Keyring(a['pinned'])
    for n in a.get('prior') or []:
        kr.add(ops_by_name[n])
    try:
        op = kr.add(a['op'])
    except Rejected:
        added[a['name']] = 'invalid'
        continue
    added[a['name']] = kr.state()['status'][op.id]
v7 = {r['name']: verify_record(r, states[r['scenario']]) for r in kf['v7']}
results = canon({'v6': v6, 'v6_add': added, 'v7': v7})
expected = json.loads(kf['expected_jcs'])
for part in ('v6', 'v6_add'):
    for name, want in expected[part].items():
        got = json.loads(results)[part].get(name)
        assert got == want, '%s %s: python %r, expected %r' % (part, name, got, want)
print('V6 PASS')
for name, want in expected['v7'].items():
    assert v7.get(name) == want, 'v7 %s: python %r, expected %r' % (name, v7.get(name), want)
assert results == kf['expected_jcs'].encode(), 'canonical V6/V7 result bytes differ'
print('V7 PASS')

# ---- V6 possession bootstrap (contract sections 4.3 and 4.6) ----
# genesis: one signature by its own subject. device_add: subject possession
# plus one active device of the same genesis in the op's history. tenant_key:
# exactly one subject signature, empty parents, accepted only from a pinned
# TLS login naming the same tenant and role.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from itertools import permutations
pb = load('v06-possession-bootstrap.json')
assert pb['contract'] == 'mnc/3.0'
for k in pb['keys']:
    seed = bytes.fromhex(k['test_seed_hex'])
    assert len(seed) == 32, k['name']
    raw = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert b64(raw) == k['pub'] and key_id(raw) == k['key_id'], k['name']
pb_ops = {}
for o in pb['ops']:
    assert o['name'] not in pb_ops, o['name']
    assert digest(o['header_jcs'].encode()) == o['id'], o['name']
    pb_ops[o['name']] = o
pb_used = set()
for c in pb['cases']:
    kr = Keyring(pb['pinned_genesis'])
    for n in c['prior']:
        prior = kr.add(pb_ops[n])
        assert kr.state()['status'][prior.id] == 'authorized', c['name'] + ' prior ' + n
    pb_used.add(c['op'])
    try:
        added_op = kr.add(pb_ops[c['op']])
        got = kr.state()['status'][added_op.id]
    except Rejected:
        got = 'invalid'
    assert got == c['expected'], '%s: python %r, expected %r' % (c['name'], got, c['expected'])
assert pb_used == set(pb_ops), 'ops not exercised: %s' % sorted(set(pb_ops) - pb_used)
boot = pb['bootstrap']
for order in permutations(boot['ops']):
    kr = Keyring(pb['pinned_genesis'])
    for n in order:
        kr.add(pb_ops[n])
    st = kr.state()
    for n, want in boot['expected'].items():
        assert st['status'][pb_ops[n]['id']] == want, '%s in %s' % (n, order)
    assert len(st['keys']) == len(boot['keys']), order
    for want in boot['keys']:
        k = key_for(st, want['key_id'], want['role'], want['domain'])
        assert k is not None and k.status == want['status'] and k.machine == want['machine_id'], (want, order)
        assert want['role'] != 'device' or want['domain'] == st['genesis']
print('V6 possession bootstrap PASS')
if args.results:
    Path(args.results).write_bytes(results)
