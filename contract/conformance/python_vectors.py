#!/usr/bin/env python3
"""Independent V1–V5 reference runner. No Go or service subprocesses."""
import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
import sys
parser = argparse.ArgumentParser()
parser.add_argument('--deps', help='Optional isolated pip --target directory')
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
    assert h['v'] == 2
    assert h['body']['digest'] == f['Digest'] and h['body']['size'] == len(body)
    assert 'subj' in h and 'trust' in h and 'epoch' in h['red'] and 'findings' in h['red']
print('V3 PASS')
f = load('v04-salt.json')
msg = canon(['mnc1-salt', f['kind'], f['lid'], f['body_without_salt']])
key = bytes.fromhex(f['salt_key_hex'])
assert b64(hmac.new(key, msg, hashlib.sha256).digest()[:16]) == f['salt']
assert b64(hmac.new(bytes([8])*32, msg, hashlib.sha256).digest()[:16]) != f['salt']
assert b64(hmac.new(key, canon(['mnc1-salt', f['kind'], f['lid'], '{\"text\":\"sibling\"}']), hashlib.sha256).digest()[:16]) != f['salt']
ef = load('v04-events.json')
event = ef['event']
salt_input = {k:v for k,v in event.items() if k not in ('revision', 'salt')}
nonce = bytes.fromhex(ef['test_nonce_hex'])
assert b64(hmac.new(bytes.fromhex(ef['salt_key_hex']), canon(['mnc2-event-salt', event['id'], b64(nonce), canon(salt_input).decode()]), hashlib.sha256).digest()[:16]) == event['salt']
revision_input = {k:v for k,v in event.items() if k != 'revision'}
assert H('event-rev', event['id'], canon(revision_input).decode()) == event['revision']
assert 'nonce' not in event and 'test_nonce_hex' not in event
print('V4 PASS')
f = load('v05-signature.json')
header = f['header_jcs'].encode()
h = json.loads(header)
assert canon(h) == header and h['v'] == 2
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
