#!/usr/bin/env python3

from sys import argv, stderr, stdout, version_info
from functools import partial
eprint = partial(print, file=stderr)

import re
import hashlib
import cryptography

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, load_der_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature

from base64 import b64decode as b64d, b64encode as b64e
from binascii import hexlify, unhexlify

ubody = b''
cbody = b''
headers = {}
state = 'initial'

with open(argv[1], 'rb') as f:
    last_header = None
    for line in map(lambda x: x.strip(b'\r\n'), f):
        if state == 'initial' and line == b'-----BEGIN PRIVACY-ENHANCED MESSAGE-----':
            state = 'headers'
        elif state == 'headers' and line == b'':
            state = 'body'
        elif state == 'headers' and line[0] not in (0x20, 0x09):
            key, value = re.split(rb':\s*', line, 1)
            last_header = key.decode()
            headers[last_header] = value
        elif state == 'headers':
            headers[last_header] += line.lstrip(b'\t ')
        elif state == 'body' and line == b'-----END PRIVACY-ENHANCED MESSAGE-----':
            state = 'end'
        elif state == 'body':
            cbody += line + b'\r\n'
            ubody += line + b'\n'

for k in ('Proc-Type', 'MIC-Info', 'Originator-Key-Asymmetric'):
    if k not in headers:
        eprint(f'Missing critical header `{k}`')
        sys.exit(1)

if headers['Proc-Type'] != b'2001,MIC-CLEAR':
    eprint(f'Unknown Proc-Type: `{headers["Proc-Type"].decode()}`')
    sys.exit(1)

pub_der = b64d(headers['Originator-Key-Asymmetric'])
pub_fp = b64e(hashlib.sha256(pub_der).digest())[0:43].decode()
pub_key = load_der_public_key(pub_der)
mic_hash, mic_algo, mic_sig = headers['MIC-Info'].split(b',')
sig_data = b64d(mic_sig)

if mic_hash == b'RSA-MD5':
    body_hash = hashlib.md5(cbody).digest()
    sig_hash = hashes.MD5()
else:
    eprint(f'Unknown hash `{mic_hash.decode()}`')
    sys.exit(1)

if mic_algo != b'RSA':
    eprint(f'Unknown algo `{mic_algo.decode()}`')
    sys.exit(1)

result = None
try:
    pub_key.verify(sig_data, cbody, PKCS1v15(), sig_hash)
    result = True
except InvalidSignature:
    result = False

if 'Originator-Name' in headers:
    print(f'Originator-Name: {headers["Originator-Name"].decode()}')

print(f'Originator-Key-SHA256: {pub_fp}')
print(f'Canonical-Body-Hash: {hexlify(body_hash).decode()}')
print(f'Signature-Valid: {result}')
if result:
    print('\n'+ubody.decode()[:-1])
