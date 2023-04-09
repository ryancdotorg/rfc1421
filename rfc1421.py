#!/usr/bin/env python3

from sys import argv, exit, stdin, stdout, stderr, version_info
from functools import partial
eprint = partial(print, file=stderr)

import re
import sys
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature

from os import fdopen
from base64 import b64decode as b64d, b64encode as b64e
from binascii import hexlify, unhexlify
from io import StringIO

def parse(f, mode):
    rbody = b''
    cbody = b''
    headers = {}
    state = 'initial'

    last_header = None
    for raw_line in f:
        line = raw_line.strip(b'\r\n')
        if state == 'initial' and line == b'-----BEGIN PRIVACY-ENHANCED MESSAGE-----':
            state = 'headers'
        elif state == 'initial' and mode == 'sign':
            state = 'body'
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
            rbody += raw_line

    return rbody, headers, cbody

def main():
    infile = keyfile = None
    if len(argv) == 2 and argv[1] == 'verify':
        mode = 'verify'
    elif len(argv) == 3 and argv[1] == 'verify':
        mode, infile = 'verify', argv[2]
    elif len(argv) == 4 and argv[1] == 'sign':
        mode, name, keyfile = 'sign', argv[2], argv[3]
    elif len(argv) == 5 and argv[1] == 'sign':
        mode, name, keyfile, infile = 'sign', argv[2], argv[3], argv[4]
    else:
        eprint(f'usage:\n\t{argv[0]} verify [INFILE]\n\t{argv[0]} sign NAME KEYFILE [INFILE]')
        sys.exit(255)

    key = None
    if mode == 'sign':
        with open(keyfile, 'rb') as f:
            key = load_pem_private_key(f.read(), password=None)

    with open(infile, 'rb') if infile else fdopen(stdin.fileno(), 'rb') as ifile:
        rbody, headers, cbody = parse(ifile, mode)

        if mode == 'verify':
            verify(rbody, headers, cbody)
        elif mode == 'sign':
            sign(rbody, headers, cbody, name, key)

def sign(rbody, headers, cbody, name, key):
    #headers.setdefault('Proc-Type', b'2001,MIC-CLEAR')
    pub = key.public_key()
    pub_bytes = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    print('-----BEGIN PRIVACY-ENHANCED MESSAGE-----')
    print('Proc-Type: 2001,MIC-CLEAR')
    print(f'Originator-Name: {name}')
    print('Originator-Key-Asymmetric:')
    with StringIO(b64e(pub_bytes).decode()) as s:
        while True:
            line = s.read(64)
            if not line: break
            print(' '+line)
    print('MIC-Info: RSA-MD5,RSA,')
    sig = key.sign(cbody, PKCS1v15(), hashes.MD5())
    pub.verify(sig, cbody, PKCS1v15(), hashes.MD5())
    with StringIO(b64e(sig).decode()) as s:
        while True:
            line = s.read(64)
            if not line: break
            print(' '+line)
    print()
    print(rbody.decode(), end='')
    print('-----END PRIVACY-ENHANCED MESSAGE-----')

def verify(rbody, headers, cbody):
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
        print('\n'+rbody.decode()[:-1])

if __name__ == '__main__':
    main()
