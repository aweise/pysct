#!/usr/bin/env python

import sys
import os.path
import fileinput
import json
import base64
import struct
import datetime
from argparse import ArgumentParser

import hashlib
import ecdsa
from ecdsa import util

try:
    # We need Crypto for RSA support
    import Crypto
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256
    HAVE_CRYPTO = True
except:
    HAVE_CRYPTO = False

def load_logs(path=None):
    # List of known logs, taken from https://ct.grahamedgecombe.com/logs.json
    logs_path = path or os.path.join(os.path.dirname(__file__), 'logs.json')
    logs = json.loads(open(logs_path).read())['logs']
    
    # convert to binary
    for l in logs:
        l['log_id'] = base64.b64decode(l['log_id'])
        l['key'] = base64.b64decode(l['key'])
    
    # clean format, we want something like { 'log_x_id': { details_for_log_x } }
    logs = { l['log_id']: { k: v for k, v in l.items() if k != 'log_id' } for l in logs }
    return logs

# Q Why use strings instead of objects here?
# A If hashlib uses its openssl backend, hash.name is not available,
#   but we still want to pretty-print the algo name later.
hash_algos = [
    None,
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha512']

signature_algos = [None, 'RSA', 'DSA', 'ECDSA']

def pretty_hex(blob, indent=0, line_width=80):
    if isinstance(blob, str):
        blob = [ord(x) for x in blob]
    bytes_per_line = int((line_width - indent) / 3) # 2 hex digits + 1 space
    lines = int(len(blob) / bytes_per_line + 0.5)
    result = []
    for i in range(lines):
        result.append(' '.join(('{:02x}'.format(b) for b in blob[i * bytes_per_line:(i + 1) * bytes_per_line])))
    return ('\n' + (indent * ' ')).join(result)

def strip_newlines(blob):
    return type(blob)(b for b in blob if int(b) != ord('\n'))

def loadSCT(path):
    if path == '-':
        sct = sys.stdin.read()
    else:
        sct = bytearray(open(path, 'rb').read())
    # The file could be Base64-encoded, e.g. when downloaded from a webserver.
    # As binary SCTs start with 0x0 (which is not a valid Base64 character),
    # it is safe -- and convenient -- to try to decode it.
    try:
        sct = base64.b64decode(strip_newlines(sct), validate=True)
    except:
        pass
    return sct

def parseSCT(sct, logs, offset=0):
    header_fmt = '>B32sQHBBH'
    header_len = struct.calcsize(header_fmt)
    ver, logid, timestamp, extensions, hashid, sigid, siglen = struct.unpack_from(header_fmt, sct, offset)
    offset += header_len
    sigfmt = '>{}s'.format(siglen)
    sig = struct.unpack_from(sigfmt, sct, offset)[0]
    offset += siglen

    try:
        log = logs[logid]
    except:
        raise ValueError('Unknown log - id: {}'.format(pretty_hex(logid)))
    if extensions != 0:
        raise ValueError('SCT contains extensions. What do?') 
    try:
        hash_algo_name = hash_algos[hashid]
    except:
        raise ValueError('Unknown hashing algorithm - id: {}'.format(hashid))
    try:
        signature_algo = signature_algos[sigid]
    except:
        raise ValueError('Unknown signature algorithm - id: {}'.format(signature_id))
    return dict(
        version=ver,
        log=log,
        timestamp=timestamp,
        extensions=extensions,
        hash_algo=hash_algo_name.upper(),
        sig_algo=signature_algo,
        signature=sig,
        next_offset=offset
    )

def printSCT(sct, sct_number=0, verify=None):
    logname = sct['log']['description']
    print('''SCT (#{number}):
    Version:             {version}
    Log:                 {logname}
    Timestamp:           {ts}
    Extensions:          {extensions}
    Hashing algorithm:   {hash_algo}
    Signature algorithm: {sig_algo}
    Signature length:    {siglen}
    Signature:           {pretty_sig}'''.format(
        number=sct_number,
        pretty_sig=pretty_hex(sct['signature'], indent=25),
        siglen=len(sct['signature']),
        logname=logname,
        ts=datetime.datetime.fromtimestamp(sct['timestamp']/1000.0),
        **sct))
    if verify is not None:
        label='    Verification key:    '
        print(label + pretty_hex(verify['key'], indent=len(label)))
        if verify['valid']:
            result = 'Valid signature from {}'.format(logname)
        else:
            result = 'Signature verification FAILED'
        print('    Verification result: {}'.format(result))

def loadCert(path):
    cert = open(path, 'rb').read()
    # Cert could be either in base64-encoded PEM format or as binary DER.
    if cert.startswith(b'-----BEGIN CERTIFICATE-----'):
        fmt = 'PEM'
    else:
        fmt = 'DER'
    # We need DER to craft the signed message for verification
    if fmt == 'PEM':
        plain_cert = cert.decode('ascii')
        # PEM could include the full chain, so we only take the first cert
        end_marker = '-----END CERTIFICATE-----'
        plain_cert = plain_cert[:plain_cert.index(end_marker)+len(end_marker)]
        import ssl
        cert = ssl.PEM_cert_to_DER_cert(plain_cert)
    return cert

def verify_ecdsa(message, signature, key, hash_algo):
    vk = ecdsa.VerifyingKey.from_string(
            key[27:], ecdsa.NIST256p)
    hashfn = hashlib.new(hash_algo)
    hashfn.update(message)
    digest = hashfn.digest()
    try:
        vk.verify_digest(signature, digest, util.sigdecode_der)
        return True
    except:
        return False

def verify_rsa(message, signature, key, hash_algo):
    rsakey = RSA.importKey(key)
    verifier = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(message)
    return verifier.verify(digest, signature)

supported_algos = dict(ECDSA=verify_ecdsa)
if HAVE_CRYPTO:
    supported_algos['RSA'] = verify_rsa

def verifySCT(sct, cert):
    sig_algo = sct['sig_algo']
    if sig_algo not in supported_algos:
        raise ValueError('Unsupported signature algorithm: {}'.format(sig_algo))
    # Signature uses 3 bytes for length -> pack into 4 bytes and ignore 1st
    _der_len_0, der_len_1, der_len_2, der_len_3 = struct.unpack(
        ">4B", struct.pack( ">I", len(cert)))

    signed_data_fmt = '>BBQHBBB{}sH'.format(len(cert))
    sigtype = 0 # "certificate_timestamp"
    x509_entry = 0
    signed_data = struct.pack(
        signed_data_fmt,
        parsed['version'],
        sigtype,
        parsed['timestamp'],
        x509_entry,
        der_len_1, der_len_2, der_len_3,
        cert,
        parsed['extensions'])

    key = parsed['log']['key']
    valid = supported_algos[sig_algo](
        signed_data, parsed['signature'], key, parsed['hash_algo'])
    return dict(valid=valid, key=key)

if __name__=='__main__':
    cli = ArgumentParser(description='Work with signed certificate timestamp files')
    cli.add_argument('sct', help='SCT file to process')
    cli.add_argument(
        '-v', '--verify', nargs=1, metavar='CERT',
        help='Verify SCT against a certificate in DER or PEM format')
    cli.add_argument(
        '-t', '--tls', action='store_true',
        help='Process SCT in TLS extension format')
    cli.add_argument('-l', '--logs', help='Path to list of CT logs in JSON format.')
    args = cli.parse_args()
    if args.tls:
        '''SCT in TLS format starts with two bytes "00 12" + two bytes length
           of the extension + another two bytes length of the
           SignedCertificateTimestampList'''
        tls_padding = 6
        '''In a SignedCertificateTimestampList, every SCT is prepended with
           a length field of two bytes'''
        sctl_padding = 2
    else:
        tls_padding = sctl_padding = 0
    logs = load_logs(args.logs)
    sct = loadSCT(args.sct)
    if args.verify:
        cert = loadCert(args.verify[0])
    sct_number = 0
    offset = tls_padding
    ok = len(sct) > 0
    while offset < len(sct):
        offset += sctl_padding
        parsed = parseSCT(sct, logs, offset)
        offset = parsed['next_offset']
        if args.verify:
            verify = verifySCT(parsed, cert)
            printSCT(parsed, sct_number, verify)
            ok &= verify['valid']
        else:
            printSCT(parsed, sct_number)
        sct_number += 1 
    sys.exit(0 if ok else 1)

