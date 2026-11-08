#!/usr/bin/env python3
"""Make test certificates for the HTTPS tests.

Usage: make_test_certs.py <out_dir>

Writes:
  ca.pem                 test root CA (RSA)
  rsa.pem / rsa.key      server cert (RSA) for localhost and 127.0.0.1
  ec.pem / ec.key        server cert (ECDSA P-256) for localhost and 127.0.0.1
  other.pem / other.key  server cert for other.example only (name mismatch)
  old.pem / old.key      expired server cert for localhost
  self.pem / self.key    self-signed server cert for localhost
"""
import datetime as dt
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
now = dt.datetime.now(dt.timezone.utc)


def save(name, cert, key):
    (out / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        (out / f"{name}.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject_cn, pub, issuer_cn, issuer_key, sans, ca=False,
         start=now - dt.timedelta(days=1), end=now + dt.timedelta(days=30)):
    b = (x509.CertificateBuilder()
         .subject_name(name(subject_cn)).issuer_name(name(issuer_cn))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(end)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True,
                                          False, False), critical=True)
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


local = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]

ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca = cert("p2f test CA", ca_key.public_key(), "p2f test CA", ca_key, None, ca=True,
          end=now + dt.timedelta(days=365))
save("ca", ca, None)

k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
save("rsa", cert("localhost", k.public_key(), "p2f test CA", ca_key, local), k)

k = ec.generate_private_key(ec.SECP256R1())
save("ec", cert("localhost", k.public_key(), "p2f test CA", ca_key, local), k)

k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
save("other", cert("other.example", k.public_key(), "p2f test CA", ca_key,
                   [x509.DNSName("other.example")]), k)

k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
save("old", cert("localhost", k.public_key(), "p2f test CA", ca_key, local,
                 start=now - dt.timedelta(days=60), end=now - dt.timedelta(days=30)), k)

k = ec.generate_private_key(ec.SECP256R1())
save("self", cert("localhost", k.public_key(), "localhost", k, local), k)
