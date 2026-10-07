"""Validate public test vectors with an independent X.509 decoder.

Requires Python cryptography. This validates the fixtures, not the C# runtime.
No certificate is installed, and no private key is used or retained.
"""
from pathlib import Path
import csv
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding

root = Path(__file__).resolve().parent
fixtures = {}
with (root / "metadata-vectors.csv").open(newline="") as stream:
    for vector in csv.DictReader(stream):
        der = (root / vector["file"]).read_bytes()
        cert = x509.load_der_x509_certificate(der)
        key = cert.public_key()
        spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        digest = cert.signature_hash_algorithm.name.upper().replace("SHA1", "SHA-1").replace("SHA256", "SHA-256")
        assert cert.public_key_algorithm_oid.dotted_string == vector["key_oid"]
        assert key.key_size == int(vector["key_bits"])
        assert cert.signature_algorithm_oid.dotted_string == vector["signature_oid"]
        assert digest == vector["signature_hash"]
        assert hashlib.sha256(spki).hexdigest().upper() == vector["spki_sha256"]
        assert hashlib.sha256(der).hexdigest().upper() == vector["certificate_sha256"]
        weak = isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048 or digest in ("MD5", "SHA-1")
        assert weak == (vector["weak_expected"] == "true")
        if isinstance(key, rsa.RSAPublicKey):
            parameters = cert.signature_algorithm_parameters
            if parameters is None and cert.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.4":
                parameters = padding.PKCS1v15()
            key.verify(cert.signature, cert.tbs_certificate_bytes, parameters, cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_algorithm_parameters)
        fixtures[vector["file"]] = cert
        print("PASS: independent fixture metadata, SPKI, and signature: " + vector["file"])

base = fixtures["metadata/rsa2048.cer"]
reissue = fixtures["metadata/rsa2048-reissue.cer"]
renamed = fixtures["metadata/rsa2048-other-subject.cer"]
assert base.subject == reissue.subject and base.subject != renamed.subject
assert base.public_key().public_numbers() == reissue.public_key().public_numbers() == renamed.public_key().public_numbers()
assert base.fingerprint(hashes.SHA256()) != reissue.fingerprint(hashes.SHA256())
print("PASS: same-subject reissue and different-subject reuse fixtures share a key and have distinct certificates")
print("NOT RUN: C# metadata/signal implementation; Windows APIs and GUI")
