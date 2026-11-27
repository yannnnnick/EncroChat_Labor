"""Lokale Test-CA und drei Serveridentitaeten erzeugen. Kein Netzwerk."""

import argparse
import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tls_transport import ROOT, SERVICES


def write_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)
    path.chmod(0o600)


def provision(root, offline):
    root, offline = Path(root), Path(offline)
    outputs = [
        root / "trust" / "ca.pem",
        root / "trust" / "config-pin.sha256",
        offline / "ca.key",
    ]
    outputs += [
        root / "pki" / f"{service}.{suffix}"
        for service in SERVICES.values()
        for suffix in ("pem", "key")
    ]
    if any(path.exists() for path in outputs):
        raise ValueError(
            "Vorhandene PKI wird nicht ueberschrieben; neues Laborverzeichnis verwenden"
        )
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Local simulation test CA")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    write_new(
        offline / "ca.key",
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    write_new(root / "trust" / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    for service in SERVICES.values():
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, service)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
            )
            .add_extension(
                x509.KeyUsage(
                    True, False, False, False, False, False, False, False, False
                ),
                True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        write_new(
            root / "pki" / f"{service}.key",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        write_new(
            root / "pki" / f"{service}.pem",
            cert.public_bytes(serialization.Encoding.PEM),
        )
        if service == "config":
            pin = hashlib.sha256(
                cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest()
            write_new(
                root / "trust" / "config-pin.sha256", (pin + "\n").encode("ascii")
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--offline-dir", type=Path, required=True)
    args = parser.parse_args()
    provision(args.root, args.offline_dir)
    print(
        "Lokale Test-PKI erstellt; CA-Schluessel ausschliesslich im Offline-Verzeichnis."
    )


if __name__ == "__main__":
    main()
