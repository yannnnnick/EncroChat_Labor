"""Separates Offline-Werkzeug. Niemals vom Config-Server importieren/starten."""

import argparse
import base64
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from update_protocol import canonical, verify_package


def write_new(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)
    path.chmod(0o600)


def keygen(private_path, public_path):
    if Path(private_path).exists() or Path(public_path).exists():
        raise ValueError("Vorhandene Signierschluessel werden nicht ueberschrieben")
    key = Ed25519PrivateKey.generate()
    write_new(
        private_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    write_new(
        public_path,
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )


def sign(private_path, name, version, target, output):
    # Einzige Stelle der Anwendung, die einen privaten Ed25519-Schluessel liest.
    key = serialization.load_pem_private_key(
        Path(private_path).read_bytes(), password=None
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Ed25519-Schluessel erforderlich")
    manifest = {
        "type": "plugin_update",
        "name": name,
        "version": version,
        "target": target,
        "sha256": hashlib.sha256(name.encode("utf-8")).hexdigest(),
    }
    package = dict(
        manifest,
        signature=base64.b64encode(key.sign(canonical(manifest))).decode("ascii"),
    )
    verify_package(
        package, key.public_key(), "client_2" if target == "client_2" else "client_1"
    )
    write_new(output, canonical(package) + b"\n")
    return package


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    gen = commands.add_parser("keygen")
    gen.add_argument("--private", type=Path, required=True)
    gen.add_argument("--public", type=Path, required=True)
    command = commands.add_parser("sign")
    command.add_argument("--private", type=Path, required=True)
    command.add_argument("--name", choices=("dummy", "audit"), required=True)
    command.add_argument("--version", type=int, required=True)
    command.add_argument(
        "--target", choices=["all", "client_1", "client_2"], required=True
    )
    command.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "keygen":
        keygen(args.private, args.public)
        print("Offline-Signierschluessel und oeffentlicher Vertrauensanker erstellt.")
    else:
        sign(args.private, args.name, args.version, args.target, args.out)
        print(
            f"Paket {args.name}, Version {args.version}, Ziel {args.target} signiert."
        )


if __name__ == "__main__":
    main()
