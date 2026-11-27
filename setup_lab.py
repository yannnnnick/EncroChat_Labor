"""Isoliertes, startbereites Labor erstellen; keine Netzwerkzugriffe."""

import argparse
import hashlib
import shutil
from pathlib import Path

from offline_signer.sign import keygen, sign
from provision_tls import provision
from update_protocol import canonical

ROOT = Path(__file__).resolve().parent
FILES = (
    "routing_server.py",
    "config_server.py",
    "audit_collector.py",
    "client_1.py",
    "client_2.py",
    "chat_client.py",
    "audit_event.py",
    "plugin_runtime.py",
    "tls_transport.py",
    "update_protocol.py",
    "demo_ipc.py",
)


def setup(destination):
    destination = Path(destination).resolve()
    # Keine bestehenden Schluessel, Vertrauensanker oder Client-Zustaende ersetzen.
    destination.mkdir(parents=True, exist_ok=False)
    runtime, offline = destination / "runtime", destination / "offline"
    runtime.mkdir()
    for filename in FILES:
        shutil.copyfile(ROOT / filename, runtime / filename)
    provision(runtime, offline)
    private = offline / "update-signing.key"
    keygen(private, runtime / "trust" / "update-signing.pub")

    def package(name, version, filename, target="all"):
        return sign(private, name, version, target, runtime / "packages" / filename)

    package("dummy", 1, "initial.json")
    valid = package("audit", 2, "update.json")
    package("dummy", 3, "reset.json")
    package("audit", 2, "client_1.json", "client_1")
    package("audit", 2, "client_2.json", "client_2")
    tampered = dict(valid, name="dummy")
    (runtime / "packages" / "tampered.json").write_bytes(canonical(tampered) + b"\n")
    forged = dict(
        tampered,
        version=20,
        sha256=hashlib.sha256(tampered["name"].encode("utf-8")).hexdigest(),
    )
    (runtime / "packages" / "server-forged.json").write_bytes(canonical(forged) + b"\n")
    unsigned = dict(forged)
    del unsigned["signature"]
    (runtime / "packages" / "unsigned.json").write_bytes(canonical(unsigned) + b"\n")
    return runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=ROOT / ".lab")
    args = parser.parse_args()
    try:
        runtime = setup(args.destination)
    except (OSError, ValueError) as exc:
        raise SystemExit(
            f"Labor nicht erstellt ({type(exc).__name__}); neues Zielverzeichnis verwenden."
        )
    print(f"Labor bereit: {runtime}")
    print(
        "Offline-Verzeichnis getrennt halten; niemals an den Config-Server verteilen."
    )


if __name__ == "__main__":
    main()
