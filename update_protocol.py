"""Oeffentliches Updateformat und ausschliesslich clientseitige Verifikation."""

import base64
import binascii
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CLIENT_IDS = {"client_1", "client_2"}
MAX_UPDATE_BYTES = 128 * 1024
FIELDS = {"type", "name", "version", "target", "sha256", "signature"}


def canonical(manifest):
    return json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Doppelte JSON-Felder")
        result[key] = value
    return result


def read_package(path):
    with Path(path).open("rb") as handle:
        data = handle.read(MAX_UPDATE_BYTES + 1)
    if len(data) > MAX_UPDATE_BYTES:
        raise ValueError("Update zu gross")
    package = json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates)
    if not isinstance(package, dict):
        raise ValueError("Update muss ein Objekt sein")
    return package


def load_public_key(path):
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Ed25519-Vertrauensanker erforderlich")
    return key


def verify_package(package, public_key, client_id, current_version=0):
    if isinstance(package, dict) and "signature" not in package:
        raise ValueError("Unsigniertes Update: Ed25519-Signatur fehlt")
    if not isinstance(package, dict) or set(package) != FIELDS:
        raise ValueError("Unsigniertes oder ungueltiges Updateformat")
    if (
        package["type"] != "plugin_update"
        or not isinstance(package["name"], str)
        or not 1 <= len(package["name"]) <= 80
        or type(package["version"]) is not int
        or not 1 <= package["version"] < 2**63
        or not isinstance(package["target"], str)
        or package["target"] not in CLIENT_IDS | {"all"}
        or not isinstance(package["sha256"], str)
        or not isinstance(package["signature"], str)
    ):
        raise ValueError("Ungueltige signierte Felder")
    if len(canonical(package)) + 1 > MAX_UPDATE_BYTES:
        raise ValueError("Update zu gross")
    manifest = {key: value for key, value in package.items() if key != "signature"}
    try:
        signature = base64.b64decode(package["signature"], validate=True)
        public_key.verify(signature, canonical(manifest))
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        raise ValueError("Ed25519-Signatur ungueltig") from exc
    if hashlib.sha256(package["name"].encode("utf-8")).hexdigest() != package["sha256"]:
        raise ValueError("SHA-256 stimmt nicht ueberein")
    if package["name"] not in {"dummy", "audit"}:
        raise ValueError("Unbekanntes Betriebsprofil")
    if package["target"] not in {"all", client_id}:
        raise ValueError("Update fuer anderen Client")
    if package["version"] <= current_version:
        raise ValueError("Veraltete oder bereits installierte Version")
    return package
