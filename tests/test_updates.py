"""Kryptographische Negativtests und persistente, atomare Installation."""

import base64
import hashlib
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from offline_signer.sign import keygen, sign
from plugin_runtime import load_client_runtime
from update_protocol import canonical, load_public_key, read_package, verify_package

ROOT = Path(__file__).resolve().parents[1]


class SignedUpdateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="signed-update-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "runtime"
        self.root.mkdir()
        self.private = self.base / "offline" / "signing.key"
        keygen(self.private, self.root / "trust" / "update-signing.pub")
        self.public = load_public_key(self.root / "trust" / "update-signing.pub")
        self.package = self.make_package(1)

    def make_package(self, version, target="all", name="dummy"):
        output = self.base / f"package-{version}-{target}.json"
        return sign(self.private, name, version, target, output)

    def resign_for_hash_test(self, package):
        # Ausschliesslich Testfixture: auch ein korrekt signierter falscher Hash
        # muss abgelehnt werden.
        key = serialization.load_pem_private_key(
            self.private.read_bytes(), password=None
        )
        manifest = {k: v for k, v in package.items() if k != "signature"}
        return dict(
            manifest, signature=base64.b64encode(key.sign(canonical(manifest))).decode()
        )

    def test_valid_signature_and_sha256(self):
        self.assertEqual(
            verify_package(self.package, self.public, "client_1"), self.package
        )

    def test_unsigned_and_malformed_packages_rejected(self):
        unsigned = dict(self.package)
        del unsigned["signature"]
        for package in (
            unsigned,
            {},
            [],
            dict(self.package, version=True),
            dict(self.package, signature="!"),
            dict(self.package, signature=""),
        ):
            with (
                self.subTest(package_type=type(package).__name__),
                self.assertRaises(ValueError),
            ):
                verify_package(package, self.public, "client_1")

    def test_every_signed_field_is_bound(self):
        changes = {
            "version": 10,
            "name": "forged",
            "target": "client_2",
            "sha256": "0" * 64,
        }
        for field, value in changes.items():
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "Signatur"),
            ):
                verify_package(
                    dict(self.package, **{field: value}), self.public, "client_1"
                )

    def test_valid_signature_with_wrong_hash_rejected(self):
        package = self.resign_for_hash_test(dict(self.package, sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            verify_package(package, self.public, "client_1")

    def test_untrusted_signing_key_rejected(self):
        key = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(ValueError, "Signatur"):
            verify_package(self.package, key.public_key(), "client_1")

    def test_old_equal_version_and_wrong_target_rejected(self):
        for current in (1, 2):
            with self.assertRaisesRegex(ValueError, "Version"):
                verify_package(self.package, self.public, "client_1", current)
        targeted = self.make_package(2, "client_1")
        with self.assertRaisesRegex(ValueError, "anderen Client"):
            verify_package(targeted, self.public, "client_2")

    def test_duplicate_json_fields_rejected(self):
        path = self.base / "duplicate.json"
        path.write_text('{"version":1,"version":2}', "utf-8")
        with self.assertRaises(ValueError):
            read_package(path)

    def test_even_signed_packages_cannot_supply_new_behaviour(self):
        runtime = load_client_runtime("client_1", threading.Event(), self.root)
        for change in ({"source": "unexpected"}, {"name": "unknown"}):
            package = dict(self.package, **change)
            if "name" in change:
                package["sha256"] = hashlib.sha256(package["name"].encode()).hexdigest()
            with self.subTest(change=change), self.assertRaises(ValueError):
                runtime.install(self.resign_for_hash_test(package))
            self.assertFalse(runtime.state_file.exists())

    def test_install_restart_and_rollback_protection(self):
        runtime = load_client_runtime("client_1", threading.Event(), self.root)
        runtime.install(self.package)
        new = self.make_package(2, name="audit")
        runtime.install(new)
        self.assertEqual(read_package(runtime.state_file), new)
        restarted = load_client_runtime("client_1", threading.Event(), self.root)
        self.assertEqual((restarted.name, restarted.version), ("audit", 2))
        with self.assertRaisesRegex(ValueError, "Version"):
            restarted.install(self.package)

    def test_commit_failure_keeps_previous_profile(self):
        runtime = load_client_runtime("client_1", threading.Event(), self.root)
        runtime.install(self.package)
        with (
            patch("plugin_runtime.write_state", side_effect=OSError),
            self.assertRaises(OSError),
        ):
            runtime.install(self.make_package(2, name="audit"))
        self.assertEqual(runtime.version, 1)
        self.assertEqual(read_package(runtime.state_file), self.package)

    def test_tampered_persistent_package_fails_closed(self):
        runtime = load_client_runtime("client_1", threading.Event(), self.root)
        runtime.install(self.package)
        runtime.state_file.write_bytes(canonical(dict(self.package, version=100)))
        with self.assertRaises(ValueError):
            load_client_runtime("client_1", threading.Event(), self.root)


if __name__ == "__main__":
    unittest.main()
