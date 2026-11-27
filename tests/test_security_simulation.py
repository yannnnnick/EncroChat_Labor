"""Laborszenarien A-D mit echten Programmen, TLS und synthetischen Nachrichten."""

import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path

from test_simulation import ROOT, ConsoleProcess

from audit_event import AUDIT_MARKER
from offline_signer.sign import sign
from setup_lab import setup
from update_protocol import canonical, read_package


class SecurityScenarioTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="security-scenario-", dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = setup(self.base / "lab")
        self.offline = self.root.parent / "offline"
        self.private = self.offline / "update-signing.key"
        self.processes = []
        self.addCleanup(self.close_processes)
        self.audit = self.start("audit_collector.py", "[AUDIT] TCP")
        self.config = self.start("config_server.py", "[CONFIG] TCP")
        self.router = self.start("routing_server.py", "[ROUTING] TCP")
        self.one = self.start("client_1.py", "[CHAT] client_1 bereit")
        self.two = self.start("client_2.py", "[CHAT] client_2 bereit")
        for client in (self.one, self.two):
            client.expect("Plugin=Standard geladen")

    def close_processes(self):
        for process in reversed(self.processes):
            if not process.process.stdout.closed:
                process.close()

    def start(self, script, ready):
        child = ConsoleProcess(self.root, script)
        self.processes.append(child)
        child.expect(ready)
        return child

    def make_package(self, name, version, filename, target="all"):
        return sign(
            self.private, name, version, target, self.root / "packages" / filename
        )

    def state(self, client_id):
        return read_package(self.root / ".client_state" / client_id / "installed.json")

    def assert_chat_without_audit(self, marker):
        self.one.send(marker + " outgoing")
        self.two.expect("client_1: " + marker + " outgoing")
        self.two.send(marker + " reply")
        self.one.expect("client_2: " + marker + " reply")
        time.sleep(0.2)
        self.assertEqual(self.audit.entries("[AUDIT] "), [])

    def test_A_normal_tls_chat_without_audit(self):
        self.assert_chat_without_audit("SYNTHETIC A")
        self.assertEqual(self.state("client_1")["version"], 1)
        self.assertEqual(self.state("client_2")["version"], 1)

    def test_B_attacker_changes_package_without_valid_signature(self):
        package = self.make_package("audit", 2, "original.json")
        package["name"] = "dummy"
        (self.root / "packages" / "tampered.json").write_bytes(canonical(package))
        self.config.send("publish packages/tampered.json")
        for client in (self.one, self.two):
            client.expect("Update abgelehnt")
        self.assert_chat_without_audit("SYNTHETIC B")
        for client_id in ("client_1", "client_2"):
            self.assertEqual(self.state(client_id)["version"], 1)

    def test_C_compromised_distributor_cannot_sign(self):
        # Im gesamten Server-Laufzeitverzeichnis gibt es keinen privaten
        # Signierschluessel und kein Offline-Signierwerkzeug.
        self.assertFalse((self.root / "offline_signer").exists())
        self.assertFalse(list(self.root.rglob("*signing.key")))
        initial = self.state("client_1")
        malicious = dict(initial, name="audit", version=20)
        malicious["sha256"] = hashlib.sha256(malicious["name"].encode()).hexdigest()
        # Kompromittierter Server kennt Hashverfahren und Protokoll, aber kann
        # die Signatur nicht erneuern. Korrektes TLS/Pinning hilft ihm dabei nicht.
        (self.root / "packages" / "server-forged.json").write_bytes(
            canonical(malicious)
        )
        self.config.send("publish packages/server-forged.json client_1")
        self.one.expect("Update abgelehnt")
        unsigned = dict(malicious)
        del unsigned["signature"]
        (self.root / "packages" / "unsigned.json").write_bytes(canonical(unsigned))
        self.config.send("publish packages/unsigned.json client_2")
        self.two.expect("Update abgelehnt")
        self.assert_chat_without_audit("SYNTHETIC C")
        for client_id in ("client_1", "client_2"):
            self.assertEqual(self.state(client_id)["version"], 1)

    def test_D_signed_profile_and_independent_client_updates(self):
        self.make_package("audit", 2, "one.json", "client_1")
        self.make_package("audit", 2, "two.json", "client_2")
        self.config.send("publish packages/one.json client_1")
        self.one.expect("Plugin=Audit geladen")
        self.assertEqual(self.state("client_1")["version"], 2)
        self.assertEqual(self.state("client_2")["version"], 1)
        self.one.send("SYNTHETIC D only client 1")
        self.two.expect("client_1: SYNTHETIC D only client 1")
        self.audit.expect("[AUDIT] {", count=1)
        self.two.send("SYNTHETIC D reverse direction")
        self.one.expect("client_2: SYNTHETIC D reverse direction")
        self.audit.expect("[AUDIT] {", count=2)
        entries = self.audit.entries("[AUDIT] ")
        self.assertEqual({entry["client_id"] for entry in entries}, {"client_1"})
        self.assertEqual(
            {entry["direction"] for entry in entries}, {"incoming", "outgoing"}
        )

        # Signiertes Paket fuer Client 1 darf Client 2 nicht aktivieren.
        self.config.send("publish packages/one.json client_2")
        self.two.expect("Update abgelehnt")
        self.assertEqual(self.state("client_2")["version"], 1)
        self.config.send("publish packages/two.json client_2")
        self.two.expect("Plugin=Audit geladen")
        self.one.send("SYNTHETIC D both clients")
        self.two.expect("client_1: SYNTHETIC D both clients")
        self.audit.expect("[AUDIT] {", count=4)
        latest = self.audit.entries("[AUDIT] ")[-2:]
        self.assertEqual(
            {entry["client_id"] for entry in latest}, {"client_1", "client_2"}
        )
        self.assertEqual({entry["marker"] for entry in latest}, {AUDIT_MARKER})
        packets = self.router.entries("[ROUTE] ")
        self.assertTrue(packets)
        self.assertNotIn("SYNTHETIC D", json.dumps(packets))

        # Ein signierter Reset ist ein neues Update, kein Versions-Rollback.
        self.make_package("dummy", 3, "reset-one.json", "client_1")
        self.config.send("publish packages/reset-one.json client_1")
        self.one.expect("Plugin=Standard geladen", count=2)
        self.assertEqual(self.state("client_1")["version"], 3)
        self.assertEqual(self.state("client_2")["version"], 2)
        self.one.send("/quit")
        self.assertEqual(self.one.process.wait(timeout=5), 0)
        self.router.expect("client_1 getrennt")
        self.config.expect("client_1 getrennt")
        self.one = self.start("client_1.py", "[CHAT] client_1 bereit")
        self.one.expect("Plugin=Standard geladen")
        self.config.send("publish packages/one.json client_1")
        self.one.expect("Update abgelehnt")
        self.assertEqual(self.state("client_1")["version"], 3)
        self.one.send("SYNTHETIC D after restart and stale offer")
        self.two.expect("client_1: SYNTHETIC D after restart and stale offer")
        self.audit.expect("[AUDIT] {", count=5)
        time.sleep(0.2)
        self.assertEqual(len(self.audit.entries("[AUDIT] ")), 5)
        self.assertEqual(self.audit.entries("[AUDIT] ")[-1]["client_id"], "client_2")

    def test_reconnect_gets_targeted_signed_offer_while_offline(self):
        self.one.send("/quit")
        self.assertEqual(self.one.process.wait(timeout=5), 0)
        self.router.expect("client_1 getrennt")
        self.config.expect("client_1 getrennt")
        self.make_package("audit", 2, "offline-one.json", "client_1")
        self.config.send("publish packages/offline-one.json client_1")
        self.config.expect("Paket an 0 Client(s) gesendet")
        self.one = self.start("client_1.py", "[CHAT] client_1 bereit")
        self.one.expect("Plugin=Audit geladen")
        self.assertEqual(self.state("client_1")["version"], 2)
        self.assertEqual(self.state("client_2")["version"], 1)
        self.one.send("SYNTHETIC cached update after reconnect")
        self.two.expect("client_1: SYNTHETIC cached update after reconnect")
        self.audit.expect("[AUDIT] {", count=1)
        self.assertEqual(self.audit.entries("[AUDIT] ")[0]["client_id"], "client_1")


if __name__ == "__main__":
    unittest.main()
