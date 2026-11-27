"""Integrationstest mit echten Prozessen und den festen Loopback-TCP-Ports."""

import base64
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from audit_event import AUDIT_MARKER
from offline_signer.sign import sign
from setup_lab import setup
from tls_transport import connect
from update_protocol import read_package

ROOT = Path(__file__).resolve().parents[1]


class ConsoleProcess:
    def __init__(self, directory, script):
        self.script = script
        self.lines = []
        self.condition = threading.Condition()
        self.process = subprocess.Popen(
            [sys.executable, "-X", "utf8", "-u", script],
            cwd=directory,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self.reader = threading.Thread(target=self.read_output, daemon=True)
        self.reader.start()

    def read_output(self):
        for line in self.process.stdout:
            with self.condition:
                self.lines.append(line.rstrip("\n"))
                self.condition.notify_all()

    def send(self, text):
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()

    def wait_for(self, predicate, description, timeout=20):
        deadline = time.monotonic() + timeout
        with self.condition:
            while not predicate(self.lines):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.process.poll() is not None:
                    raise AssertionError(
                        f"{self.script}: {description}\n" + "\n".join(self.lines[-12:])
                    )
                self.condition.wait(min(remaining, 0.1))

    def expect(self, text, count=1):
        self.wait_for(
            lambda lines: sum(text in line for line in lines) >= count, repr(text)
        )

    def entries(self, prefix):
        with self.condition:
            payloads = [
                line.split(prefix, 1)[1] for line in self.lines if prefix in line
            ]
            return [
                json.loads(payload) for payload in payloads if payload.startswith("{")
            ]

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.process.stdin.close()
        self.process.stdout.close()


class SimulationTest(unittest.TestCase):
    def test_complete_local_flow(self):
        # Keinen schon laufenden Demo-Prozess stoeren.
        for port in (5001, 5002, 5003):
            with socket.socket() as probe:
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                probe.bind(("127.0.0.1", port))

        processes = []
        with tempfile.TemporaryDirectory(prefix="e2ee-test-", dir=ROOT) as laboratory:
            directory = setup(Path(laboratory) / "lab")

            def start(script, ready):
                child = ConsoleProcess(directory, script)
                processes.append(child)
                child.expect(ready)
                return child

            try:
                audit = start("audit_collector.py", "[AUDIT] TCP")
                config = start("config_server.py", "[CONFIG] TCP")
                router = start("routing_server.py", "[ROUTING] TCP")
                one = start("client_1.py", "[CHAT] client_1 bereit")
                two = start("client_2.py", "[CHAT] client_2 bereit")
                for client in (one, two):
                    client.expect("[CONFIG] Plugin=Standard geladen")

                before = [
                    "Vor Update: Gruesse \u00e4\u00f6\u00fc \U0001f512",
                    "Antwort ohne Audit",
                ]
                one.send(before[0])
                two.expect("client_1: " + before[0])
                two.send(before[1])
                one.expect("client_2: " + before[1])
                router.expect("[ROUTE] ", count=2)
                time.sleep(0.2)
                self.assertEqual(audit.entries("[AUDIT] "), [])

                config.send("update")
                for client in (one, two):
                    client.expect("[CONFIG] Plugin=Audit geladen")
                for client_id in ("client_1", "client_2"):
                    installed = read_package(
                        directory / ".client_state" / client_id / "installed.json"
                    )
                    self.assertEqual(
                        (installed["name"], installed["version"]), ("audit", 2)
                    )
                after = ["Nach Update: vertraulicher Testtext", "Antwort mit Audit"]
                one.send(after[0])
                two.expect("client_1: " + after[0])
                two.send(after[1])
                one.expect("client_2: " + after[1])
                audit.expect("[AUDIT] {", count=4)
                router.expect("[ROUTE] ", count=4)
                entries = audit.entries("[AUDIT] ")
                self.assertEqual(len(entries), 4)
                self.assertEqual({entry["marker"] for entry in entries}, {AUDIT_MARKER})
                for text in after:
                    self.assertNotIn(text, json.dumps(entries))
                ids = {entry["message_id"] for entry in entries}
                self.assertEqual(len(ids), 2)
                for mid in ids:
                    copies = [entry for entry in entries if entry["message_id"] == mid]
                    self.assertEqual(
                        {entry["direction"] for entry in copies},
                        {"incoming", "outgoing"},
                    )
                    self.assertEqual(
                        {entry["client_id"] for entry in copies},
                        {"client_1", "client_2"},
                    )
                    self.assertEqual(len({entry["message_id"] for entry in copies}), 1)
                    for entry in copies:
                        expected_client = (
                            entry["sender"]
                            if entry["direction"] == "outgoing"
                            else entry["recipient"]
                        )
                        self.assertEqual(entry["client_id"], expected_client)
                packets = router.entries("[ROUTE] ")
                for packet in packets:
                    self.assertEqual(
                        set(packet),
                        {
                            "type",
                            "message_id",
                            "sender",
                            "recipient",
                            "timestamp",
                            "nonce",
                            "ciphertext",
                        },
                    )
                    self.assertEqual(len(base64.b64decode(packet["nonce"])), 12)
                    for text in before + after:
                        self.assertNotIn(text, json.dumps(packet, ensure_ascii=False))
                self.assertEqual(len({packet["nonce"] for packet in packets}), 4)

                # Echte Empfaenger-Pruefung: korrekten Ciphertext mit veraenderten
                # Metadaten und danach einen beschaedigten Ciphertext weiterleiten.
                one.send("/quit")
                self.assertEqual(one.process.wait(timeout=5), 0)
                router.expect("[ROUTING] client_1 getrennt")
                config.expect("[CONFIG] client_1 getrennt")
                with connect(5001, timeout=2, root=directory) as attacker:
                    with attacker.makefile("rb") as response:
                        attacker.sendall(
                            b'{"type":"register","client_id":"client_1"}\n'
                        )
                        self.assertEqual(
                            json.loads(response.readline())["type"], "registered"
                        )
                        altered = dict(
                            packets[0], timestamp="2030-01-01T00:00:00+00:00"
                        )
                        attacker.sendall((json.dumps(altered) + "\n").encode())
                        damaged = dict(packets[0])
                        ciphertext = bytearray(base64.b64decode(damaged["ciphertext"]))
                        ciphertext[0] ^= 1
                        damaged["ciphertext"] = base64.b64encode(ciphertext).decode()
                        attacker.sendall((json.dumps(damaged) + "\n").encode())
                        two.expect("manipulierte Nachricht verworfen", count=2)
                router.expect("[ROUTING] client_1 getrennt", count=2)
                time.sleep(0.2)
                self.assertEqual(len(audit.entries("[AUDIT] ")), 4)

                # Ein spaet verbundener Client erhaelt das aktuelle Profil.
                one = start("client_1.py", "[CHAT] client_1 bereit")
                one.expect("[CONFIG] Plugin=Audit geladen")
                one.send("Nach Wiederverbindung")
                two.expect("client_1: Nach Wiederverbindung")
                audit.expect("[AUDIT] {", count=6)

                config.send("reset")
                one.expect("[CONFIG] Plugin=Standard geladen")
                two.expect("[CONFIG] Plugin=Standard geladen", count=2)
                for client_id in ("client_1", "client_2"):
                    self.assertEqual(
                        read_package(
                            directory / ".client_state" / client_id / "installed.json"
                        )["name"],
                        "dummy",
                    )
                two.send("Nach Reset ohne Audit")
                one.expect("client_2: Nach Reset ohne Audit")
                time.sleep(0.2)
                self.assertEqual(len(audit.entries("[AUDIT] ")), 6)

                target = directory / "packages" / "v4.json"
                sign(
                    directory.parent / "offline" / "update-signing.key",
                    "audit",
                    4,
                    "all",
                    target,
                )
                config.send("publish packages/v4.json")
                one.expect("Plugin=Audit geladen", count=2)
                two.expect("Plugin=Audit geladen", count=2)
                one.send("Profilwechsel ohne Neustart")
                two.expect("client_1: Profilwechsel ohne Neustart")
                audit.expect("[AUDIT] {", count=8)
                self.assertEqual(
                    {e["marker"] for e in audit.entries("[AUDIT] ")[-2:]},
                    {AUDIT_MARKER},
                )

                # Ein ausgefallener Collector darf den normalen Chat nicht stoppen.
                audit.close()
                one.send("Chat trotz Collector-Ausfall")
                two.expect("client_1: Chat trotz Collector-Ausfall")
                two.send("Auch die Antwort kommt an")
                one.expect("client_2: Auch die Antwort kommt an")
                for client in (one, two):
                    client.expect("Collector nicht erreichbar")
                    client.send("/quit")
                    self.assertEqual(client.process.wait(timeout=5), 0)
                for child in processes:
                    self.assertFalse(
                        any("Traceback" in line for line in child.lines), child.script
                    )
            finally:
                if sys.exc_info()[0] is not None:
                    for child in processes:
                        print(
                            ascii(
                                f"\n--- {child.script} ---\n"
                                + "\n".join(child.lines[-20:])
                            )
                        )
                for child in reversed(processes):
                    if not child.process.stdout.closed:
                        child.close()


if __name__ == "__main__":
    unittest.main()
