"""Reale Praesentationsphasen, Mitschnitt, Debugschluessel und Resume."""

import csv
import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from audit_event import AUDIT_MARKER
from demo_capture import (
    Capture,
    find_program,
    loopback_interface,
    merge_keylogs,
    pcapng_packets,
    repair_graph_colors,
    run,
    write_graph_profile,
)
from demo_controller import new_results
from start_lab import ROOT, LabSession, WindowsJob, check_ports


class CaptureFormatTest(unittest.TestCase):
    def test_graph_colors_and_repair_of_existing_profile(self):
        with tempfile.TemporaryDirectory(prefix="demo-test-", dir=ROOT) as root:
            profile = Path(root)
            write_graph_profile(profile, marked=True)
            path = profile / "io_graphs"
            with path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.reader(handle, escapechar="\\", doublequote=False))
            self.assertEqual(len(rows), 10)
            for row in rows:
                self.assertEqual(len(row), 10)
                self.assertRegex(row[3], r"^#[0-9A-Fa-f]{6}$")
            self.assertIn('frame.comment contains "LAB-PHASE-1 BEGIN"', rows[3])
            self.assertFalse(repair_graph_colors(profile))
            broken = path.read_text("utf-8").replace('"#', '"')
            path.write_text(broken, "utf-8")
            self.assertTrue(repair_graph_colors(profile))
            self.assertEqual(
                (profile / "io_graphs.before-color-fix").read_text("utf-8"), broken
            )
            self.assertFalse(repair_graph_colors(profile))

    def test_interface_name_is_discovered_instead_of_number(self):
        self.assertEqual(
            loopback_interface(
                "7. \\Device\\NPF_x (WiFi)\n31. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)"
            ),
            "\\Device\\NPF_Loopback",
        )
        with self.assertRaises(RuntimeError):
            loopback_interface("1. physical (Ethernet)")

    def test_missing_tshark_produces_manual_fallback(self):
        with tempfile.TemporaryDirectory(prefix="demo-test-", dir=ROOT) as root:
            with patch("demo_capture.find_program", return_value=None):
                capture = Capture(new_results(root))
            self.assertFalse(capture.start())
            self.assertEqual(capture.info["state"], "manual_required")
            self.assertIn("VOR dem Laborstart", capture.manual_hint())
            self.assertEqual(capture.finish()["state"], "invalid")
            self.assertFalse(
                capture.finished
            )  # spaeter gespeicherte manuelle Datei noch pruefbar

    def test_empty_capture_and_invalid_keylogs_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="demo-test-", dir=ROOT) as root:
            path = new_results(root)
            (path / "demo.pcapng").write_bytes(b"not pcapng")
            with self.assertRaises(ValueError):
                pcapng_packets(path / "demo.pcapng")
            (path / "tls-client1.keys").write_text("invalid NSS line", "ascii")
            with self.assertRaises(ValueError):
                merge_keylogs(path)
            self.assertFalse((path / "tls-combined.keys").exists())


@unittest.skipUnless(os.name == "nt", "Windows-Jobobjekte")
class DemoIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="demo-test-", dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    @contextmanager
    def session(self, mode="fresh"):
        with WindowsJob() as job:
            session = LabSession(job, self.root, mode=mode, headless=True)
            try:
                session.start()
                yield session
            finally:
                session.stop()
                for _, process in session.processes:
                    if process.stdin:
                        process.stdin.close()
        check_ports()

    def test_six_phases_without_keylogging_and_resume_preserves_versions(self):
        with self.session() as session:
            demo = session.demo
            with self.assertRaisesRegex(RuntimeError, "Zuerst Phase"):
                demo.phase(3)
            for number in range(1, 7):
                result = demo.phase(number)
                self.assertEqual(result["result"], "PASS", result)
            before = len(demo.select("chat_encrypted"))
            self.assertEqual(demo.phase(6)["result"], "PASS")
            self.assertEqual(len(demo.select("chat_encrypted")), before)
            self.assertTrue(session.config_stopped)
            demo.refresh()
            attempts = len(demo.select("config_connect_attempt"))
            time.sleep(2.2)  # laenger als die bisherige Fehlerschleife
            demo.refresh()
            self.assertEqual(len(demo.select("config_connect_attempt")), attempts)
            self.assertEqual(
                {e["actor"] for e in demo.select("config_paused")},
                {"client_1", "client_2"},
            )
            for actor in ("client_1", "client_2"):
                log = (demo.directory / (actor + ".log")).read_text("utf-8")
                self.assertEqual(log.count("keine weiteren Verbindungsversuche"), 1)
                self.assertNotIn("Neuer Versuch", log)
            self.assertEqual(demo.snapshot["counts"]["audit_events"], 6)
            self.assertEqual(demo.snapshot["counts"]["chat_sent"], 6)
            self.assertEqual(demo.snapshot["counts"]["chat_decrypted"], 6)
            for name in ("tls-client1.keys", "tls-client2.keys"):
                self.assertEqual((demo.directory / name).stat().st_size, 0)
            trust = (session.runtime / "trust" / "update-signing.pub").read_bytes()
        with self.session("resume") as session:
            self.assertEqual(
                (session.runtime / "trust" / "update-signing.pub").read_bytes(), trust
            )
            self.assertTrue(
                all(
                    state["version"] == 2
                    for state in session.demo.client_states().values()
                )
            )
            session.demo.wait(
                lambda: len(session.demo.select("update_rejected")) >= 2,
                "Rollback des beim Resume angebotenen v1 ablehnen",
            )
            self.assertTrue(
                all(
                    "Version" in e["reason"]
                    for e in session.demo.select("update_rejected")
                )
            )
            self.assertTrue(
                session.demo.send("LAB-RESUME-007", audit=True)["decrypted"]
            )

    def test_real_capture_keylogs_all_services_and_repeat_W(self):
        tshark = find_program("tshark")
        if not tshark:
            self.skipTest("TShark nicht installiert")
        interfaces = run([tshark, "-D"])
        if interfaces.returncode or "loopback" not in interfaces.stdout.lower():
            self.skipTest("Npcap-Loopback nicht verfuegbar")
        with self.session("presentation") as session:
            demo = session.demo
            self.assertEqual(demo.capture.info["state"], "recording", demo.capture.info)
            for number in range(1, 7):
                result = demo.phase(number)
                self.assertEqual(result["result"], "PASS", result)
            real_popen = subprocess.Popen
            opens = []

            def intercept(args, **kwargs):
                if Path(args[0]).name.lower() == "wireshark.exe" and "-r" in args:
                    opens.append(args)
                    return None
                return real_popen(args, **kwargs)

            # Das erste W stoppt die noch laufende echte Aufzeichnung.
            with (
                patch("demo_capture.subprocess.Popen", side_effect=intercept),
                patch("demo_controller.webbrowser.open", return_value=True),
            ):
                demo.open_wireshark()
            info = demo.capture.info
            self.assertEqual(info["state"], "complete", info)
            self.assertTrue(info["graceful_stop"])
            self.assertGreater(pcapng_packets(demo.capture.path), 20)
            self.assertGreater(info["matching_tls_sessions"], 5)
            self.assertEqual(info["annotations"]["state"], "complete", info)
            self.assertEqual(info["packet_index"]["state"], "complete", info)
            message_packets = info["packet_index"]["messages"][
                demo.last_message["message_id"]
            ]
            self.assertGreaterEqual(len(message_packets["chat"]), 2)
            self.assertEqual(len(message_packets["audit"]), 2)
            report_html = (demo.directory / "phase-report.html").read_text("utf-8")
            self.assertIn(demo.last_message["message_id"], report_html)
            self.assertIn("frame.number ==", report_html)
            self.assertIn("Standard v1", report_html)
            self.assertNotIn("<script src=", report_html)
            # Jeder genaue Filter muss den TLS-entschluesselten Inhalt mit
            # derselben Nachrichten-ID enthalten, nicht nur einen nahen Marker.
            for channel in ("chat", "audit"):
                for packet in message_packets[channel]:
                    checked = run(
                        [
                            tshark,
                            "-n",
                            "-r",
                            str(demo.capture.path),
                            "-o",
                            "tls.keylog_file:"
                            + str(demo.directory / "tls-combined.keys"),
                            "-d",
                            f"tcp.port=={5001 if channel == 'chat' else 5003},tls",
                            "-Y",
                            f"frame.number == {packet['frame']}",
                            "-T",
                            "fields",
                            "-e",
                            "data.data",
                        ]
                    )
                    self.assertEqual(checked.returncode, 0)
                    self.assertIn(
                        demo.last_message["message_id"].encode(),
                        bytes.fromhex(
                            checked.stdout.strip().replace(",", "").replace(":", "")
                        ),
                    )
            marked = Path(info["annotations"]["path"])
            comments = run(
                [
                    tshark,
                    "-n",
                    "-r",
                    str(marked),
                    "-Y",
                    'frame.comment contains "LAB-"',
                    "-T",
                    "fields",
                    "-e",
                    "frame.comment",
                ]
            )
            self.assertEqual(comments.returncode, 0)
            for number in range(1, 7):
                self.assertIn(f"LAB-PHASE-{number} BEGIN", comments.stdout)
            self.assertIn("LAB-CONFIG-OFFLINE", comments.stdout)
            fields = [
                "-T",
                "fields",
                "-e",
                "frame.time_epoch",
                "-e",
                "frame.len",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "tcp.payload",
            ]
            raw_packets = run([tshark, "-n", "-r", str(demo.capture.path)] + fields)
            marked_packets = run([tshark, "-n", "-r", str(marked)] + fields)
            self.assertEqual(raw_packets.returncode, 0)
            self.assertEqual(marked_packets.returncode, 0)
            self.assertTrue(
                raw_packets.stdout == marked_packets.stdout,
                "Metadatenmarkierungen duerfen keine Paketnutzdaten oder Zeitstempel aendern",
            )
            for actor in ("client_1", "client_2"):
                connections = [
                    e for e in demo.select("tls_connected") if e["actor"] == actor
                ]
                self.assertEqual(
                    {e["port"] for e in connections if e["port"] != 5004},
                    {5001, 5002, 5003},
                )
                self.assertTrue(all(e["version"] == "TLSv1.3" for e in connections))
                self.assertTrue(
                    all(
                        e["pin_verified"]
                        for e in connections
                        if e["service_port"] == 5002
                    )
                )
            combined = demo.directory / "tls-combined.keys"
            self.assertTrue(combined.is_file())
            # Nach TLS-Debugentschluesselung JSON aus echten Netzwerkpaketen lesen.
            args = [
                tshark,
                "-n",
                "-r",
                str(marked),
                "-o",
                "tls.keylog_file:" + str(combined),
            ]
            for port in (5001, 5002, 5003, 5004):
                args += ["-d", f"tcp.port=={port},tls"]
            result = run(
                args
                + [
                    "-Y",
                    "tls && data.data",
                    "-T",
                    "fields",
                    "-e",
                    "tcp.srcport",
                    "-e",
                    "tcp.dstport",
                    "-e",
                    "data.data",
                ]
            )
            self.assertEqual(result.returncode, 0)
            payloads = {5001: bytearray(), 5002: bytearray(), 5003: bytearray()}
            for line in result.stdout.splitlines():
                fields = line.split("\t")
                if len(fields) != 3:
                    continue
                for port in payloads:
                    if str(port) in fields[:2]:
                        for hexdata in fields[2].split(","):
                            payloads[port].extend(
                                bytes.fromhex(hexdata.replace(":", ""))
                            )
            mid = demo.last_message["message_id"].encode()
            self.assertIn(mid, payloads[5001])
            self.assertIn(mid, payloads[5003])
            self.assertNotIn(b"LAB-PERSISTENCE-006", payloads[5001])
            self.assertIn(b"ciphertext", payloads[5001])
            self.assertIn(b"signature", payloads[5002])
            self.assertNotIn(b"LAB-PERSISTENCE-006", payloads[5003])
            self.assertIn(AUDIT_MARKER.encode(), payloads[5003])
            self.assertIn(b"outgoing", payloads[5003])
            self.assertIn(b"incoming", payloads[5003])
            checksums = {
                p: hashlib.sha256(p.read_bytes()).digest()
                for p in (demo.capture.path, marked, combined)
            }
            with (
                patch("demo_capture.subprocess.Popen", side_effect=intercept),
                patch("demo_controller.webbrowser.open", return_value=True),
            ):
                demo.open_wireshark()
            self.assertEqual(len(opens), 2)
            self.assertIn(str(marked), opens[0])
            self.assertIn("tls.keylog_file:" + str(combined), opens[0])
            for path, checksum in checksums.items():
                self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), checksum)
            session.ensure_alive()
            self.assertTrue(demo.send("LAB-AFTER-W-008", audit=True)["decrypted"])
            demo.report()
            report = json.loads((demo.directory / "results.json").read_text("utf-8"))
            self.assertEqual([p["result"] for p in report["phases"]], ["PASS"] * 6)
