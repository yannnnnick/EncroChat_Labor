"""Lab-Neustart, Sicherungen und Lebenszyklus echter Windows-Kindprozesse."""

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

from start_lab import (
    ROOT,
    LabSession,
    WindowsJob,
    check_ports,
    launcher_lock,
    prepare_lab,
)
from update_protocol import load_public_key, read_package, verify_package


@unittest.skipUnless(os.name == "nt", "Windows-Konsolenstarter")
class LabStartTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="launcher-test-", dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_fresh_baseline_archives_previous_client_state_and_renews_trust(self):
        self.assertIsNone(prepare_lab(self.root))
        runtime = self.root / ".lab" / "runtime"
        old_ca = (runtime / "trust" / "ca.pem").read_bytes()
        marker = runtime / ".client_state" / "client_1" / "previous-demo.txt"
        marker.parent.mkdir(parents=True)
        marker.write_text("previous run", encoding="utf-8")
        backup = prepare_lab(self.root)
        self.assertEqual(
            (backup / "runtime" / marker.relative_to(runtime)).read_text("utf-8"),
            "previous run",
        )
        self.assertFalse((runtime / ".client_state").exists())
        self.assertNotEqual(old_ca, (runtime / "trust" / "ca.pem").read_bytes())
        package = read_package(runtime / "packages" / "initial.json")
        public = load_public_key(runtime / "trust" / "update-signing.pub")
        for client_id in ("client_1", "client_2"):
            verify_package(package, public, client_id)
        self.assertEqual((package["name"], package["version"]), ("dummy", 1))

    def test_setup_failure_preserves_existing_lab(self):
        destination = self.root / ".lab"
        destination.mkdir()
        marker = destination / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        with patch(
            "setup_lab.setup", side_effect=OSError("simulated provisioning failure")
        ):
            with self.assertRaises(OSError):
                prepare_lab(self.root)
        self.assertEqual(marker.read_text("utf-8"), "keep")
        self.assertEqual(list(self.root.glob(".lab-backup-*")), [])

    def test_busy_port_aborts_before_reset_and_keeps_foreign_listener(self):
        destination = self.root / ".lab"
        destination.mkdir()
        marker = destination / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        check_ports()
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(("127.0.0.1", 5002))
            listener.listen()
            with self.assertRaisesRegex(RuntimeError, "5002"):
                LabSession(Mock(), self.root).start()
            self.assertEqual(listener.getsockname(), ("127.0.0.1", 5002))
        self.assertEqual(marker.read_text("utf-8"), "keep")
        self.assertEqual(list(self.root.glob(".lab-backup-*")), [])

    def test_second_launcher_is_blocked_and_lock_can_be_reused(self):
        code = (
            "from pathlib import Path; from start_lab import launcher_lock; import sys\n"
            "try:\n"
            "    with launcher_lock(Path(sys.argv[1])): pass\n"
            "except RuntimeError: sys.exit(7)\n"
        )
        with launcher_lock(self.root):
            result = subprocess.run(
                [sys.executable, "-c", code, str(self.root)],
                cwd=ROOT,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 7, result.stderr)
        with launcher_lock(self.root):
            pass

    @contextmanager
    def running_session(self):
        processes = []
        real_popen = subprocess.Popen

        def headless(*args, **kwargs):
            kwargs.update(
                creationflags=(kwargs["creationflags"] & ~subprocess.CREATE_NEW_CONSOLE)
                | subprocess.CREATE_NO_WINDOW,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
            )
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        with WindowsJob() as job:
            session = LabSession(job, self.root)
            try:
                with patch("start_lab.subprocess.Popen", side_effect=headless):
                    yield session, job, processes
            finally:
                session.stop()
                job.close()
                for process in processes:
                    process.communicate(timeout=5)

    def wait_versions(self, session, version):
        def installed():
            return all(
                read_package(
                    session.runtime / ".client_state" / client_id / "installed.json"
                )["version"]
                == version
                for client_id in ("client_1", "client_2")
            )

        session.wait_until(installed, f"Plugin-Version {version}")

    def test_all_five_processes_update_then_restart_with_dummy_v1(self):
        with (
            patch.dict(
                os.environ, {"LAB_TLS_KEYLOG": str(self.root / "inherited.keylog")}
            ),
            self.running_session() as (session, _, processes),
        ):
            session.start()
            self.assertEqual(len(session.processes), 5)
            self.wait_versions(session, 1)
            config = processes[1]
            config.stdin.write("update\n")
            config.stdin.flush()
            self.wait_versions(session, 2)
            session.stop()
            check_ports()
            backup = session.start()
            self.wait_versions(session, 1)
            for client_id in ("client_1", "client_2"):
                previous = read_package(
                    backup / "runtime" / ".client_state" / client_id / "installed.json"
                )
                self.assertEqual(previous["version"], 2)
            self.assertFalse((self.root / "inherited.keylog").exists())
        check_ports()

    def test_job_close_kills_all_children_and_releases_ports(self):
        with self.running_session() as (session, job, processes):
            session.start()
            job.close()
            for process in processes:
                process.wait(timeout=5)
            # Windows may need a moment to release descendants' TCP sockets.
            deadline = time.monotonic() + 5
            while True:
                try:
                    check_ports()
                    break
                except RuntimeError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)

    def test_partial_start_failure_stops_already_started_services(self):
        with self.running_session() as (session, job, processes):
            real_attach = job.attach

            def fail_third(process):
                if len(processes) == 3:
                    raise OSError("simulated job assignment failure")
                real_attach(process)

            with patch.object(job, "attach", side_effect=fail_third):
                with self.assertRaisesRegex(OSError, "simulated"):
                    session.start()
            self.assertTrue(all(process.poll() is not None for process in processes))
            check_ports()


if __name__ == "__main__":
    unittest.main()
