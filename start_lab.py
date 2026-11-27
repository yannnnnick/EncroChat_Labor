"""Zentraler Windows-Labstart: lokal vorbereiten, fuenf Konsolen, Neustart/Stop."""

import argparse
import ctypes
import hashlib
import hmac
import os
import runpy
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import uuid
from contextlib import ExitStack, contextmanager
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PORTS = (5001, 5002, 5003, 5004)
COMPONENTS = (
    ("audit_collector.py", "01 Audit-Collector", 5003),
    ("config_server.py", "02 Config-Server", 5002),
    ("routing_server.py", "03 Routing-Server", 5001),
    ("client_1.py", "04 Client 1", None),
    ("client_2.py", "05 Client 2", None),
)


def check_environment():
    if os.name != "nt":
        raise RuntimeError("Der Konsolenstarter benoetigt Windows.")
    if sys.version_info < (3, 10) or not ssl.HAS_TLSv1_3:
        raise RuntimeError("Python ab 3.10 mit TLS-1.3-faehigem OpenSSL erforderlich.")
    try:
        from setup_lab import FILES
    except ImportError as exc:
        raise RuntimeError(
            "Python-Abhaengigkeiten fehlen. Installation siehe README.md; "
            "der Starter fuehrt keine Downloads aus."
        ) from exc
    for name in (*FILES, "offline_signer/sign.py"):
        if not (ROOT / name).is_file():
            raise RuntimeError(f"Projektdatei fehlt: {name}")


def check_ports():
    """Drei Dienste und Rogue-Testport pruefen, ohne fremde Prozesse anzufassen."""
    with ExitStack() as stack:
        for port in PORTS:
            probe = stack.enter_context(socket.socket())
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as exc:
                raise RuntimeError(
                    f"Port {port} ist belegt oder nicht verfuegbar. "
                    "Laufendes Lab zuerst in seiner Steuerkonsole mit q beenden; "
                    "manuell gestartete Konsolen vorher schliessen."
                ) from exc


def local_directory(path, root):
    """Vor Umbenennungen absolute Ziele und Windows-Reparse-Points pruefen."""
    if path.parent != root or path.resolve().parent != root:
        raise RuntimeError("Labverzeichnis liegt ausserhalb des Projektordners.")
    if os.path.lexists(path):
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        if (
            path.is_symlink()
            or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
            or not path.is_dir()
        ):
            raise RuntimeError(
                "Labverzeichnis muss ein lokaler Ordner ohne Verknuepfung sein."
            )


def prepare_lab(root=ROOT):
    """Erst vollstaendig provisionieren, dann bisherigen Stand reversibel sichern."""
    from setup_lab import setup

    root = Path(root).resolve()
    destination = root / ".lab"
    suffix = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    staging = root / (".lab-preparing-" + suffix)
    backup = root / (".lab-backup-" + suffix)
    for path in (destination, staging, backup):
        local_directory(path, root)
    # Fehler beim Erzeugen lassen das bestehende Labor unangetastet.
    setup(staging)
    previous = None
    if destination.exists():
        destination.rename(backup)
        previous = backup
    try:
        staging.rename(destination)
    except OSError:
        if previous is not None and not destination.exists():
            previous.rename(destination)
        raise
    return previous


@contextmanager
def launcher_lock(root=ROOT):
    """Windows gibt die Sperre auch beim Schliessen des Konsolenfensters frei."""
    import msvcrt

    with (Path(root) / ".lab-start.lock").open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise RuntimeError(
                "Eine Lab-Steuerung laeuft bereits. Dort r fuer Neustart "
                "oder q zum Beenden eingeben."
            ) from exc
        try:
            yield
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


class WindowsJob:
    """Kill-on-close beendet eigene Kinder auch beim Schliessen mit dem Fenster-X."""

    def __init__(self):
        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_longlong),
                ("job_time", ctypes.c_longlong),
                ("flags", wintypes.DWORD),
                ("min_ws", ctypes.c_size_t),
                ("max_ws", ctypes.c_size_t),
                ("active", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD),
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("basic", BasicLimits),
                ("io", ctypes.c_ulonglong * 6),
                ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t),
                ("peak_process", ctypes.c_size_t),
                ("peak_job", ctypes.c_size_t),
            ]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self.api.SetInformationJobObject.restype = wintypes.BOOL
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.AssignProcessToJobObject.restype = wintypes.BOOL
        self.api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.api.TerminateJobObject.restype = wintypes.BOOL
        self.api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.api.OpenProcess.restype = wintypes.HANDLE
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(
            self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            error = ctypes.get_last_error()
            self.close()
            raise ctypes.WinError(error)

    def attach(self, process):
        handle = self.api.OpenProcess(0x0100 | 0x0001, False, process.pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self.api.AssignProcessToJobObject(self.handle, handle):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.api.CloseHandle(handle)

    def resume(self, process):
        # Popen schliesst den primaeren Threadhandle. Der suspendierte Prozess
        # besitzt genau einen Thread; ueber Toolhelp dessen Handle neu oeffnen.
        class ThreadEntry(ctypes.Structure):
            _fields_ = [
                ("size", wintypes.DWORD),
                ("usage", wintypes.DWORD),
                ("thread_id", wintypes.DWORD),
                ("process_id", wintypes.DWORD),
                ("base_priority", wintypes.LONG),
                ("delta_priority", wintypes.LONG),
                ("flags", wintypes.DWORD),
            ]

        self.api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self.api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        for name in ("Thread32First", "Thread32Next"):
            function = getattr(self.api, name)
            function.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
            function.restype = wintypes.BOOL
        self.api.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.api.OpenThread.restype = wintypes.HANDLE
        self.api.ResumeThread.argtypes = [wintypes.HANDLE]
        self.api.ResumeThread.restype = wintypes.DWORD
        snapshot = self.api.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            found = self.api.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.process_id == process.pid:
                    thread = self.api.OpenThread(0x0002, False, entry.thread_id)
                    if not thread:
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        if self.api.ResumeThread(thread) == 0xFFFFFFFF:
                            raise ctypes.WinError(ctypes.get_last_error())
                        return
                    finally:
                        self.api.CloseHandle(thread)
                found = self.api.Thread32Next(snapshot, ctypes.byref(entry))
            raise RuntimeError("Suspendierter Labprozess hat keinen startbaren Thread.")
        finally:
            self.api.CloseHandle(snapshot)

    def terminate(self):
        if self.handle and not self.api.TerminateJobObject(self.handle, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.handle:
            return

        class Accounting(ctypes.Structure):
            _fields_ = [
                ("times", ctypes.c_longlong * 4),
                ("faults", wintypes.DWORD),
                ("total", wintypes.DWORD),
                ("active", wintypes.DWORD),
                ("terminated", wintypes.DWORD),
            ]

        self.api.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        self.api.QueryInformationJobObject.restype = wintypes.BOOL
        deadline = time.monotonic() + 5
        while True:
            accounting = Accounting()
            if not self.api.QueryInformationJobObject(
                self.handle,
                1,
                ctypes.byref(accounting),
                ctypes.sizeof(accounting),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if accounting.active == 0:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "Windows hat die Labprozesse nicht rechtzeitig beendet."
                )
            time.sleep(0.02)

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def set_title(title):
    ctypes.windll.kernel32.SetConsoleTitleW("Lab - " + title)


def run_component(script, runtime):
    title = next(title for filename, title, _ in COMPONENTS if filename == script)
    set_title(title)
    from window_layout import apply_layout

    apply_layout(
        Path(os.environ.get("LAB_LAYOUT_FILE", ROOT / "window_layout.json")),
        Path(script).stem,
    )
    sys.path.insert(0, str(runtime))
    runpy.run_path(str(runtime / script), run_name="__main__")


class LabSession:
    def __init__(
        self, job, root=ROOT, mode="fresh", headless=False, manual_capture_wait=None
    ):
        self.job = job
        self.root = Path(root).resolve()
        self.runtime = self.root / ".lab" / "runtime"
        self.processes = []
        self.mode = mode
        self.headless = headless
        self.manual_capture_wait = manual_capture_wait
        self.demo = None
        self.config_stopped = False
        self.component_jobs = {}
        self.output_handles = []
        self.environment = os.environ.copy()
        # Jede Vorfuehrung beginnt ohne geerbte TLS-Keylog-Einstellungen.
        for variable in (
            "LAB_TLS_KEYLOG",
            "SSLKEYLOGFILE",
            "LAB_DEMO_DIR",
            "LAB_DEMO_ACTOR",
        ):
            self.environment.pop(variable, None)

    def ensure_alive(self):
        for title, process in self.processes:
            if self.config_stopped and title == "02 Config-Server":
                continue
            if process.poll() is not None:
                raise RuntimeError(
                    f"{title} wurde beendet (Exitcode {process.returncode})."
                )
        if self.demo and self.demo.capture and not self.demo.capture.alive():
            if (
                self.demo.capture.info["state"] == "failed"
                and not self.demo.capture_warning
            ):
                print(
                    "[LAB] WARNUNG: Mitschnitt unerwartet beendet; Capture-Erfolg nicht bestaetigt.",
                    flush=True,
                )
                self.demo.capture_warning = True

    def wait_until(self, probe, description, timeout=15):
        from window_layout import pump_window_messages

        deadline = time.monotonic() + timeout
        while True:
            pump_window_messages()
            self.ensure_alive()
            try:
                if probe():
                    return
            except (OSError, ValueError):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Zeitlimit beim Warten auf {description}.")
            time.sleep(0.1)

    def tls_ready(self, port):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(self.runtime / "trust" / "ca.pem"))
        with socket.create_connection(("127.0.0.1", port), timeout=0.5) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as secured:
                if port == 5002:
                    expected = (
                        (self.runtime / "trust" / "config-pin.sha256")
                        .read_text("ascii")
                        .strip()
                    )
                    actual = hashlib.sha256(
                        secured.getpeercert(binary_form=True)
                    ).hexdigest()
                    if not hmac.compare_digest(expected, actual):
                        raise ValueError("Config-Pin stimmt nicht ueberein")
        return True

    def client_ready(self, client_id):
        from update_protocol import load_public_key, read_package, verify_package

        package = read_package(
            self.runtime / ".client_state" / client_id / "installed.json"
        )
        key = load_public_key(self.runtime / "trust" / "update-signing.pub")
        verify_package(package, key, client_id)
        valid = self.mode == "resume" or (
            package["name"] == "dummy" and package["version"] == 1
        )
        if self.demo:
            self.demo.refresh()
            valid = valid and any(
                e["actor"] == client_id for e in self.demo.select("client_ready")
            )
        return valid

    def resume_lab(self):
        from setup_lab import FILES
        from update_protocol import load_public_key, read_package, verify_package

        local_directory(self.root / ".lab", self.root)
        if not self.runtime.is_dir():
            raise RuntimeError(
                "Kein Labor fuer Resume vorhanden; zuerst --mode fresh verwenden"
            )
        key = load_public_key(self.runtime / "trust" / "update-signing.pub")
        for client in ("client_1", "client_2"):
            state = self.runtime / ".client_state" / client / "installed.json"
            verify_package(
                read_package(
                    state
                    if state.exists()
                    else self.runtime / "packages" / "initial.json"
                ),
                key,
                client,
            )
        changed = [
            name
            for name in FILES
            if not (self.runtime / name).is_file()
            or (self.runtime / name).read_bytes() != (ROOT / name).read_bytes()
        ]
        if changed:
            backup = self.root / ".lab" / ("code-backup-" + uuid.uuid4().hex)
            backup.mkdir()
            for name in changed:
                if (self.runtime / name).is_file():
                    shutil.copy2(self.runtime / name, backup / name)
            for name in changed:
                shutil.copy2(ROOT / name, self.runtime / name)

    def start(self):
        check_ports()
        self.config_stopped = False
        if self.mode == "resume":
            self.resume_lab()
            backup = None
        else:
            backup = prepare_lab(self.root)
        from demo_controller import DemoController

        self.demo = DemoController(self, capture=self.mode == "presentation")
        self.environment["LAB_DEMO_DIR"] = str(self.demo.directory)
        self.environment["LAB_LAYOUT_FILE"] = str(self.root / "window_layout.json")
        try:
            if not self.demo.start_capture() and self.manual_capture_wait:
                self.manual_capture_wait()
            for script, title, port in COMPONENTS:
                from window_layout import component_command

                environment = self.environment.copy()
                actor = Path(script).stem
                environment["LAB_DEMO_ACTOR"] = actor
                if self.mode == "presentation" and actor in {"client_1", "client_2"}:
                    number = actor[-1]
                    environment["LAB_TLS_KEYLOG"] = str(
                        self.demo.directory / f"tls-client{number}.keys"
                    )
                options = dict(creationflags=subprocess.CREATE_NEW_CONSOLE | 0x00000004)
                if self.headless:
                    output = (self.demo.directory / (actor + ".log")).open("ab")
                    self.output_handles.append(output)
                    options.update(
                        creationflags=subprocess.CREATE_NO_WINDOW | 0x00000004,
                        stdin=subprocess.PIPE,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                    )
                process = subprocess.Popen(
                    component_command(
                        [
                            sys.executable,
                            "-X",
                            "utf8",
                            "-u",
                            str(ROOT / "start_lab.py"),
                            "--component",
                            script,
                            "--runtime",
                            str(self.runtime),
                        ],
                        self.root / "window_layout.json",
                        self.headless,
                    ),
                    cwd=self.root,
                    env=environment,
                    # Vor Ausfuehrung zuordnen: auch Kinder des Windows-venv-
                    # Redirectors gehoeren dadurch garantiert zu unserem Job.
                    **options,
                )
                self.processes.append((title, process))
                self.job.attach(process)
                component_job = WindowsJob()
                self.component_jobs[title] = component_job
                component_job.attach(process)
                self.job.resume(process)
                if port is not None:
                    self.wait_until(lambda: self.tls_ready(port), title)
                else:
                    self.wait_until(lambda: self.client_ready(Path(script).stem), title)
                print(f"[LAB] {title} bereit.", flush=True)
            self.ensure_alive()
            self.demo.report()
        except BaseException:
            self.stop()
            raise
        return backup

    def stop_config(self):
        process = next(p for title, p in self.processes if title == "02 Config-Server")
        # Erst erwartetes Ende markieren; die uebrigen vier Prozesse weiter pruefen.
        self.config_stopped = True
        self.demo.request("config_server", "shutdown")
        graceful = True
        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            graceful = False
            self.component_jobs["02 Config-Server"].terminate()
            process.wait(timeout=5)
        if graceful:
            self.demo.wait(
                lambda: (
                    {e["actor"] for e in self.demo.select("config_paused")}
                    == {"client_1", "client_2"}
                ),
                "Abschaltmeldung bei beiden Clients",
            )
        deadline = time.monotonic() + 5
        while self.demo.services()["5002"]:
            if time.monotonic() >= deadline:
                raise RuntimeError("Config-Port nach Prozessende noch erreichbar")
            time.sleep(0.05)
        result = dict(
            pid=process.pid,
            exitcode=process.returncode,
            reachable=False,
            graceful=graceful,
            observed_utc=datetime.now(timezone.utc).isoformat(),
        )
        self.demo.note("config_stopped", **result)
        self.ensure_alive()
        return result

    def stop(self):
        if self.demo and self.demo.capture:
            self.demo.capture.finish()
        # Der venv-Interpreter kann ein Redirector mit eigenem Kindprozess sein.
        # Daher den ganzen eigenen Job und zusaetzlich unzugeordnete Kinder stoppen.
        had_processes = bool(self.processes)
        self.job.terminate()
        for _, process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
        for _, process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if self.headless:
            for _, process in self.processes:
                if process.stdin:
                    process.stdin.close()
        self.processes.clear()
        for component_job in self.component_jobs.values():
            component_job.close()
        self.component_jobs.clear()
        for handle in self.output_handles:
            handle.close()
        self.output_handles.clear()
        if had_processes:
            # Prozessende und Freigabe der TCP-Bindings sind unter Windows
            # nicht synchron. Erst nach deren Freigabe ist Neustart moeglich.
            deadline = time.monotonic() + 5
            while True:
                try:
                    check_ports()
                    break
                except RuntimeError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
        if self.demo:
            self.demo.finish()

    def status(self):
        if self.demo:
            self.demo.status()
        for title, process in self.processes:
            result = (
                "laeuft"
                if process.poll() is None
                else f"beendet ({process.returncode})"
            )
            print(f"[LAB] {title}: {result}", flush=True)


def read_key(session):
    import msvcrt

    from window_layout import pump_window_messages

    while True:
        pump_window_messages()
        session.ensure_alive()
        if msvcrt.kbhit():
            key = msvcrt.getwch()
            if key == "\x03":
                raise KeyboardInterrupt
            if key in {"\x00", "\xe0"}:
                msvcrt.getwch()
                continue
            return key.lower()
        time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Voraussetzungen pruefen, nichts starten/aendern",
    )
    parser.add_argument(
        "--mode", choices=("presentation", "fresh", "resume"), default="presentation"
    )
    parser.add_argument(
        "--automated-demo",
        action="store_true",
        help="Sechs echte Phasen automatisch pruefen und beenden",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Fuer Prueflaeufe: technische Konsolen in Logdateien",
    )
    parser.add_argument(
        "--open-wireshark",
        action="store_true",
        help="Nach --automated-demo Wireshark oeffnen",
    )
    parser.add_argument(
        "--classic-controller", action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--component", choices=[item[0] for item in COMPONENTS], help=argparse.SUPPRESS
    )
    parser.add_argument("--runtime", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.component:
        if args.runtime is None:
            parser.error("--component benoetigt --runtime")
        run_component(args.component, args.runtime.resolve())
        return 0
    try:
        check_environment()
        if args.check:
            check_ports()
            print(
                "[LAB] Python, Abhaengigkeiten, TLS 1.3, Projektdateien und Ports 5001-5004: bereit."
            )
            return 0
        from window_layout import component_command, needs_classic_controller

        if (
            not args.headless
            and not args.classic_controller
            and needs_classic_controller(ROOT / "window_layout.json")
        ):
            command = component_command(
                [
                    sys.executable,
                    "-X",
                    "utf8",
                    "-u",
                    str(ROOT / "start_lab.py"),
                    *sys.argv[1:],
                    "--classic-controller",
                ],
                ROOT / "window_layout.json",
            )
            if Path(command[0]).name.lower() == "conhost.exe":
                print(
                    "[LAB] Steuerung im eigenen klassischen Konsolenfenster geoeffnet.",
                    flush=True,
                )
                return subprocess.Popen(
                    command, cwd=ROOT, creationflags=subprocess.CREATE_NEW_CONSOLE
                ).wait()
        set_title("Steuerung")
        from window_layout import apply_layout

        apply_layout(ROOT / "window_layout.json", "controller")
        with launcher_lock(), WindowsJob() as job:
            manual_wait = (
                None
                if args.automated_demo
                else lambda: input(
                    "[LAB] Manuellen Mitschnitt jetzt starten, dann hier Enter druecken: "
                )
            )
            session = LabSession(
                job,
                mode=args.mode,
                headless=args.headless,
                manual_capture_wait=manual_wait,
            )
            try:
                while True:
                    print(f"[LAB] Startmodus: {session.mode}", flush=True)
                    backup = session.start()
                    if backup:
                        print(
                            f"[LAB] Vorheriger Stand gesichert: {backup.name}",
                            flush=True,
                        )
                    print(f"[LAB] Ergebnisse: {session.demo.directory}", flush=True)
                    session.demo.status()
                    from window_layout import focus_controller

                    focus_controller()
                    if args.automated_demo:
                        for number in range(1, 7):
                            if session.demo.phase(number)["result"] != "PASS":
                                return 1
                        if session.demo.capture:
                            if args.open_wireshark:
                                session.demo.open_wireshark()
                            else:
                                session.demo.capture.finish()
                            if session.demo.capture.info["state"] != "complete":
                                return 1
                        return 0
                    while True:
                        command = read_key(session)
                        if command in {"q", "quit", "exit"}:
                            return 0
                        if command in {"r", "restart", "neustart"}:
                            break
                        try:
                            if command in "123456":
                                session.demo.phase(int(command))
                            elif command == "w":
                                session.demo.open_wireshark()
                            elif command == "b":
                                session.demo.open_report()
                            elif command == "s":
                                session.status()
                        except (OSError, RuntimeError, ValueError) as exc:
                            print(f"[LAB] Aktion nicht erfolgreich: {exc}", flush=True)
                    session.stop()
                    session.mode = (
                        "presentation" if args.mode == "presentation" else "fresh"
                    )
            finally:
                session.stop()
                print("[LAB] Eigene Labprozesse beendet.", flush=True)
    except (KeyboardInterrupt, EOFError):
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[LAB] Start abgebrochen: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
