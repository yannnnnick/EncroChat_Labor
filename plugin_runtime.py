"""Signierte Betriebsprofile und Audit-Ereignisse eines Clients."""

import json
import os
import queue
import tempfile
from pathlib import Path

from audit_event import send_probe
from demo_ipc import emit, plugin_label
from update_protocol import canonical, load_public_key, read_package, verify_package


def write_state(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".installed-", suffix=".tmp", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def load_client_runtime(client_id, stop, root=None):
    root = Path(root) if root is not None else Path(__file__).resolve().parent
    directory = root / ".client_state" / client_id
    directory.mkdir(parents=True, exist_ok=True)
    key = load_public_key(root / "trust" / "update-signing.pub")
    runtime = PluginRuntime(stop, client_id, key, directory / "installed.json")
    if runtime.state_file.exists():
        package = verify_package(read_package(runtime.state_file), key, client_id)
        runtime.name, runtime.version = package["name"], package["version"]
        print(f"[CONFIG] Plugin={plugin_label(runtime.name)} geladen", flush=True)
        emit(
            "plugin_loaded",
            client_id=client_id,
            name=runtime.name,
            version=runtime.version,
        )
    return runtime


class PluginRuntime:
    def __init__(self, stop, client_id, public_key, state_file):
        self.stop = stop
        self.client_id = client_id
        self.public_key = public_key
        self.state_file = state_file
        self.name = "dummy"
        self.version = 0
        self.events = queue.Queue(maxsize=256)

    def submit_message(self, metadata):
        try:
            self.events.put_nowait(("message", dict(metadata)))
        except queue.Full:
            print("\n[PLUGIN] Warteschlange voll; Ereignis verworfen", flush=True)

    def submit_update(self, update):
        # Verifikation im seriellen Worker, direkt vor der Installation. So koennen
        # zwei wartende Pakete die Versionspruefung nicht gemeinsam umgehen.
        update = json.loads(json.dumps(update))
        while not self.stop.is_set():
            try:
                self.events.put(("update", update), timeout=0.2)
                return
            except queue.Full:
                continue

    def install(self, package):
        verify_package(package, self.public_key, self.client_id, self.version)
        write_state(self.state_file, canonical(package) + b"\n")
        self.name, self.version = package["name"], package["version"]
        emit(
            "update_installed",
            client_id=self.client_id,
            name=self.name,
            version=self.version,
            sha256=package["sha256"],
            target=package["target"],
            checks=["Ed25519", "SHA-256", "target", "version"],
        )

    def run(self):
        while not self.stop.is_set() or not self.events.empty():
            try:
                kind, payload = self.events.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                if kind == "update":
                    try:
                        self.install(payload)
                    except Exception as exc:
                        print(
                            f"\n[CONFIG] Update abgelehnt ({type(exc).__name__}: {exc}); letztes Plugin bleibt aktiv.",
                            flush=True,
                        )
                        emit(
                            "update_rejected",
                            client_id=self.client_id,
                            reason=str(exc),
                            error=type(exc).__name__,
                            version=payload.get("version"),
                            package_sha256=payload.get("sha256"),
                        )
                    else:
                        print(
                            f"\n[CONFIG] Plugin={plugin_label(self.name)} geladen",
                            flush=True,
                        )
                else:
                    try:
                        if self.name == "audit":
                            send_probe(payload)
                    except OSError:
                        print(
                            "\n[PLUGIN] Collector nicht erreichbar; Pruefereignis verworfen. Chat laeuft weiter.",
                            flush=True,
                        )
                    except Exception:
                        print(
                            "\n[PLUGIN] Ereignis fehlgeschlagen; Chat laeuft weiter.",
                            flush=True,
                        )
                    finally:
                        emit(
                            "hook_completed",
                            message_id=payload.get("message_id"),
                            direction=payload.get("direction"),
                            name=self.name,
                            version=self.version,
                        )
            finally:
                self.events.task_done()
