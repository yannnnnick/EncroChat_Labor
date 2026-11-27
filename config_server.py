"""TLS-Verteiler fertiger Pakete. Besitzt keinen privaten Signaturschluessel."""

import json
import shlex
import socket
import socketserver
import threading
from pathlib import Path

from demo_ipc import console_lines, control_worker, emit
from tls_transport import TLSServer
from update_protocol import CLIENT_IDS, MAX_UPDATE_BYTES, canonical, read_package

HOST, PORT = "127.0.0.1", 5002
ROOT = Path(__file__).resolve().parent
MAX_PACKET_BYTES = 4096


class Peer:
    def __init__(self, sock):
        self.sock = sock
        self.send_lock = threading.Lock()

    def send(self, update):
        wire = canonical(update) + b"\n"
        if len(wire) > MAX_UPDATE_BYTES:
            raise ValueError("Paket zu gross")
        with self.send_lock:
            self.sock.sendall(wire)


class ConfigServer(TLSServer):
    def __init__(self):
        initial = read_package(ROOT / "packages" / "initial.json")
        self.updates = {client_id: initial for client_id in CLIENT_IDS}
        self.peers = {}
        self.peers_lock = threading.Lock()
        super().__init__((HOST, PORT), ConfigHandler)

    def broadcast(self, package, target="all"):
        if target not in CLIENT_IDS | {"all"}:
            raise ValueError("Unbekannter Zielclient")
        # Auch ungueltige Pakete duerfen verteilt werden (Szenario C).
        # Ausschliesslich der Client entscheidet ueber deren Installation.
        if len(canonical(package)) + 1 > MAX_UPDATE_BYTES:
            raise ValueError("Paket zu gross")
        with self.peers_lock:
            targets = CLIENT_IDS if target == "all" else {target}
            count = 0
            for client_id in targets:
                self.updates[client_id] = package
                peer = self.peers.get(client_id)
                if peer is None:
                    continue
                try:
                    peer.send(package)
                    count += 1
                except OSError:
                    self.peers.pop(client_id, None)
                    try:
                        peer.sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
        print(
            f"[CONFIG] Paket an {count} Client(s) gesendet; Ziel={target}", flush=True
        )
        emit(
            "update_distributed",
            target=target,
            count=count,
            version=package.get("version"),
            package_sha256=package.get("sha256"),
        )

    def announce_shutdown(self):
        with self.peers_lock:
            for client_id, peer in self.peers.items():
                try:
                    peer.send({"type": "service_shutdown", "service": "config"})
                    emit("config_shutdown_sent", client_id=client_id)
                except OSError:
                    pass


class ConfigHandler(socketserver.StreamRequestHandler):
    def handle(self):
        client_id = None
        peer = Peer(self.request)
        try:
            self.request.settimeout(5)
            line = self.rfile.readline(MAX_PACKET_BYTES + 1)
            if not line:
                return
            if len(line) > MAX_PACKET_BYTES or not line.endswith(b"\n"):
                raise ValueError("Ungueltige Registrierung")
            hello = json.loads(line.decode("utf-8"))
            if not isinstance(hello, dict) or hello.get("type") != "register":
                raise ValueError("Registrierung erwartet")
            candidate = hello.get("client_id")
            if candidate not in CLIENT_IDS:
                raise ValueError("Unbekannte Client-ID")
            with self.server.peers_lock:
                if candidate in self.server.peers:
                    raise ValueError("Client-ID ist bereits verbunden")
                self.server.peers[candidate] = peer
                client_id = candidate
                peer.send(self.server.updates[client_id])
            self.request.settimeout(None)
            print(f"[CONFIG] {client_id} verbunden", flush=True)
            while self.rfile.read(1):
                pass
        except (OSError, ValueError, TypeError):
            pass
        finally:
            if client_id is not None:
                with self.server.peers_lock:
                    if self.server.peers.get(client_id) is peer:
                        del self.server.peers[client_id]
                print(f"[CONFIG] {client_id} getrennt", flush=True)


def main():
    try:
        server = ConfigServer()
    except (OSError, ValueError) as exc:
        raise SystemExit(f"[CONFIG] Start fehlgeschlagen: {exc}")
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    stop = threading.Event()

    def control(command):
        if command.get("action") == "publish":
            filename = command.get("package")
            if filename not in {
                "unsigned.json",
                "update.json",
                "tampered.json",
                "server-forged.json",
                "reset.json",
            }:
                raise ValueError("Nur vorbereitete Laborpakete erlaubt")
            server.broadcast(read_package(ROOT / "packages" / filename))
            return {"published": filename}
        if command.get("action") == "shutdown":
            stop.set()
            return {"stopping": True}
        raise ValueError("Unbekannter Configbefehl")

    control_worker(stop, control)
    print(
        f"[CONFIG] TCP {HOST}:{PORT} | TLS 1.3 | update [Ziel] | reset [Ziel] | "
        "publish DATEI [Ziel] | status | quit",
        flush=True,
    )
    try:
        for line in console_lines(stop):
            try:
                parts = shlex.split(line.strip())
                if not parts:
                    continue
                command = parts[0].lower()
                if command in {"update", "reset", "publish"}:
                    if command == "publish":
                        if len(parts) not in {2, 3}:
                            raise ValueError("publish DATEI [Ziel]")
                        path = Path(parts[1])
                        target = parts[2] if len(parts) == 3 else "all"
                    else:
                        if len(parts) not in {1, 2}:
                            raise ValueError("update/reset [Ziel]")
                        path = (
                            ROOT
                            / "packages"
                            / ("update.json" if command == "update" else "reset.json")
                        )
                        target = parts[1] if len(parts) == 2 else "all"
                    server.broadcast(read_package(path), target)
                elif command == "status":
                    with server.peers_lock:
                        for client_id in sorted(CLIENT_IDS):
                            package = server.updates[client_id]
                            print(
                                f"[CONFIG] {client_id}: angeboten={package.get('name', '?')}, "
                                f"Version={package.get('version', '?')}, "
                                f"verbunden={client_id in server.peers}",
                                flush=True,
                            )
                elif command in {"quit", "exit"}:
                    break
                else:
                    print(
                        "Befehle: update [Ziel], reset [Ziel], publish DATEI [Ziel], status, quit",
                        flush=True,
                    )
            except (OSError, ValueError, TypeError):
                print(
                    "[CONFIG] Paket/Befehl fehlt, ist ungueltig oder zu gross; nicht verteilt.",
                    flush=True,
                )
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        stop.set()
        server.announce_shutdown()
        with server.peers_lock:
            for peer in server.peers.values():
                try:
                    peer.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


if __name__ == "__main__":
    main()
