"""Demo-Client: AES-256-GCM-Chat mit signierten lokalen Betriebsprofilen."""

import base64
import binascii
import json
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from demo_ipc import control_worker, digest, emit, plugin_label
from plugin_runtime import load_client_runtime
from tls_transport import connect
from update_protocol import no_duplicates

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise SystemExit(
        "cryptography fehlt. Installation: python -m pip install -r requirements.txt"
    )

ROUTING_PORT, CONFIG_PORT = 5001, 5002
KEY_FILE = Path(__file__).resolve().with_name(".chat_demo_key.bin")
MAX_PACKET_BYTES = 128 * 1024
MAX_MESSAGE_BYTES = 16 * 1024
META_FIELDS = ("type", "message_id", "sender", "recipient", "timestamp")


def load_demo_key():
    """Gemeinsame lokale Demo-Datei; kein Schluesseltransport ueber die drei Ports."""
    try:
        with KEY_FILE.open("xb") as handle:
            handle.write(AESGCM.generate_key(bit_length=256))
    except FileExistsError:
        pass
    # Ein zweiter, gleichzeitig gestarteter Client kann die Datei kurz leer sehen.
    for _ in range(20):
        key = KEY_FILE.read_bytes()
        if len(key) == 32:
            return key
        if key:
            break
        time.sleep(0.05)
    raise ValueError("Demo-Schluesseldatei muss genau 32 Bytes enthalten")


def encode(packet):
    return (json.dumps(packet, ensure_ascii=False) + "\n").encode("utf-8")


def read_packet(stream):
    line = stream.readline(MAX_PACKET_BYTES + 1)
    if not line:
        return None
    if len(line) > MAX_PACKET_BYTES or not line.endswith(b"\n"):
        raise ValueError("JSON-Zeile fehlt oder ist zu gross")
    packet = json.loads(line.decode("utf-8"), object_pairs_hook=no_duplicates)
    if not isinstance(packet, dict):
        raise ValueError("JSON-Objekt erwartet")
    return packet


def authenticated_metadata(packet):
    metadata = {field: packet[field] for field in META_FIELDS}
    if not all(isinstance(value, str) for value in metadata.values()):
        raise ValueError("Ungueltige Metadaten")
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ChatClient:
    def __init__(self, client_id, peer_id):
        self.client_id = client_id
        self.peer_id = peer_id
        self.cipher = AESGCM(load_demo_key())
        self.stop = threading.Event()
        self.plugin = load_client_runtime(self.client_id, self.stop)
        self.config_socket = None
        self.send_lock = threading.Lock()
        self.updates_paused = threading.Event()
        self.config_connected = threading.Event()

    def message_event(self, packet, direction):
        metadata = {
            "client_id": self.client_id,
            "direction": direction,
            "message_id": packet["message_id"],
            "timestamp": packet["timestamp"],
            "sender": packet["sender"],
            "recipient": packet["recipient"],
        }
        self.plugin.submit_message(metadata)

    def config_loop(self):
        unavailable = False
        retry_delay = 1
        while not self.stop.is_set():
            try:
                emit("config_connect_attempt", port=CONFIG_PORT)
                with connect(CONFIG_PORT, timeout=1) as sock:
                    self.config_socket = sock
                    sock.settimeout(None)
                    sock.sendall(
                        encode({"type": "register", "client_id": self.client_id})
                    )
                    self.config_connected.set()
                    if unavailable:
                        print(
                            "\n[UPDATE] TLS-Kanal wieder verbunden; warte auf Server-Push.",
                            flush=True,
                        )
                    unavailable = False
                    retry_delay = 1
                    emit("config_connected", mode="server_push")
                    with sock.makefile("rb") as stream:
                        while not self.stop.is_set():
                            update = read_packet(stream)
                            if update is None:
                                raise ConnectionError("Konfigurationskanal geschlossen")
                            if update == {
                                "type": "service_shutdown",
                                "service": "config",
                            }:
                                self.updates_paused.set()
                                emit(
                                    "config_paused",
                                    reason="authenticated_server_shutdown",
                                )
                                print(
                                    "\n[UPDATE] Update-Server offline. Lokal installiert: "
                                    f"{plugin_label(self.plugin.name)} v{self.plugin.version}. "
                                    "Das gespeicherte Profil bleibt aktiv; "
                                    "keine weiteren Verbindungsversuche.",
                                    flush=True,
                                )
                                return
                            self.plugin.submit_update(update)
            except (OSError, ValueError):
                if not self.stop.is_set() and not unavailable:
                    unavailable = True
                    emit("config_disconnected", retry="quiet_backoff")
                    print(
                        "\n[UPDATE] Kanal unterbrochen; Plugin und Chat bleiben aktiv. "
                        "Wiederverbindung erfolgt im Hintergrund.",
                        flush=True,
                    )
            finally:
                self.config_socket = None
                self.config_connected.clear()
            self.stop.wait(retry_delay)
            retry_delay = min(30, retry_delay * 2)

    def receive_loop(self, stream):
        try:
            while not self.stop.is_set():
                packet = read_packet(stream)
                if packet is None:
                    break
                if packet.get("type") == "error":
                    print(f"\n[ROUTING] {packet.get('message', 'Fehler')}", flush=True)
                    continue
                try:
                    expected_fields = set(META_FIELDS) | {"nonce", "ciphertext"}
                    if set(packet) != expected_fields or packet.get("type") != "chat":
                        raise ValueError("Ungueltiges Chat-Paket")
                    if (
                        packet["sender"] != self.peer_id
                        or packet["recipient"] != self.client_id
                    ):
                        raise ValueError("Unerwarteter Sender/Empfaenger")
                    nonce = base64.b64decode(packet["nonce"], validate=True)
                    ciphertext = base64.b64decode(packet["ciphertext"], validate=True)
                    if len(nonce) != 12:
                        raise ValueError("Nonce muss 12 Bytes enthalten")
                    plaintext = self.cipher.decrypt(
                        nonce, ciphertext, authenticated_metadata(packet)
                    ).decode("utf-8")
                except (ValueError, TypeError, KeyError, InvalidTag, binascii.Error):
                    print(
                        "\n[CHAT] Ungueltige oder manipulierte Nachricht verworfen",
                        flush=True,
                    )
                    continue
                print(
                    f"\n[{packet['timestamp']}] {packet['sender']}: {plaintext}\n> ",
                    end="",
                    flush=True,
                )
                self.message_event(packet, "incoming")
                emit(
                    "chat_decrypted",
                    message_id=packet["message_id"],
                    plaintext_sha256=digest(plaintext),
                    algorithm="AES-256-GCM",
                )
        except (OSError, ValueError):
            pass
        finally:
            if not self.stop.is_set():
                print(
                    "\n[ROUTING] Verbindung beendet. Mit Enter den Client schliessen.",
                    flush=True,
                )
            self.stop.set()

    def send_chat(self, sock, plaintext):
        data = plaintext.encode("utf-8")
        if len(data) > MAX_MESSAGE_BYTES:
            print("[CHAT] Nachricht zu lang (maximal 16 KiB UTF-8).", flush=True)
            return
        packet = {
            "type": "chat",
            "message_id": uuid.uuid4().hex,
            "sender": self.client_id,
            "recipient": self.peer_id,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        }
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(nonce, data, authenticated_metadata(packet))
        packet["nonce"] = base64.b64encode(nonce).decode("ascii")
        packet["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        with self.send_lock:
            sock.sendall(encode(packet))
        emit(
            "chat_encrypted",
            message_id=packet["message_id"],
            packet=packet,
            plaintext_sha256=digest(plaintext),
            algorithm="AES-256-GCM",
        )
        print(f"[DU -> {self.peer_id}] {plaintext}", flush=True)
        self.message_event(packet, "outgoing")
        return packet["message_id"]

    def control(self, sock, command):
        action = command.get("action")
        if action == "send":
            text = command.get("text", "")
            if (
                not isinstance(text, str)
                or not text.startswith("LAB-")
                or len(text) > 256
            ):
                raise ValueError("Nur kurze synthetische LAB-Nachrichten erlaubt")
            return {"message_id": self.send_chat(sock, text)}
        if action == "probe_update":
            import ssl

            try:
                with connect(5004, timeout=2, service_port=CONFIG_PORT):
                    emit("rogue_accepted")
                    return {"rejected": False}
            except ssl.SSLCertVerificationError as exc:
                emit(
                    "rogue_rejected",
                    reason=str(exc),
                    error=type(exc).__name__,
                    endpoint="127.0.0.1:5004",
                )
                return {"rejected": True}
        if action == "status":
            return {
                "name": self.plugin.name,
                "version": self.plugin.version,
                "pid": os.getpid(),
                "updates_paused": self.updates_paused.is_set(),
            }
        raise ValueError("Unbekannter Clientbefehl")

    def run(self):
        with connect(ROUTING_PORT, timeout=3) as sock:
            stream = sock.makefile("rb")
            worker = None
            receiver = None
            config = None
            try:
                sock.sendall(encode({"type": "register", "client_id": self.client_id}))
                response = read_packet(stream)
                if response is None or response.get("type") != "registered":
                    raise ValueError(
                        "Registrierung am Router fehlgeschlagen; Client eventuell bereits gestartet"
                    )
                sock.settimeout(None)
                receiver = threading.Thread(
                    target=self.receive_loop, args=(stream,), daemon=True
                )
                config = threading.Thread(target=self.config_loop, daemon=True)
                worker = threading.Thread(target=self.plugin.run, daemon=True)
                for thread in (receiver, config, worker):
                    thread.start()
                control_worker(self.stop, lambda command: self.control(sock, command))
                emit("client_ready", pid=os.getpid())
                print(
                    f"[CHAT] {self.client_id} bereit. Empfaenger: {self.peer_id}. /status | /quit",
                    flush=True,
                )
                while not self.stop.is_set():
                    try:
                        message = input("> ")
                    except (EOFError, KeyboardInterrupt):
                        break
                    if self.stop.is_set() or message.strip() == "/quit":
                        break
                    if message.strip() == "/status":
                        print(
                            f"[STATUS] Plugin={plugin_label(self.plugin.name)}, Version={self.plugin.version}",
                            flush=True,
                        )
                    elif message:
                        self.send_chat(sock, message)
            finally:
                self.stop.set()
                for connection in (sock, self.config_socket):
                    if connection is not None:
                        try:
                            connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                for thread in (receiver, config, worker):
                    if thread is not None:
                        thread.join(timeout=2)
                stream.close()


def main(client_id, peer_id):
    try:
        ChatClient(client_id, peer_id).run()
    except (OSError, ValueError) as exc:
        raise SystemExit(f"[CLIENT] {exc}. Bitte zuerst die Server starten.")
    except KeyboardInterrupt:
        pass
