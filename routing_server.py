"""Lokaler JSON-Router: Port 5001 sieht Metadaten und Ciphertext, keinen Schluessel."""

import base64
import binascii
import json
import socketserver
import threading

from demo_ipc import emit
from tls_transport import TLSServer

HOST, PORT = "127.0.0.1", 5001
CLIENT_IDS = {"client_1", "client_2"}
MAX_PACKET_BYTES = 128 * 1024
CHAT_FIELDS = {
    "type",
    "message_id",
    "sender",
    "recipient",
    "timestamp",
    "nonce",
    "ciphertext",
}


def read_packet(stream):
    line = stream.readline(MAX_PACKET_BYTES + 1)
    if not line:
        return None
    if len(line) > MAX_PACKET_BYTES or not line.endswith(b"\n"):
        raise ValueError("JSON-Zeile fehlt oder ist zu gross")
    packet = json.loads(line.decode("utf-8"))
    if not isinstance(packet, dict):
        raise ValueError("JSON-Objekt erwartet")
    return packet


class Peer:
    def __init__(self, sock):
        self.sock = sock
        self.send_lock = threading.Lock()

    def send(self, packet):
        wire = (json.dumps(packet, ensure_ascii=False) + "\n").encode("utf-8")
        with self.send_lock:
            self.sock.sendall(wire)


class RoutingServer(TLSServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__((HOST, PORT), RoutingHandler)
        self.peers = {}
        self.peers_lock = threading.Lock()


def validate_chat(packet, client_id):
    if set(packet) != CHAT_FIELDS or packet.get("type") != "chat":
        raise ValueError("Ungueltiges Chat-Paket")
    if packet["sender"] != client_id:
        raise ValueError("Sender passt nicht zur Registrierung")
    if packet["recipient"] not in CLIENT_IDS or packet["recipient"] == client_id:
        raise ValueError("Unbekannter Empfaenger")
    for field in ("message_id", "timestamp"):
        if not isinstance(packet[field], str) or not 1 <= len(packet[field]) <= 80:
            raise ValueError("Ungueltige Metadaten")
    try:
        nonce = base64.b64decode(packet["nonce"], validate=True)
        ciphertext = base64.b64decode(packet["ciphertext"], validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ValueError("Base64 erwartet") from exc
    if len(nonce) != 12 or not 16 <= len(ciphertext) <= 16 * 1024 + 16:
        raise ValueError("Ungueltige Nonce- oder Ciphertext-Laenge")


class RoutingHandler(socketserver.StreamRequestHandler):
    def handle(self):
        peer = Peer(self.request)
        client_id = None
        try:
            self.request.settimeout(5)
            hello = read_packet(self.rfile)
            if hello is None:
                return
            if (
                hello.get("type") != "register"
                or hello.get("client_id") not in CLIENT_IDS
            ):
                raise ValueError("Zuerst mit client_1 oder client_2 registrieren")
            candidate = hello["client_id"]
            with self.server.peers_lock:
                if candidate in self.server.peers:
                    raise ValueError("Client-ID ist bereits verbunden")
                self.server.peers[candidate] = peer
                client_id = candidate
                peer.send({"type": "registered", "client_id": client_id})
            self.request.settimeout(None)
            print(f"[ROUTING] {client_id} verbunden", flush=True)
            while True:
                packet = read_packet(self.rfile)
                if packet is None:
                    break
                validate_chat(packet, client_id)
                with self.server.peers_lock:
                    recipient = self.server.peers.get(packet["recipient"])
                if recipient is None:
                    peer.send(
                        {
                            "type": "error",
                            "message": "Empfaenger ist offline",
                            "message_id": packet["message_id"],
                        }
                    )
                    continue
                try:
                    recipient.send(packet)
                except OSError:
                    peer.send(
                        {
                            "type": "error",
                            "message": "Empfaenger nicht erreichbar",
                            "message_id": packet["message_id"],
                        }
                    )
                    continue
                print("[ROUTE] " + json.dumps(packet, ensure_ascii=False), flush=True)
                emit("chat_routed", message_id=packet["message_id"], packet=packet)
        except (OSError, ValueError, TypeError) as exc:
            try:
                peer.send({"type": "error", "message": str(exc)})
            except OSError:
                pass
        finally:
            if client_id is not None:
                with self.server.peers_lock:
                    if self.server.peers.get(client_id) is peer:
                        del self.server.peers[client_id]
                print(f"[ROUTING] {client_id} getrennt", flush=True)


def main():
    try:
        with RoutingServer() as server:
            print(
                f"[ROUTING] TCP {HOST}:{PORT} | TLS 1.3 | Beenden: Strg+C", flush=True
            )
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    except OSError as exc:
        raise SystemExit(f"[ROUTING] Start fehlgeschlagen: {exc}")


if __name__ == "__main__":
    main()
