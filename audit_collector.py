"""TLS-Log-Empfaenger auf Port 5003; schreibt nur auf die Konsole."""

import json
import socketserver
import threading

from audit_event import AUDIT_MARKER
from demo_ipc import emit
from tls_transport import TLSServer

HOST, PORT = "127.0.0.1", 5003
MAX_PACKET_BYTES = 128 * 1024
PRINT_LOCK = threading.Lock()
FIELDS = {
    "client_id",
    "direction",
    "message_id",
    "timestamp",
    "sender",
    "recipient",
    "marker",
}


class AuditHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            while True:
                line = self.rfile.readline(MAX_PACKET_BYTES + 1)
                if not line:
                    return
                if len(line) > MAX_PACKET_BYTES or not line.endswith(b"\n"):
                    raise ValueError("Ungueltige JSON-Zeile")
                entry = json.loads(line.decode("utf-8"))
                if not isinstance(entry, dict) or set(entry) != FIELDS:
                    raise ValueError("Ungueltige Audit-Felder")
                if not all(isinstance(value, str) for value in entry.values()):
                    raise ValueError("Audit-Felder muessen Zeichenketten sein")
                if entry["direction"] not in {"incoming", "outgoing"}:
                    raise ValueError("Ungueltige Richtung")
                if entry["marker"] != AUDIT_MARKER:
                    raise ValueError("Ungueltiger Audit-Prueftext")
                with PRINT_LOCK:
                    print(
                        "[AUDIT] " + json.dumps(entry, ensure_ascii=False), flush=True
                    )
                emit("audit_received", **entry)
                self.request.sendall(b"OK\n")
        except (OSError, ValueError, TypeError):
            print(
                "[AUDIT] Ungueltigen oder unvollstaendigen Eintrag verworfen",
                flush=True,
            )


class AuditServer(TLSServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    try:
        with AuditServer((HOST, PORT), AuditHandler) as server:
            print(
                f"[AUDIT] TCP {HOST}:{PORT} | TLS 1.3 | Warte auf Logs | Beenden: Strg+C",
                flush=True,
            )
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    except OSError as exc:
        raise SystemExit(f"[AUDIT] Start fehlgeschlagen: {exc}")


if __name__ == "__main__":
    main()
