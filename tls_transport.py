"""TLS 1.3 fuer die drei festen Loopback-Dienste; kein Klartext-Fallback."""

import hashlib
import hmac
import os
import socket
import socketserver
import ssl
from pathlib import Path

from demo_ipc import emit

ROOT = Path(__file__).resolve().parent
HOST = "127.0.0.1"
SERVICES = {5001: "routing", 5002: "config", 5003: "audit"}


def configure(context):
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    # Bewusst opt-in; SSLKEYLOGFILE wird nicht automatisch ausgewertet.
    keylog = os.environ.get("LAB_TLS_KEYLOG")
    if keylog:
        context.keylog_filename = str(Path(keylog).resolve())
    return context


def client_context(root=ROOT):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(Path(root) / "trust" / "ca.pem"))
    return configure(context)


def server_context(port, root=ROOT):
    service = SERVICES[port]
    context = configure(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
    context.load_cert_chain(
        str(Path(root) / "pki" / f"{service}.pem"),
        str(Path(root) / "pki" / f"{service}.key"),
    )
    return context


def connect(port, timeout=3, root=ROOT, *, service_port=None):
    service = port if service_port is None else service_port
    if service not in SERVICES or (
        service_port is not None and (service != 5002 or port != 5004)
    ):
        raise ValueError(
            "Nur feste lokale Lab-Dienste oder Rogue-Updateport 5004 erlaubt"
        )
    context = client_context(root)
    raw = socket.create_connection((HOST, port), timeout=timeout)
    try:
        sock = context.wrap_socket(raw, server_hostname=HOST)
        if service == 5002:
            expected = (
                (Path(root) / "trust" / "config-pin.sha256").read_text("ascii").strip()
            )
            actual = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
            if len(expected) != 64 or not hmac.compare_digest(actual, expected):
                raise ssl.SSLCertVerificationError(
                    "Config-Zertifikat stimmt nicht mit dem Pin ueberein"
                )
        emit(
            "tls_connected",
            port=port,
            service_port=service,
            version=sock.version(),
            pin_verified=service == 5002,
        )
        return sock
    except BaseException:
        raw.close()
        if "sock" in locals():
            sock.close()
        raise


class TLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, root=ROOT):
        if address[0] != HOST or address[1] not in SERVICES:
            raise ValueError("Nur die drei festen Loopback-Ports sind erlaubt")
        self.tls_context = server_context(address[1], root)
        super().__init__(address, handler)

    def process_request_thread(self, request, client_address):
        # Handshake im Worker: ein stummer TCP-Peer blockiert keine neuen Clients.
        try:
            request.settimeout(3)
            secured = self.tls_context.wrap_socket(request, server_side=True)
        except OSError:
            request.close()
            return
        super().process_request_thread(secured, client_address)
