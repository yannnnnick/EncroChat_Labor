"""Echte TLS-Handshakes auf den festen Ports und TLS-Record-Nachweis."""

import base64
import ipaddress
import json
import os
import socket
import socketserver
import ssl
import tempfile
import threading
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID

from audit_event import AUDIT_MARKER
from provision_tls import provision
from tls_transport import SERVICES, TLSServer, client_context, connect, server_context


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            data = self.rfile.readline(1024)
            if data:
                self.request.sendall(data)
        except OSError:
            pass


class TLSTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tls-lab-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "runtime"
        self.offline = self.base / "offline"
        provision(self.root, self.offline)

    @contextmanager
    def serving(self, port):
        with TLSServer(("127.0.0.1", port), Echo, self.root) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                yield
            finally:
                server.shutdown()
                worker.join(timeout=4)

    def replace_certificate(self, service, ip="127.0.0.1", expired=False):
        ca = x509.load_pem_x509_certificate(
            (self.root / "trust" / "ca.pem").read_bytes()
        )
        ca_key = serialization.load_pem_private_key(
            (self.offline / "ca.key").read_bytes(), None
        )
        key = serialization.load_pem_private_key(
            (self.root / "pki" / f"{service}.key").read_bytes(), None
        )
        original = x509.load_pem_x509_certificate(
            (self.root / "pki" / f"{service}.pem").read_bytes()
        )
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(original.subject)
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(
                now - timedelta(days=1) if expired else now + timedelta(days=1)
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),
                False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
            )
            .sign(ca_key, hashes.SHA256())
        )
        (self.root / "pki" / f"{service}.pem").write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
        )

    def test_tls13_all_ports_separate_certificates_and_valid_sans(self):
        certificates = set()
        for port, service in SERVICES.items():
            with (
                self.subTest(port=port),
                self.serving(port),
                connect(port, root=self.root) as sock,
            ):
                self.assertEqual(sock.version(), "TLSv1.3")
                der = sock.getpeercert(binary_form=True)
                certificates.add(der)
                cert = x509.load_der_x509_certificate(der)
                sans = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
                self.assertIn(
                    ipaddress.ip_address("127.0.0.1"),
                    sans.get_values_for_type(x509.IPAddress),
                )
                sock.sendall(b"synthetic TLS test\n")
                self.assertEqual(sock.recv(1024), b"synthetic TLS test\n")
        self.assertEqual(len(certificates), 3)

    def test_unknown_ca_rejected(self):
        other = self.base / "other"
        provision(other, self.base / "other-offline")
        with self.serving(5001), self.assertRaises(ssl.SSLCertVerificationError):
            connect(5001, root=other)

    def test_wrong_ip_san_rejected(self):
        self.replace_certificate("routing", ip="127.0.0.2")
        with self.serving(5001), self.assertRaises(ssl.SSLCertVerificationError):
            connect(5001, root=self.root)

    def test_expired_certificate_rejected(self):
        self.replace_certificate("routing", expired=True)
        with self.serving(5001), self.assertRaises(ssl.SSLCertVerificationError):
            connect(5001, root=self.root)

    def test_valid_ca_and_san_but_different_pinned_certificate_rejected(self):
        self.replace_certificate("config")
        with (
            self.serving(5002),
            self.assertRaisesRegex(ssl.SSLCertVerificationError, "Pin"),
        ):
            connect(5002, root=self.root)

    def test_tls12_downgrade_and_plain_tcp_rejected(self):
        context = client_context(self.root)
        # Nur der negative Testclient versucht TLS 1.2; Verifikation bleibt aktiv.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        with self.serving(5001):
            with socket.create_connection(("127.0.0.1", 5001), timeout=2) as raw:
                with self.assertRaises(ssl.SSLError):
                    context.wrap_socket(raw, server_hostname="127.0.0.1")
            with socket.create_connection(("127.0.0.1", 5001), timeout=2) as raw:
                raw.sendall(b"this is plaintext, not a TLS handshake\n")
                try:
                    self.assertEqual(raw.recv(1024), b"")
                except ConnectionResetError:
                    pass

    def test_keylogging_is_opt_in(self):
        with patch.dict(os.environ, {"LAB_TLS_KEYLOG": ""}):
            self.assertIsNone(client_context(self.root).keylog_filename)
        path = self.base / "capture.keylog"
        with patch.dict(os.environ, {"LAB_TLS_KEYLOG": str(path)}), self.serving(5001):
            with connect(5001, root=self.root) as sock:
                self.assertEqual(sock.version(), "TLSv1.3")
                sock.sendall(b"synthetic keylog test\n")
                self.assertEqual(sock.recv(1024), b"synthetic keylog test\n")
        # Niemals Inhalte des Keylogs ausgeben.
        self.assertGreater(path.stat().st_size, 100)

    def test_tls_records_hide_payload_and_decryption_preserves_inner_aes(self):
        # MemoryBIO liefert echte OpenSSL-TLS-Records ohne Capture-Treiber.
        # Die entschluesselten Bytes entsprechen Follow TLS Stream.
        for port in (5001, 5003):
            with self.subTest(port=port):
                incoming_c, outgoing_c = ssl.MemoryBIO(), ssl.MemoryBIO()
                incoming_s, outgoing_s = ssl.MemoryBIO(), ssl.MemoryBIO()
                client = client_context(self.root).wrap_bio(
                    incoming_c, outgoing_c, server_hostname="127.0.0.1"
                )
                server = server_context(port, self.root).wrap_bio(
                    incoming_s, outgoing_s, server_side=True
                )
                finished = set()
                for _ in range(20):
                    for name, endpoint in (("client", client), ("server", server)):
                        if name not in finished:
                            try:
                                endpoint.do_handshake()
                                finished.add(name)
                            except ssl.SSLWantReadError:
                                pass
                    if outgoing_c.pending:
                        incoming_s.write(outgoing_c.read())
                    if outgoing_s.pending:
                        incoming_c.write(outgoing_s.read())
                    if len(finished) == 2:
                        break
                self.assertEqual(len(finished), 2)
                plaintext = "SYNTHETIC_LAB_MESSAGE_5001_5003"
                if port == 5001:
                    nonce = os.urandom(12)
                    ciphertext = AESGCM(AESGCM.generate_key(256)).encrypt(
                        nonce, plaintext.encode(), b"metadata"
                    )
                    payload = {
                        "type": "chat",
                        "ciphertext": base64.b64encode(ciphertext).decode(),
                    }
                else:
                    payload = {"marker": AUDIT_MARKER}
                application_data = json.dumps(payload).encode()
                client.write(application_data)
                record = outgoing_c.read()
                self.assertEqual(record[0], 23)  # TLS application_data
                self.assertNotIn(plaintext.encode(), record)
                self.assertNotIn(application_data, record)
                incoming_s.write(record)
                decrypted = server.read(4096)
                self.assertEqual(decrypted, application_data)
                self.assertNotIn(plaintext.encode(), decrypted)
                self.assertEqual(AUDIT_MARKER.encode() in decrypted, port == 5003)


if __name__ == "__main__":
    unittest.main()
