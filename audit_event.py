"""Auditformat für den synthetischen Nachweis am Endpunkt."""

import json

from tls_transport import connect

AUDIT_MARKER = "LAB-AUDIT-PROBE"


def send_probe(metadata):
    entry = dict(metadata, marker=AUDIT_MARKER)
    with connect(5003, timeout=0.75) as sock:
        sock.sendall((json.dumps(entry) + "\n").encode("utf-8"))
        with sock.makefile("rb") as stream:
            if stream.readline(4) != b"OK\n":
                raise OSError("Collector hat den Prüftext nicht bestätigt")
