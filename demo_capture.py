"""Lokaler TShark-Mitschnitt und laufbezogene TLS-Debugdateien."""

import csv
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from bisect import bisect_left
from datetime import datetime, timezone
from pathlib import Path

from demo_ipc import utc

PORTS = (5001, 5002, 5003, 5004)
CAPTURE_FILTER = (
    "ip and src host 127.0.0.1 and dst host 127.0.0.1 and tcp and ("
    + " or ".join(f"port {port}" for port in PORTS)
    + ")"
)
DISPLAY_FILTER = (
    "tcp.port == 5001 || tcp.port == 5002 || tcp.port == 5003 || tcp.port == 5004"
)


def find_program(name):
    found = shutil.which(name)
    if found:
        return found
    for base in (
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Programs"),
    ):
        if base:
            path = Path(base) / "Wireshark" / (name + ".exe")
            if path.is_file():
                return str(path)
    return None


def run(args, timeout=15):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )


def loopback_interface(listing):
    for line in listing.splitlines():
        match = re.match(r"\d+\.\s+(\S+)\s+\((.*)\)", line)
        if match and (
            "npf_loopback" in match[1].lower() or "loopback" in match[2].lower()
        ):
            return match[1]  # stabiler Geraetename statt wechselnder Interface-Nummer
    raise RuntimeError("Keine Npcap-Loopback-Schnittstelle gefunden")


def pcapng_packets(path):
    """Vollstaendige Blockgrenzen, Section und Enhanced Packet Blocks pruefen."""
    count = 0
    endian = None
    with Path(path).open("rb") as handle:
        while True:
            header = handle.read(12)
            if not header:
                break
            if len(header) != 12:
                raise ValueError("Unvollstaendiger pcapng-Header")
            if header[:4] == b"\x0a\x0d\x0d\x0a":
                endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(
                    header[8:12]
                )
            if endian is None:
                raise ValueError("Keine gueltige pcapng-Section")
            kind, length = struct.unpack(endian + "II", header[:8])
            if length < 12 or length % 4 or length > 64 * 1024 * 1024:
                raise ValueError("Ungueltige pcapng-Blocklaenge")
            tail = handle.read(length - 12)
            if (
                len(tail) != length - 12
                or len(tail) < 4
                or struct.unpack(endian + "I", tail[-4:])[0] != length
            ):
                raise ValueError("Unvollstaendiger pcapng-Block")
            if kind == 6:
                count += 1
    if endian is None or count == 0:
        raise ValueError("Mitschnitt enthaelt keine Netzwerkpakete")
    return count


KEY_LINE = re.compile(
    r"(?:CLIENT|SERVER)_(?:HANDSHAKE_TRAFFIC_SECRET|TRAFFIC_SECRET_\d+)|EXPORTER_SECRET"
)

PHASE_LABELS = {
    1: "Normalbetrieb",
    2: "Rogue-TLS-Test",
    3: "Unsigniertes Update",
    4: "Audit-Update verteilen",
    5: "Updater abschalten",
    6: "Fortdauer beweisen",
}


def mark_capture(directory, tshark, editcap, frames):
    """Nur Metadaten einer Kopie ergaenzen: Originalpakete bleiben unveraendert."""
    directory = Path(directory)
    event_file = directory / "events.jsonl"
    events = [json.loads(line) for line in event_file.read_text("utf-8").splitlines()]
    times = [float(line.split("\t")[1]) for line in frames]
    annotations, timeline = {}, []
    for event in sorted(events, key=lambda e: e["utc"]):
        kind = event["event"]
        if kind in {"phase_started", "phase_finished"}:
            phase = event["phase"]
            token = f"LAB-PHASE-{phase} " + (
                "BEGIN" if kind == "phase_started" else "END"
            )
            label = PHASE_LABELS[phase]
            if kind == "phase_finished":
                label += ": " + event["result"]
        elif kind == "config_stopped":
            phase, token, label = (
                5,
                "LAB-CONFIG-OFFLINE",
                "Config-Prozess beendet, Port 5002 geschlossen",
            )
        elif kind == "update_installed" and event.get("version") == 2:
            phase, token = 4, "LAB-INSTALL-V2"
            label = event["actor"] + ": Audit v2 installiert"
        else:
            continue
        moment = datetime.fromisoformat(event["utc"]).timestamp()
        index = min(bisect_left(times, moment), len(times) - 1)
        if index and abs(times[index - 1] - moment) <= abs(times[index] - moment):
            index -= 1
        number = int(frames[index].split("\t")[0])
        comment = f"{token} | {label} | Controller-UTC: {event['utc']} | zeitlich naechstes Paket"
        annotations.setdefault(number, []).append(comment)
        timeline.append(
            dict(
                phase=phase,
                marker=token,
                description=label,
                event_utc=event["utc"],
                frame_number=number,
                seconds_from_capture=round(moment - times[0], 6),
                packet_delta_ms=round((times[index] - moment) * 1000, 3),
            )
        )
    if not timeline:
        return {"state": "no_phase_events"}
    with (directory / "phase-timeline.csv").open(
        "x", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(timeline[0]))
        writer.writeheader()
        writer.writerows(timeline)
    lines = [
        "# Phasen im echten Mitschnitt",
        "",
        "Die Markierungen sind Kommentare zu zeitlich benachbarten echten Paketen.",
        "Sie erzeugen keinen Netzwerkverkehr und aendern keine Paketnutzdaten. Ereignis und Paket sind nicht zwingend zeitgleich.",
        "Original: demo.pcapng. Kommentierte Kopie: demo-marked.pcapng.",
        "",
        "| Aktion | Controller-UTC | Zeit ab erstem Paket (s) | Naechstes Paket | Abstand (ms) |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines += [
        f"| {e['marker']}: {e['description']} | {e['event_utc']} | {e['seconds_from_capture']} | {e['frame_number']} | {e['packet_delta_ms']} |"
        for e in timeline
    ]
    (directory / "phase-timeline.md").write_text("\n".join(lines) + "\n", "utf-8")
    if not editcap:
        return {
            "state": "timeline_only",
            "reason": "editcap fehlt",
            "events": len(timeline),
        }
    help_result = run([editcap, "--help"])
    if "--preserve-packet-comments" not in help_result.stdout:
        return {
            "state": "timeline_only",
            "reason": "editcap-Kommentaroption nicht bestaetigt",
            "events": len(timeline),
        }
    output = directory / "demo-marked.pcapng"
    if output.exists():
        raise ValueError(
            "Kommentierter Mitschnitt existiert bereits; wird nicht ersetzt"
        )
    args = [editcap, "-F", "pcapng", "--preserve-packet-comments"]
    for number, comments in annotations.items():
        args += ["-a", str(number) + ":" + "\n".join(comments)]
    result = run(args + [str(directory / "demo.pcapng"), str(output)])
    if result.returncode or pcapng_packets(output) != len(frames):
        raise ValueError("Kommentierte Kopie konnte nicht bestaetigt werden")
    checked = run(
        [
            tshark,
            "-n",
            "-r",
            str(output),
            "-Y",
            'frame.comment contains "LAB-"',
            "-T",
            "fields",
            "-e",
            "frame.number",
        ]
    )
    if checked.returncode or len(checked.stdout.splitlines()) != len(annotations):
        raise ValueError("Paketkommentare im Dissector nicht nachweisbar")
    return {
        "state": "complete",
        "path": str(output),
        "events": len(timeline),
        "commented_packets": len(annotations),
        "timeline": str(directory / "phase-timeline.csv"),
    }


def write_graph_profile(profile, marked):
    """10-Spalten-Format gemaess lokal erzeugtem Wireshark-io_graphs-Header."""
    rows = [
        [
            "Enabled",
            "Chat 5001",
            "tcp.port == 5001",
            "#22aa55",
            "Line",
            "Packets",
            "",
            "0",
            "1",
            "FALSE",
        ],
        [
            "Enabled",
            "Updates 5002",
            "tcp.port == 5002",
            "#ee9900",
            "Line",
            "Packets",
            "",
            "0",
            "1",
            "FALSE",
        ],
        [
            "Enabled",
            "Audit 5003",
            "tcp.port == 5003",
            "#dd3344",
            "Line",
            "Packets",
            "",
            "0",
            "1",
            "FALSE",
        ],
    ]
    if marked:
        for number, label in PHASE_LABELS.items():
            rows.append(
                [
                    "Enabled",
                    str(number) + ": " + label + " [Marker x20]",
                    f'frame.comment contains "LAB-PHASE-{number} BEGIN"',
                    "#777777" if number in (2, 3) else "#3366dd",
                    "Impulse",
                    "Packets",
                    "",
                    "0",
                    "20",
                    "FALSE",
                ]
            )
        rows.append(
            [
                "Enabled",
                "Updater OFFLINE [Marker x25]",
                'frame.comment contains "LAB-CONFIG-OFFLINE"',
                "#ee9900",
                "Impulse",
                "Packets",
                "",
                "0",
                "25",
                "FALSE",
            ]
        )
    with (profile / "io_graphs").open("x", newline="", encoding="utf-8") as handle:
        csv.writer(
            handle, quoting=csv.QUOTE_ALL, escapechar="\\", doublequote=False
        ).writerows(rows)


def repair_graph_colors(profile):
    """Auch bestehende laufbezogene Profile unter Erhalt der alten Datei reparieren."""
    path = Path(profile) / "io_graphs"
    if not path.exists():
        return False
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle, escapechar="\\", doublequote=False))
    changed = False
    for row in rows:
        if len(row) == 10 and re.fullmatch(r"[0-9a-fA-F]{6}", row[3]):
            row[3] = "#" + row[3]
            changed = True
    if changed:
        backup = path.with_name("io_graphs.before-color-fix")
        if not backup.exists():
            shutil.copy2(path, backup)
        temporary = path.with_name("io_graphs.tmp")
        with temporary.open("w", newline="", encoding="utf-8") as handle:
            csv.writer(
                handle, quoting=csv.QUOTE_ALL, escapechar="\\", doublequote=False
            ).writerows(rows)
        temporary.replace(path)
    return changed


def index_message_packets(directory, tshark):
    """Exakte Paketnummern anhand echter Nachrichten-IDs, nicht naher Zeitstempel.

    TLS-Debugdaten bleiben im Prozess. Nur Frame-/Streamnummern exportieren.
    Fehlende Zuordnungen (z.B. segmentierte Nutzdaten) niemals erfinden.
    """
    directory = Path(directory)
    events = [
        json.loads(line)
        for line in (directory / "events.jsonl").read_text("utf-8").splitlines()
    ]
    messages = {
        e["message_id"]: {"chat": [], "audit": []}
        for e in events
        if e["event"] == "chat_encrypted"
    }
    args = [
        tshark,
        "-2",
        "-n",
        "-r",
        str(directory / "demo.pcapng"),
        "-o",
        "tls.keylog_file:" + str(directory / "tls-combined.keys"),
    ]
    for port in PORTS:
        args += ["-d", f"tcp.port=={port},tls"]
    result = run(
        args
        + [
            "-Y",
            "tls && data.data",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "tcp.stream",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "data.data",
        ],
        timeout=30,
    )
    if result.returncode:
        raise ValueError(
            "TLS-Anwendungsdaten konnten nicht fuer die Paketzuordnung gelesen werden"
        )
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            continue
        frame, stream, src, dst, payloads = fields
        channel = (
            "chat"
            if "5001" in (src, dst)
            else "audit"
            if "5003" in (src, dst)
            else None
        )
        if channel is None:
            continue
        payload = b"".join(
            bytes.fromhex(part.replace(":", "")) for part in payloads.split(",")
        )
        for mid, channels in messages.items():
            if mid.encode("ascii") in payload:
                channels[channel].append(dict(frame=int(frame), stream=int(stream)))
    index = dict(state="complete", messages=messages)
    (directory / "packet-index.json").write_text(json.dumps(index, indent=2), "utf-8")
    return index


def merge_keylogs(directory):
    lines, randoms = set(), set()
    per_client = {}
    for name in ("tls-client1.keys", "tls-client2.keys"):
        path = Path(directory) / name
        valid = 0
        for line in path.read_text("ascii").splitlines():
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            if (
                len(fields) != 3
                or KEY_LINE.fullmatch(fields[0]) is None
                or re.fullmatch(r"[0-9a-fA-F]{64}", fields[1]) is None
                or re.fullmatch(r"(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{96})", fields[2])
                is None
            ):
                raise ValueError(
                    f"Ungueltiges NSS-Keylog-Format in {name}; Inhalt wird nicht ausgegeben"
                )
            lines.add(" ".join(fields))
            randoms.add(fields[1].lower())
            valid += 1
        if not valid:
            raise ValueError(f"Keine TLS-Sitzungsschluessel in {name}")
        per_client[name] = valid
    output = Path(directory) / "tls-combined.keys"
    with output.open("x", encoding="ascii") as handle:
        handle.write(
            "# TLS 1.3 NSS secrets: local laboratory only\n"
            + "\n".join(sorted(lines))
            + "\n"
        )
    output.chmod(0o600)
    return {"records": len(lines), "per_client": per_client}, randoms


class Capture:
    def __init__(self, directory, job=None):
        self.directory = Path(directory)
        self.path = self.directory / "demo.pcapng"
        self.tshark = find_program("tshark")
        self.wireshark = find_program("wireshark")
        self.dumpcap = find_program("dumpcap")
        self.editcap = find_program("editcap")
        self.process = None
        self.job = job
        self.finished = False
        self.info = {
            "state": "not_started",
            "filter": CAPTURE_FILTER,
            "tshark": self.tshark,
            "wireshark": self.wireshark,
            "dumpcap": self.dumpcap,
            "started_utc": None,
            "ended_utc": None,
        }
        self.log = None

    def manual_hint(self):
        return (
            "Manuell VOR dem Laborstart: Wireshark > Capture Options > Npcap Loopback; "
            f"Capture-Filter: {CAPTURE_FILTER}. Nach Phase 6 stoppen und als {self.path} speichern. "
            "Danach W; bei spaeter begonnenem Mitschnitt fehlen TLS-Handshakes."
        )

    def start(self):
        if not self.tshark:
            self.info.update(state="manual_required", reason="TShark nicht installiert")
            return False
        try:
            listing = run([self.tshark, "-D"])
            if listing.returncode:
                raise RuntimeError(
                    "TShark kann Capture-Interfaces nicht oeffnen; Npcap/Rechte pruefen"
                )
            interface = loopback_interface(listing.stdout)
            version = run([self.tshark, "--version"])
            self.info.update(
                interface=interface,
                tshark_version=version.stdout.splitlines()[0],
                npcap_available=True,
            )
            self.log = (self.directory / "capture.log").open("ab")
            options = {}
            if os.name == "nt":
                startup = subprocess.STARTUPINFO()
                startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
                startup.wShowWindow = 0
                options.update(
                    creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup
                )
                if self.job:
                    options["creationflags"] |= 4  # CREATE_SUSPENDED vor Job-Zuordnung
            self.process = subprocess.Popen(
                [
                    self.tshark,
                    "-n",
                    "-i",
                    interface,
                    "-f",
                    CAPTURE_FILTER,
                    "-F",
                    "pcapng",
                    "-w",
                    str(self.path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=self.log,
                stderr=self.log,
                **options,
            )
            if self.job:
                self.job.attach(self.process)
                if os.name == "nt":
                    self.job.resume(self.process)
            deadline = time.monotonic() + 12
            while not self.path.exists() or self.path.stat().st_size < 28:
                if self.process.poll() is not None:
                    raise RuntimeError(
                        "Capture-Prozess vor Bereitschaft beendet; siehe capture.log"
                    )
                if time.monotonic() > deadline:
                    raise RuntimeError(
                        "Capture nicht rechtzeitig bereit; siehe capture.log"
                    )
                time.sleep(0.1)
            self.info.update(state="recording", started_utc=utc())
            return True
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            self.stop_process()
            self.info.update(state="manual_required", reason=str(exc))
            return False

    def alive(self):
        if self.info["state"] == "recording" and self.process.poll() is not None:
            self.info.update(
                state="failed", reason="Capture unerwartet beendet", ended_utc=utc()
            )
            return False
        return self.info["state"] == "recording"

    def stop_process(self):
        graceful = True
        if self.process and self.process.poll() is None:
            try:
                if os.name == "nt":
                    # Eigenes verstecktes Capture-Konsolenfenster: Ctrl+Break erreicht
                    # TShark und dessen dumpcap, keines der Laborfenster.
                    code = (
                        "import ctypes,time,sys; k=ctypes.WinDLL('kernel32'); "
                        "k.FreeConsole(); "
                        "sys.exit(3) if not k.AttachConsole(int(sys.argv[1])) else None; "
                        "handler=ctypes.WINFUNCTYPE(ctypes.c_bool,ctypes.c_ulong)(lambda event: True); "
                        "k.SetConsoleCtrlHandler(handler,True); "
                        "sys.exit(4) if not k.GenerateConsoleCtrlEvent(1,0) else None; time.sleep(.2)"
                    )
                    result = run(
                        [sys.executable, "-c", code, str(self.process.pid)], timeout=5
                    )
                    if result.returncode:
                        raise RuntimeError(
                            f"Capture-Ctrl+Break fehlgeschlagen (Helper {result.returncode})"
                        )
                else:
                    import signal

                    self.process.send_signal(signal.SIGINT)
                self.process.wait(timeout=12)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                self.info["stop_error"] = str(exc)
                graceful = False
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log:
            self.log.close()
            self.log = None
        return graceful

    def finish(self):
        if self.finished:
            return self.info
        if self.info["state"] == "recording":
            self.alive()
        was_failed = self.info["state"] == "failed"
        graceful = self.stop_process()
        self.info.update(ended_utc=utc(), graceful_stop=graceful)
        try:
            count = pcapng_packets(self.path)
            self.info["packets"] = count
            if was_failed:
                raise ValueError(
                    "Capture war unerwartet beendet; kein bestaetigter vollstaendiger Lauf"
                )
            if not graceful:
                raise ValueError(
                    "Capture musste hart beendet werden; keine Erfolgsmeldung"
                )
            metadata, randoms = merge_keylogs(self.directory)
            self.info["keylogs"] = metadata
            if self.tshark:
                result = run(
                    [
                        self.tshark,
                        "-n",
                        "-r",
                        str(self.path),
                        "-T",
                        "fields",
                        "-e",
                        "frame.number",
                        "-e",
                        "frame.time_epoch",
                    ]
                )
                if result.returncode or len(result.stdout.splitlines()) != count:
                    raise ValueError(
                        "TShark konnte den Mitschnitt nicht vollstaendig lesen"
                    )
                frames = result.stdout.splitlines()
                for name, frame in (
                    ("first_packet_utc", frames[0]),
                    ("last_packet_utc", frames[-1]),
                ):
                    self.info[name] = datetime.fromtimestamp(
                        float(frame.split("\t")[1]), timezone.utc
                    ).isoformat()
                args = [self.tshark, "-n", "-r", str(self.path)]
                for port in PORTS:
                    args += ["-d", f"tcp.port=={port},tls"]
                result = run(
                    args
                    + [
                        "-Y",
                        "tls.handshake.type == 1",
                        "-T",
                        "fields",
                        "-e",
                        "tls.handshake.random",
                    ]
                )
                captured = set(result.stdout.lower().split())
                if result.returncode or not randoms.intersection(captured):
                    raise ValueError(
                        "TLS-Keylogs passen zu keinem ClientHello im Mitschnitt"
                    )
                self.info["matching_tls_sessions"] = len(randoms.intersection(captured))
                try:
                    self.info["annotations"] = mark_capture(
                        self.directory, self.tshark, self.editcap, frames
                    )
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    self.info["annotations"] = {"state": "failed", "reason": str(exc)}
                try:
                    self.info["packet_index"] = index_message_packets(
                        self.directory, self.tshark
                    )
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    self.info["packet_index"] = {"state": "failed", "reason": str(exc)}
            else:
                self.info["keylog_match_unverified"] = True
            self.info["state"] = "complete"
            self.finished = True
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            self.info.update(state="invalid", reason=str(exc))
            # Ein vorhandener automatischer Mitschnitt wird niemals ersetzt.
            # Bei fehlender manueller Datei darf W spaeter erneut validieren.
            self.finished = self.path.exists()
        return self.info

    def open(self):
        info = self.finish()
        if info["state"] != "complete":
            raise RuntimeError(info.get("reason", "Kein gueltiger Mitschnitt"))
        if not self.wireshark:
            raise RuntimeError(
                "Wireshark fehlt. Mitschnitt und tls-combined.keys manuell auf anderem Rechner oeffnen."
            )
        help_result = run([self.wireshark, "--help"])
        if not all(option in help_result.stdout for option in ("-r", "-o", "-d", "-Y")):
            raise RuntimeError(
                "Installierte Wireshark-CLI nicht erkannt; WIRESHARK_PRESENTATION.md verwenden"
            )
        preferences = run([self.tshark, "-G", "defaultprefs"]) if self.tshark else None
        marked = info.get("annotations", {}).get("state") == "complete"
        view_path = info["annotations"]["path"] if marked else str(self.path)
        if not marked and info.get("annotations", {}).get("state") not in {
            None,
            "no_phase_events",
        }:
            print(
                "[LAB] Plotmarkierungen nicht automatisch bestaetigt; phase-timeline.md als Zeitreferenz verwenden.",
                flush=True,
            )
        args = [self.wireshark, "-n", "-r", view_path, "-Y", DISPLAY_FILTER]
        profile = self.directory / "wireshark-profile"
        profile.mkdir(exist_ok=True)
        filters = "\n".join(
            f'"{name}" tcp.port == {port}'
            for name, port in (
                ("Chat AES-GCM", 5001),
                ("Update", 5002),
                ("Audit", 5003),
            )
        )
        if marked:
            filters += '\n"Alle Phasenmarker" frame.comment contains "LAB-"'
            filters += '\n"Updater OFFLINE" frame.comment contains "LAB-CONFIG-OFFLINE"'
        from demo_report import frames_filter, phase_filter

        for event in (
            json.loads(line)
            for line in (self.directory / "events.jsonl")
            .read_text("utf-8")
            .splitlines()
        ):
            if event["event"] != "phase_finished":
                continue
            number = event["phase"]
            filters += f'\n"Phase {number} - Zeitfenster" ' + phase_filter(event)
            mid = event["observation"].get("chat", {}).get("message_id")
            channels = info.get("packet_index", {}).get("messages", {}).get(mid, {})
            for channel, rows in channels.items():
                if rows:
                    filters += (
                        f'\n"Phase {number} - {channel} Nutzdaten" '
                        + frames_filter(rows)
                    )
        filter_path = profile / "dfilters"
        existing = filter_path.read_text("utf-8") if filter_path.exists() else ""
        additions = [
            line for line in filters.splitlines() if line not in existing.splitlines()
        ]
        if additions:
            with filter_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    ("\n" if existing and not existing.endswith("\n") else "")
                    + "\n".join(additions)
                    + "\n"
                )
        if not (profile / "io_graphs").exists():
            write_graph_profile(profile, marked)
        else:
            repair_graph_colors(profile)
        if "persconf" in help_result.stdout:
            args += ["-P", "persconf:" + str(profile)]
        # Laut installierter wireshark.html oeffnet io,stat die I/O-Graphen.
        if "-z" in help_result.stdout:
            args += ["-z", "io,stat"]
        for port in PORTS:
            args += ["-d", f"tcp.port=={port},tls"]
        if preferences and "tls.keylog_file:" in preferences.stdout:
            args += [
                "-o",
                "tls.keylog_file:" + str(self.directory / "tls-combined.keys"),
            ]
            info["automatic_keylog_option"] = True
        else:
            info["automatic_keylog_option"] = False
            print("[LAB] TLS-Keylog manuell in Preferences > Protocols > TLS laden.")
        if preferences and "gui.update.enabled:" in preferences.stdout:
            args += ["-o", "gui.update.enabled:FALSE"]
        # Anzeige bleibt beim spaeteren Q offen; kein Labor-Kind im Jobobjekt.
        subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return info
