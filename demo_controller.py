"""Sechs gemessene Versuchsphasen im vorhandenen LabSession-Lebenszyklus."""

import json
import os
import socket
import ssl
import sys
import textwrap
import threading
import time
import uuid
import webbrowser
from collections import Counter
from datetime import datetime
from pathlib import Path

from audit_event import AUDIT_MARKER
from demo_capture import Capture
from demo_ipc import digest, plugin_label, utc
from demo_report import evidence, write_phase_report

PHASES = {
    1: ("NORMALBETRIEB", "AES-GCM-Chat mit Standard v1, keine Audit-Nutzdaten"),
    2: ("ROGUE-TLS-ENDPUNKT", "Client verweigert falschen Config-Zertifikat-Pin"),
    3: ("UNSIGNIERTES UPDATE", "TLS-Zustellung, Ablehnung wegen fehlender Signatur"),
    4: (
        "SIGNIERTES AUDIT-UPDATE",
        "Beide Clients: Profilwechsel v2; zwei korrelierte Pruefmeldungen",
    ),
    5: ("UPDATE-SERVER OFFLINE", "Nur Config endet; Chat und Audit bleiben aktiv"),
    6: (
        "FORTDAUER DER AENDERUNG",
        "Neue Nachricht und Pruefmeldungen bei weiterhin beendetem Config",
    ),
}

EXPERIMENTS = {
    1: (
        "Ausgangszustand",
        "Beide Clients sollen Standard v1 verwenden. Eine LAB-Nachricht durchlaeuft AES-GCM, Router und Entschluesselung; der Collector soll keine Pruefmeldung erhalten.",
    ),
    2: (
        "Angriff auf die Update-Identitaet",
        "Ein lokaler Rogue-Endpunkt auf 5004 zeigt ein Zertifikat derselben CA mit gueltiger IP, aber falscher Dienstidentitaet. Client 1 prueft den echten Config-Pin. Der regulaere Updatekanal wird nicht veraendert.",
    ),
    3: (
        "Paket ohne Freigabe",
        "Der echte Updater liefert unsigned.json ueber den geprueften TLS-Kanal an beide Clients. Die Ed25519-Signatur fehlt absichtlich. Danach pruefen wir, ob Standard v1 und der Chat weiter funktionieren.",
    ),
    4: (
        "Aktivierung des Auditprofils",
        "Der Updater pusht das vom Laborsignierer gueltig signierte Audit v2. Beide Clients muessen Signatur, Hash, Ziel und Version pruefen. Danach sendet der installierte Hook zusaetzliche Pruefmeldungen an Port 5003.",
    ),
    5: (
        "Update-Dienst abschalten",
        "Der Updater meldet sein Ende ueber den vorhandenen TLS-Kanal und schliesst ihn. Die Clients stellen Verbindungsversuche ein; das bereits installierte Plugin wird nicht entfernt.",
    ),
    6: (
        "Fortdauer messen",
        "Bei abgeschaltetem Updater wird eine neue LAB-Nachricht gesendet. Routerzustellung, Entschluesselung und zwei korrelierte Pruefmeldungen werden erneut gemessen.",
    ),
}


def new_results(root):
    parent = Path(root) / "demo-results"
    parent.mkdir(exist_ok=True)
    # Lokale Uhrzeit fuer den Ordner, saemtliche Messereignisse in UTC.
    name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = parent / name
    if path.exists():
        path = parent / (name + "-" + uuid.uuid4().hex[:8])
    path.mkdir()
    (path / "ipc").mkdir()
    for actor in (
        "client_1",
        "client_2",
        "config_server",
        "routing_server",
        "audit_collector",
    ):
        (path / "ipc" / actor).mkdir()
    for name in ("tls-client1.keys", "tls-client2.keys", "events.jsonl"):
        (path / name).touch(mode=0o600)
    return path


class DemoController:
    def __init__(self, session, capture=True):
        self.session = session
        self.directory = new_results(session.root)
        self.capture = Capture(self.directory, session.job) if capture else None
        self.events = []
        self.offsets = {}
        self.phases = {}
        self.started = utc()
        self.last_message = None
        self.finalized = False
        self.capture_warning = False
        self.snapshot = {}

    def start_capture(self):
        if self.capture and not self.capture.start():
            print(
                "[LAB] " + self.capture.info.get("reason", "Capture fehlt"), flush=True
            )
            print("[LAB] " + self.capture.manual_hint(), flush=True)
            self.note("capture_manual_required", details=self.capture.info)
            return False
        if self.capture:
            self.note("capture_started", details=self.capture.info.copy())
        return True

    def refresh(self):
        for path in sorted((self.directory / "ipc").glob("*.jsonl")):
            with path.open("rb") as handle:
                handle.seek(self.offsets.get(path.name, 0))
                while True:
                    start = handle.tell()
                    line = handle.readline()
                    if not line or not line.endswith(b"\n"):
                        self.offsets[path.name] = start
                        break
                    event = json.loads(line)
                    self.append(event)

    def append(self, event):
        self.events.append(event)
        with (self.directory / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    def note(self, event, **data):
        entry = dict(
            data, event=event, actor="controller", utc=utc(), event_id=uuid.uuid4().hex
        )
        self.append(entry)
        return entry

    def action(self, text):
        print(textwrap.fill("AKTION: " + text, width=60), flush=True)
        self.note("phase_action", description=text)

    def explain(self, record):
        """Interpretation ausschliesslich bereits erfasster Messwerte."""
        n, observed = record["phase"], record["observation"]
        print("\nBEFUND ZU PHASE " + str(n), flush=True)
        if record["result"] != "PASS":
            print(
                textwrap.fill(
                    "Nicht bestaetigt: " + observed.get("error", "Nachweis fehlt"), 60
                ),
                flush=True,
            )
            return
        if n == 2:
            print(
                textwrap.fill(
                    "TLS-Ablehnung im echten Client: " + observed["tls_error"], 60
                ),
                flush=True,
            )
            print(
                textwrap.fill(
                    "Die CA/IP-Pruefung allein reicht fuer die Update-Identitaet nicht aus. Der zusaetzliche Pin verhindert die Annahme. Es wurde kein Update installiert. Test: Rogue-Endpunkt, kein transparenter Proxy.",
                    60,
                ),
                flush=True,
            )
        if n == 3:
            print("Transport erfolgreich; Installation verweigert:", flush=True)
            for rejection in observed["rejections"]:
                print(
                    textwrap.fill(rejection["client"] + ": " + rejection["reason"], 60),
                    flush=True,
                )
            print(
                textwrap.fill(
                    "TLS authentisiert den Transport. Die unabhaengige Updatepruefung verlangt weiterhin eine gueltige Signatur.",
                    60,
                ),
                flush=True,
            )
        if n == 4:
            print("Ed25519 / SHA-256 / Ziel / Version: akzeptiert.", flush=True)
            print(
                "Audit v2 per Profilwechsel; beide Client-PIDs unveraendert.",
                flush=True,
            )
            print(
                textwrap.fill(
                    "Beide Clients melden den festen Prueftext. Der Empfaenger entschluesselt den Chat separat.",
                    60,
                ),
                flush=True,
            )
        if n == 5:
            print(
                f"Updater-PID {observed['config']['pid']} beendet; Port 5002 geschlossen.",
                flush=True,
            )
            print("Beide Clients: Updatekanal pausiert, kein Polling.", flush=True)
            print(
                textwrap.fill(
                    "Der Server verteilt Updates; das aktive Profil ist lokal gespeichert. Sein Abschalten entfernt Audit v2 nicht. Router und Collector sind weiterhin aktiv.",
                    60,
                ),
                flush=True,
            )
        if n == 6:
            print(
                "Updater offline; Audit v2 bleibt auf beiden Clients aktiv.", flush=True
            )
        clients = observed.get("clients", {})
        if clients:
            print(
                " | ".join(
                    f"{c}: {plugin_label(s['name'])} v{s['version']}"
                    for c, s in clients.items()
                ),
                flush=True,
            )
        chat = observed.get("chat")
        if chat:
            print(
                "AES-GCM verschluesselt -> Router -> korrekt entschluesselt.",
                flush=True,
            )
            print(
                f"Nachricht: {chat['text']}\nmessage_id: {chat['message_id']}",
                flush=True,
            )
            if chat["audit_events"]:
                print(
                    f"Collector: {chat['audit_events']} Pruefmeldungen; outgoing + incoming, gleiche ID.",
                    flush=True,
                )
            else:
                print("Collector: 0 Audit-Nutzdaten; Standard aktiv.", flush=True)

    def select(self, kind, message_id=None, after=0):
        return [
            event
            for event in self.events[after:]
            if event["event"] == kind
            and (message_id is None or event.get("message_id") == message_id)
        ]

    def wait(self, predicate, description, timeout=12):
        from window_layout import pump_window_messages

        deadline = time.monotonic() + timeout
        while True:
            pump_window_messages()
            self.session.ensure_alive()
            self.refresh()
            result = predicate()
            if result:
                return result
            if time.monotonic() >= deadline:
                raise RuntimeError("Kein Messnachweis: " + description)
            time.sleep(0.04)

    def request(self, actor, action, timeout=12, **data):
        request_id = uuid.uuid4().hex
        inbox = self.directory / "ipc" / actor
        temporary = inbox / (request_id + ".tmp")
        temporary.write_text(json.dumps(dict(data, action=action)), "utf-8")
        temporary.rename(temporary.with_suffix(".json"))
        event = self.wait(
            lambda: next(
                (e for e in self.events if e.get("request_id") == request_id), None
            ),
            f"IPC {actor}: {action}",
            timeout,
        )
        if event["event"] != "command_done":
            raise RuntimeError(event.get("reason", "IPC fehlgeschlagen"))
        return event.get("result")

    def client_states(self):
        return {
            client: self.request(client, "status")
            for client in ("client_1", "client_2")
        }

    @staticmethod
    def require(condition, reason):
        if not condition:
            raise RuntimeError(reason)

    def require_plugins(self, name, version):
        states = self.client_states()
        self.require(
            all(s["name"] == name and s["version"] == version for s in states.values()),
            f"Beide Clients muessen {name} v{version} verwenden: {states}",
        )
        return states

    def send(self, text, audit):
        response = self.request("client_1", "send", text=text)
        message_id = response["message_id"]

        def complete():
            return (
                self.select("chat_encrypted", message_id)
                and self.select("chat_routed", message_id)
                and self.select("chat_decrypted", message_id)
                and len(self.select("hook_completed", message_id)) == 2
                and (not audit or len(self.select("audit_received", message_id)) >= 2)
            )

        self.wait(
            complete, "Verschluesselung, Router, Entschluesselung und Plugin-Hooks"
        )
        sent = self.select("chat_encrypted", message_id)[0]
        routed = self.select("chat_routed", message_id)[0]
        received = self.select("chat_decrypted", message_id)[0]
        copies = self.select("audit_received", message_id)
        hooks = self.select("hook_completed", message_id)
        self.require(
            sent["algorithm"] == received["algorithm"] == "AES-256-GCM",
            "Falscher Kryptopfad",
        )
        self.require(
            sent["plaintext_sha256"] == received["plaintext_sha256"] == digest(text),
            "Entschluesselter Text weicht ab",
        )
        packet = routed["packet"]
        self.require(
            packet == sent["packet"]
            and text not in json.dumps(packet)
            and "plaintext" not in packet
            and "ciphertext" in packet
            and "nonce" in packet,
            "Routerpaket ist kein unveraendertes Ciphertextpaket",
        )
        self.require(
            {e["actor"] for e in hooks} == {"client_1", "client_2"}, "Plugin-Hook fehlt"
        )
        if audit:
            self.require(
                len(copies) == 2
                and {e["direction"] for e in copies} == {"outgoing", "incoming"}
                and {e["client_id"] for e in copies} == {"client_1", "client_2"}
                and all(
                    e["marker"] == AUDIT_MARKER
                    and e["sender"] == "client_1"
                    and e["recipient"] == "client_2"
                    for e in copies
                ),
                "Pruefmeldungen sind unvollstaendig oder nicht korreliert",
            )
        else:
            self.require(not copies, "Unerwartete Audit-Nutzdaten")
        self.last_message = dict(
            text=text, message_id=message_id, audit_events=len(copies)
        )
        return dict(
            self.last_message,
            encrypted=True,
            routed=True,
            decrypted=True,
            hook_versions=[e["version"] for e in hooks],
        )

    def rogue_test(self):
        # Vertrauenswuerdige CA/IP, aber falsche Identitaet: realer Pin-Check
        # im laufenden Client. Keine Aenderung an Vertrauensankern/Updatekanal.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(
            str(self.session.runtime / "pki" / "routing.pem"),
            str(self.session.runtime / "pki" / "routing.key"),
        )
        errors = []
        with socket.socket() as listener:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(("127.0.0.1", 5004))
            listener.listen(1)
            listener.settimeout(5)

            def serve():
                try:
                    raw, _ = listener.accept()
                    with raw:
                        raw.settimeout(3)
                        with context.wrap_socket(raw, server_side=True) as secured:
                            secured.recv(1)
                except (OSError, ssl.SSLError) as exc:
                    errors.append(type(exc).__name__)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                start = len(self.events)
                result = self.request("client_1", "probe_update")
                self.require(result["rejected"], "Client hat Rogue-Endpunkt akzeptiert")
                rejected = self.select("rogue_rejected", after=start)
                self.require(
                    rejected and "Pin" in rejected[-1]["reason"],
                    "Kein echter Pin-Ablehnungsnachweis",
                )
                return {
                    "test": "Rogue-Endpunkt, kein transparenter MITM-Proxy",
                    "tls_error": rejected[-1]["reason"],
                    "endpoint": "127.0.0.1:5004",
                }
            finally:
                worker.join(timeout=6)

    def phase(self, number):
        if number in self.phases:
            print(
                f"[LAB] Phase {number} bereits ausgefuehrt; keine zweite Aktion.",
                flush=True,
            )
            return self.phases[number]
        if number > 1 and self.phases.get(number - 1, {}).get("result") != "PASS":
            raise RuntimeError(
                f"Zuerst Phase {number - 1} erfolgreich abschliessen; R startet frisch"
            )
        self.refresh()
        began = utc()
        offset = len(self.events)
        self.note("phase_started", phase=number)
        title, explanation = EXPERIMENTS[number]
        print(f"\n--- VERSUCH {number}: {title} ---", flush=True)
        print(textwrap.fill(explanation, width=60), flush=True)
        details = {}
        try:
            if number == 1:
                self.action(
                    "Standard-Versionen lesen und LAB-NORMAL-001 ueber den regulaeren Chat senden."
                )
                details["clients"] = self.require_plugins("dummy", 1)
                details["chat"] = self.send("LAB-NORMAL-001", audit=False)
            elif number == 2:
                self.action(
                    "Rogue-TLS-Endpunkt starten und Client 1 dessen Zertifikat gegen den Config-Pin pruefen lassen."
                )
                before = self.require_plugins("dummy", 1)
                details.update(self.rogue_test())
                self.action(
                    "Installationszustand und Testchat nach der TLS-Ablehnung pruefen."
                )
                details["clients"] = self.require_plugins("dummy", 1)
                self.require(
                    before == details["clients"],
                    "Installation/Prozess unerwartet geaendert",
                )
                details["chat"] = self.send("LAB-ROGUE-002", audit=False)
            elif number == 3:
                self.action(
                    "unsigned.json vom echten Update-Server an beide Clients pushen."
                )
                self.require_plugins("dummy", 1)
                self.request("config_server", "publish", package="unsigned.json")
                self.wait(
                    lambda: (
                        {
                            e["actor"]
                            for e in self.select("update_rejected", after=offset)
                            if "Unsigniertes" in e.get("reason", "")
                        }
                        == {"client_1", "client_2"}
                    ),
                    "Ablehnung der fehlenden Ed25519-Signatur durch beide Clients",
                )
                details["rejections"] = [
                    {"client": e["actor"], "reason": e["reason"]}
                    for e in self.select("update_rejected", after=offset)
                ]
                details["clients"] = self.require_plugins("dummy", 1)
                self.action(
                    "Beide Ablehnungen erfasst; Chat mit unveraendertem Standard testen."
                )
                details["chat"] = self.send("LAB-UNSIGNED-003", audit=False)
            elif number == 4:
                self.action(
                    "Signiertes update.json verteilen; auf beide Installationen und den Profilwechsel warten."
                )
                before = self.client_states()
                self.request("config_server", "publish", package="update.json")
                self.wait(
                    lambda: (
                        {
                            e["actor"]
                            for e in self.select("update_installed", after=offset)
                            if e["version"] == 2
                        }
                        == {"client_1", "client_2"}
                    ),
                    "Signatur, Hash, Ziel, Version und Profilwechsel auf beiden Clients",
                )
                details["clients"] = self.require_plugins("audit", 2)
                self.require(
                    all(
                        before[c]["pid"] == details["clients"][c]["pid"] for c in before
                    ),
                    "Client wurde neu gestartet statt Profilwechsel",
                )
                self.action(
                    "LAB-AUDIT-004 senden und die Pruefmeldungen am echten Collector korrelieren."
                )
                details["chat"] = self.send("LAB-AUDIT-004", audit=True)
            elif number == 5:
                self.action(
                    "Updater kontrolliert beenden; Abschaltmeldung bei beiden Clients und Prozessende abwarten."
                )
                self.require_plugins("audit", 2)
                details["config"] = self.session.stop_config()
                details["chat"] = self.send("LAB-CONFIG-OFFLINE-005", audit=True)
                details["clients"] = self.require_plugins("audit", 2)
                self.require(
                    all(s["updates_paused"] for s in details["clients"].values()),
                    "Clients haben Updatekanal nicht pausiert",
                )
                details["services"] = self.services()
                self.require(
                    details["services"] == {"5001": True, "5002": False, "5003": True},
                    "Unerwarteter Dienstzustand",
                )
            elif number == 6:
                self.action(
                    "LAB-PERSISTENCE-006 bei offline bleibendem Updater durch den Chatweg schicken."
                )
                self.require(
                    self.session.config_stopped,
                    "Config wurde nicht absichtlich beendet",
                )
                details["clients"] = self.require_plugins("audit", 2)
                self.require(
                    all(s["updates_paused"] for s in details["clients"].values()),
                    "Updatekanal ist nicht pausiert",
                )
                self.require(not self.services()["5002"], "Config-Port ist erreichbar")
                details["chat"] = self.send("LAB-PERSISTENCE-006", audit=True)
                details["services"] = self.services()
                self.require(
                    details["services"] == {"5001": True, "5002": False, "5003": True},
                    "Unerwarteter Dienstzustand",
                )
            self.refresh()
            if number <= 3:
                self.require(
                    not self.select("audit_received", after=offset),
                    "Zusatz-Audit vor Aktivierung",
                )
            result = "PASS"
        except (OSError, RuntimeError, ValueError, KeyError) as exc:
            details["error"] = str(exc)
            result = "FAIL"
        record = dict(
            phase=number,
            title=PHASES[number][0],
            expectation=PHASES[number][1],
            started_utc=began,
            ended_utc=utc(),
            result=result,
            observation=details,
        )
        self.phases[number] = record
        self.note("phase_finished", **record)
        self.report()
        self.display()
        return record

    def services(self):
        state = {}
        for port in (5001, 5002, 5003):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    state[str(port)] = True
            except OSError:
                state[str(port)] = False
        return state

    def report(self):
        self.refresh()
        counts = Counter(e["event"] for e in self.events)
        installed = self.select("update_installed")
        latest = {}
        for event in self.events:
            if event["event"] not in {"update_installed", "plugin_loaded"}:
                continue
            latest[event["actor"]] = {
                "name": event["name"],
                "version": event["version"],
            }
        self.snapshot = dict(
            started_utc=self.started,
            updated_utc=utc(),
            directory=str(self.directory),
            phases=[self.phases[n] for n in sorted(self.phases)],
            counts={
                "chat_sent": counts["chat_encrypted"],
                "chat_decrypted": counts["chat_decrypted"],
                "updates_installed": len(installed),
                "audit_events": counts["audit_received"],
                "updates_rejected_by_cause": dict(
                    Counter(e["reason"] for e in self.select("update_rejected"))
                ),
            },
            plugins=latest,
            services=self.services(),
            last_message=self.last_message,
            capture=self.capture.info if self.capture else {"state": "disabled"},
        )
        target = self.directory / "results.json"
        temp = target.with_suffix(".tmp")
        temp.write_text(
            json.dumps(self.snapshot, ensure_ascii=False, indent=2), "utf-8"
        )
        temp.replace(target)
        lines = [
            "# Gemessener lokaler Laborversuch",
            "",
            f"Beginn (UTC): {self.started}",
            "",
            "| Phase | Erwartung | Tatsaechliche Beobachtung | Ergebnis |",
            "| --- | --- | --- | --- |",
        ]
        for n, (title, expectation) in PHASES.items():
            record = self.phases.get(n)
            observed = evidence(record)
            observed = observed.replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {n}: {title} | {expectation} | {observed} | {record['result'] if record else 'NOT RUN'} |"
            )
        lines += [
            "",
            "## Zaehler und Zustand",
            "",
            "```json",
            json.dumps(
                {
                    k: self.snapshot[k]
                    for k in ("counts", "plugins", "services", "capture")
                },
                ensure_ascii=False,
                indent=2,
            ),
            "```",
            "",
            "TLS-Keylogs und Mitschnitt sind ausschliesslich lokales Debugmaterial. "
            "Leere TLS-Bereitschaftsverbindungen sind keine Audit-Nutzdaten. "
            "Der Rogue-Test ist kein transparenter MITM-Proxy. "
            "Die Fortdauer betrifft das gespeicherte Profil nach Update-Server-Ende, "
            "keine Betriebssystem-Persistenz. Das Szenario ist keine historische Rekonstruktion "
            "und kein kryptographischer Bruch von Ed25519, TLS oder AES-GCM.",
        ]
        (self.directory / "results.md").write_text("\n".join(lines) + "\n", "utf-8")
        write_phase_report(self.directory, self.snapshot, PHASES)

    def display(self):
        print("\n" + "=" * 56 + "\n ENCROCHAT SECURITY LAB\n" + "=" * 56, flush=True)
        colors = {1: "32", 2: "90", 3: "90", 4: "31", 5: "33", 6: "31"}
        color = (
            os.name == "nt" and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
        )
        for n, (title, _) in PHASES.items():
            state = self.phases.get(n, {}).get("result", "BEREIT")
            if state == "PASS":
                state = {
                    1: "ZUGESTELLT",
                    2: "ABGEWEHRT",
                    3: "ABGELEHNT",
                    4: "INSTALLIERT",
                    5: "OFFLINE",
                    6: "BEWIESEN",
                }[n]
            line = f"[{n}] {title:<30} {state}"
            print(f"\033[{colors[n]}m{line}\033[0m" if color else line, flush=True)
        for client, plugin in self.snapshot.get("plugins", {}).items():
            print(
                f"{client.upper()}: {plugin_label(plugin['name'])} v{plugin['version']}",
                flush=True,
            )
        print(
            " | ".join(
                f"{p}: {'AKTIV' if s else 'OFFLINE'}"
                for p, s in self.snapshot.get("services", {}).items()
            ),
            flush=True,
        )
        if self.last_message:
            print(
                f"Letzte Nachricht: {self.last_message['text']}\nID: {self.last_message['message_id']}\n"
                f"Chat zugestellt; Audit-Nutzereignisse: {self.last_message['audit_events']}",
                flush=True,
            )
        if self.capture:
            print(f"Mitschnitt: {self.capture.info['state']}", flush=True)
        if self.phases:
            last = self.phases[max(self.phases)]
            self.explain(last)
        print(
            "1-6: Phase | B: Phasenbericht | W: Wireshark\nS: Zustand | R: frisch starten | Q: beenden",
            flush=True,
        )

    def open_report(self):
        self.report()
        path = self.directory / "phase-report.html"
        if not webbrowser.open(path.resolve().as_uri()):
            print(f"[LAB] Phasenbericht manuell oeffnen: {path}", flush=True)

    def status(self):
        states = self.client_states()
        self.note("status_observed", clients=states, services=self.services())
        self.report()
        self.snapshot["plugins"] = states
        self.display()

    def open_wireshark(self):
        if not self.capture:
            raise RuntimeError("Mitschnitt nur im Presentation-Modus aktiv")
        try:
            result = self.capture.open()
            self.note("wireshark_opened", capture_state=result["state"])
        finally:
            self.report()
        self.open_report()

    def finish(self):
        if self.finalized:
            return
        if self.capture:
            self.capture.finish()
        self.refresh()
        self.note("session_finished", services=self.services())
        self.report()
        self.finalized = True
