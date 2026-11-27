"""Lokale, eigenstaendige Phasenauswertung ohne Netzwerk oder Browser-Abhaengigkeiten."""

from datetime import datetime
from html import escape
from pathlib import Path

from demo_ipc import plugin_label

EFFECTS = {
    1: "Ausgangszustand: Der Chat funktioniert. Standard v1 erzeugt keine Pruefmeldungen.",
    2: "Der falsche Config-Pin verhindert die Annahme des Rogue-Endpunkts. Das installierte Plugin bleibt unveraendert; der Chat funktioniert weiter.",
    3: "Gueltiges TLS allein erlaubt kein Update: Beide Clients verweigern die fehlende Ed25519-Signatur. Standard v1 bleibt aktiv.",
    4: "Die vertrauenswuerdige Signatur erlaubt die Installation von Audit v2. Beide Clients senden den festen Prueftext mit derselben Nachrichten-ID zum Collector.",
    5: "Das Abschalten des Verteilservers entfernt das gespeicherte Profil nicht. Router und Collector bleiben erreichbar; deshalb laufen Chat und Pruefmeldungen weiter.",
    6: "Eine weitere, neue Nachricht erzeugt erneut zwei Pruefmeldungen bei offline bleibendem Updater. Das belegt fortdauernde Wirkung nach dem Serverende; Neustart- oder Betriebssystem-Persistenz wird hier nicht getestet.",
}


def phase_filter(record, port=None):
    start = datetime.fromisoformat(record["started_utc"]).timestamp()
    end = datetime.fromisoformat(record["ended_utc"]).timestamp()
    result = f"frame.time_epoch >= {start:.6f} && frame.time_epoch <= {end:.6f}"
    if port is not None:
        result += f" && tcp.port == {port}"
    return result


def frames_filter(rows):
    return " || ".join(
        f"frame.number == {n}" for n in sorted({r["frame"] for r in rows})
    )


def evidence(record):
    if not record:
        return "Noch nicht ausgefuehrt."
    observed = record["observation"]
    if record["result"] != "PASS":
        return "Nachweis unvollstaendig: " + observed.get("error", "Messnachweis fehlt")
    chat = observed.get("chat", {})
    copies = chat.get("audit_events", 0)
    result = f"Testchat zugestellt; {copies} Pruefmeldungen am Collector."
    if record["phase"] == 2:
        result += " Pin-Pruefung: " + observed["tls_error"]
    elif record["phase"] == 3:
        result += " " + "; ".join(
            r["client"] + ": " + r["reason"] for r in observed["rejections"]
        )
    elif record["phase"] == 4:
        result += " Beide Clients: Audit v2 per Profilwechsel, gleiche Prozess-IDs."
    elif record["phase"] == 5:
        result += (
            f" Updater-PID {observed['config']['pid']} beendet; Port 5002 geschlossen."
        )
    elif record["phase"] == 6:
        result += " Port 5002 weiterhin geschlossen; beide Clients mit Audit v2."
    return result


def write_phase_report(directory, snapshot, phases):
    """Nur freigegebene Messfelder rendern; keine Keylogs oder Paketnutzdaten lesen."""
    directory = Path(directory)
    records = {p["phase"]: p for p in snapshot["phases"]}
    packet_index = snapshot.get("capture", {}).get("packet_index", {})
    indexed = packet_index.get("messages", {})
    nav, panels, summary, guide = [], [], [], ["# Pakete nach Phasen", ""]

    def copy_filter(label, value):
        if not value:
            return ""
        return (
            f'<div class="filter"><b>{escape(label)}</b><code>{escape(value)}</code>'
            '<button class="copy" type="button">Filter kopieren</button></div>'
        )

    for n, (title, expectation) in phases.items():
        record = records.get(n)
        state = record["result"] if record else "NOT RUN"
        observed = record.get("observation", {}) if record else {}
        chat = observed.get("chat", {})
        cls = "leak" if n >= 4 else "safe"
        if state != "PASS":
            cls = "pending"
        copies = str(chat["audit_events"]) if state == "PASS" and chat else "?"
        nav.append(
            f'<button class="phase {cls}" type="button" data-phase="{n}" aria-controls="phase-{n}">'
            f"<span>Phase {n} · {escape(state)}</span><strong>{escape(title)}</strong>"
            f"<span>{copies} Pruefmeldungen</span></button>"
        )
        summary.append(
            f"<tr><td>{n}</td><td>{escape(title)}</td><td>{escape(state)}</td>"
            f"<td>{copies}</td><td>{escape(evidence(record))}</td></tr>"
        )
        content = [
            f'<section id="phase-{n}" class="panel" {"hidden" if n != 1 else ""}>',
            f'<p class="eyebrow">PHASE {n} · {escape(state)}</p><h2>{escape(title)}</h2>',
            f'<p class="expectation">Versuchsziel: {escape(expectation)}</p>',
            '<div class="columns"><div><h3>Gemessen</h3>',
            f"<p>{escape(evidence(record))}</p>",
        ]
        if chat:
            content += [
                f"<p>Testnachricht: <b>{escape(chat['text'])}</b><br>"
                f"Nachrichten-ID: <code>{escape(chat['message_id'])}</code></p>"
            ]
        clients = observed.get("clients", {})
        if clients:
            content.append(
                "<p>"
                + "<br>".join(
                    escape(f"{c}: {plugin_label(s['name'])} v{s['version']}")
                    for c, s in clients.items()
                )
                + "</p>"
            )
        content.append("</div><div><h3>Einfluss und Einordnung</h3>")
        content.append(
            f"<p>{escape(EFFECTS[n]) if state == 'PASS' else 'Die Wirkung ist in diesem Lauf noch nicht bestaetigt.'}</p></div></div>"
        )
        guide += [f"## Phase {n}: {title} ({state})", "", evidence(record), ""]
        if record:
            content.append(
                "<h3>Passende Pakete in Wireshark</h3><p>Filter kopieren und in die Anzeigefilterzeile von Wireshark einfuegen.</p>"
            )
            indexed_message = indexed.get(chat.get("message_id"), {})
            for channel, label in (
                ("chat", "Chat dieser Nachricht · AES-GCM-Ciphertext"),
                (
                    "audit",
                    "Audit dieser Nachricht · Pruefmeldungen nach TLS-Debugentschluesselung",
                ),
            ):
                rows = indexed_message.get(channel, [])
                if rows:
                    value = frames_filter(rows)
                    content.append(copy_filter(label, value))
                    streams = ", ".join(
                        str(s) for s in sorted({r["stream"] for r in rows})
                    )
                    content.append(
                        f'<p class="hint">Exakt anhand der Nachrichten-ID in TLS-entschluesselten Anwendungsdaten zugeordnet. TCP-Streams: {streams}. Paket waehlen → Folgen → TLS-Stream.</p>'
                    )
                    guide += [
                        label + ":",
                        "",
                        "```text",
                        value,
                        "```",
                        "",
                        "TCP-Streams: " + streams,
                        "",
                    ]
                elif (
                    channel == "audit"
                    and state == "PASS"
                    and chat.get("audit_events") == 0
                ):
                    content.append(
                        '<p class="hint">Keine Audit-Nutzereignisse fuer diese Nachricht gemessen. TLS-Bereitschaftschecks auf Port 5003 sind keine Pruefmeldungen.</p>'
                    )
                elif chat:
                    content.append(
                        f'<p class="hint">{escape(label)}: keine exakte Paketzuordnung verfuegbar. Zeitfenster unten verwenden; daraus allein folgt kein Inhaltsnachweis.</p>'
                    )
            for label, port in (
                ("Gesamtes Zeitfenster der Phase", None),
                ("Updatekanal in dieser Phase", 5002),
                ("Rogue-TLS-Test in dieser Phase", 5004)
                if n == 2
                else ("Auditkanal in dieser Phase", 5003),
            ):
                value = phase_filter(record, port)
                content.append(copy_filter(label, value))
                guide += [label + ":", "", "```text", value, "```", ""]
            content.append(
                '<p class="hint">Zeitfenster enthalten auch Handshakes, ACKs und Portproben. Sie grenzen die Phase ein, beweisen aber keine Nutzdaten. Phasenkommentare markieren nur zeitlich benachbarte Pakete.</p>'
            )
        content.append("</section>")
        panels += content
    counts = snapshot["counts"]
    capture = snapshot.get("capture", {})
    markup = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Lab · Phasen und Wirkung</title><style>
:root{color-scheme:dark;font-family:Segoe UI,Arial,sans-serif;background:#101820;color:#eff5fb;font-size:18px}*{box-sizing:border-box}body{max-width:1440px;margin:auto;padding:36px}h1{font-size:2.2rem;margin:8px 0 16px}h2{font-size:1.6rem}h3{color:#9dd5f5;font-size:1.05rem}p{line-height:1.6}.eyebrow{letter-spacing:.15em;color:#a9c5d7;font-size:.75rem}.hint,footer{color:#b2c2d0;font-size:.85rem}.stats,.phases,.columns{display:grid;gap:16px}.stats{grid-template-columns:repeat(3,1fr);margin:24px 0}.stat,.panel{background:#1c2935;border:1px solid #3d5265;border-radius:12px;padding:22px}.stat b{font-size:2rem;display:block}.phases{grid-template-columns:repeat(6,1fr);margin:28px 0}.phase{font:inherit;text-align:left;color:inherit;background:#1c2935;border:2px solid #435364;border-radius:10px;padding:15px;cursor:pointer}.phase span{display:block;font-size:.76rem;color:#b2c2d0}.phase strong{display:block;font-size:.85rem;min-height:4.3em;padding-top:10px}.phase.safe{border-top:5px solid #65d6a0}.phase.leak{border-top:5px solid #ff947e}.phase[aria-pressed=true]{background:#30465b;outline:2px solid #a9dfff;outline-offset:3px}.columns{grid-template-columns:1fr 1fr;gap:36px}.filter{margin:14px 0;padding:16px;border:1px solid #50677c;border-radius:8px;background:#14212c}.filter b{display:block;margin-bottom:10px}code{font-family:Consolas,monospace;font-size:.83rem;overflow-wrap:anywhere}.filter code{display:block;user-select:all}.copy{background:#c9edff;color:#10212e;border:0;border-radius:6px;padding:8px 14px;font:inherit;font-size:.8rem;margin-top:12px;cursor:pointer}table{width:100%;border-collapse:collapse;font-size:.85rem;margin:26px 0}td,th{text-align:left;padding:12px;border-bottom:1px solid #3d5265;vertical-align:top}a{color:#a9dfff}footer{margin-top:28px}button:focus-visible{outline:3px solid #fff}@media(max-width:1000px){.phases{grid-template-columns:repeat(3,1fr)}.columns{grid-template-columns:1fr}}@media(max-width:650px){body{padding:16px}.phases{grid-template-columns:1fr 1fr}.stats{grid-template-columns:1fr}table{display:block;overflow:auto}}[hidden]{display:none!important}
</style><header><p class="eyebrow">LOKALES SECURITY LAB · GEMESSENER VERSUCH</p><h1>Was hat sich in welcher Phase veraendert?</h1><p>Phase auswaehlen: Aktion, gemessene Wirkung und zugehoerige Netzwerkpakete nebeneinander.</p></header>"""
    markup += (
        f'<div class="stats"><div class="stat"><b>{counts["chat_decrypted"]}</b>zugestellte Testnachrichten</div>'
        f'<div class="stat"><b>{counts["audit_events"]}</b>empfangene Pruefmeldungen</div>'
        f'<div class="stat"><b>{sum(p["result"] == "PASS" for p in records.values())} / 6</b>Phasen bestaetigt</div></div>'
    )
    markup += (
        '<nav class="phases" aria-label="Versuchsphasen">'
        + "".join(nav)
        + "</nav><main>"
        + "".join(panels)
    )
    markup += (
        "<details><summary>Alle Phasen vergleichen</summary><table><thead><tr><th>Phase</th><th>Versuch</th><th>Nachweis</th><th>Meldungen</th><th>Beobachtung</th></tr></thead><tbody>"
        + "".join(summary)
        + "</tbody></table></details></main>"
    )
    markup += (
        f"<footer>Mitschnitt: {escape(capture.get('state', 'disabled'))} · Paketzuordnung: {escape(packet_index.get('state', 'noch nicht erstellt'))} · Stand (UTC): {escape(snapshot['updated_utc'])}<br>"
        "Nach einer weiteren Phase Seite neu laden. Taste B oeffnet diese Uebersicht; W schliesst den Mitschnitt ab und oeffnet zusaetzlich Wireshark.<br>"
        '<a href="results.md">Messbericht</a> · <a href="packet-guide.md">Paketfilter als Text</a><br>'
        "Paketmengen sind keine Nachrichtenzaehler. Die Meldungen werden anhand der Collector-Ereignisse gezaehlt. TLS-Debugging zeigt Transportinhalte; Chat bleibt AES-GCM-verschluesselt.</footer>"
    )
    markup += """<script>
const buttons=[...document.querySelectorAll('[data-phase]')];
for(const b of buttons)b.addEventListener('click',()=>{for(const x of buttons)x.setAttribute('aria-pressed',String(x===b));for(const p of document.querySelectorAll('.panel'))p.hidden=p.id!=='phase-'+b.dataset.phase;});
buttons[0].setAttribute('aria-pressed','true');
for(const b of document.querySelectorAll('.copy'))b.addEventListener('click',async()=>{const c=b.parentNode.querySelector('code');try{await navigator.clipboard.writeText(c.textContent);b.textContent='Kopiert';}catch{const r=document.createRange();r.selectNodeContents(c);const s=getSelection();s.removeAllRanges();s.addRange(r);b.textContent='Markiert · Strg+C';}});
</script></html>"""
    (directory / "phase-report.html").write_text(markup, "utf-8")
    (directory / "packet-guide.md").write_text("\n".join(guide) + "\n", "utf-8")
