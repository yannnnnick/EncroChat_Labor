# Sicherheitslabor für verschlüsselten Chat und signierte Updates

Zwei Clients tauschen AES-256-GCM-verschlüsselte Nachrichten über einen lokalen Router aus. Der Versuch zeigt, wie ein signiertes Update das Verhalten beider Endpunkte verändert. Im Standardprofil bleibt der Audit-Collector still. Im Auditprofil meldet jeder Client zu einer zugestellten Nachricht den festen Prüftext `LAB-AUDIT-PROBE`. Über die Nachrichten-ID lassen sich Versand, Empfang und Prüfmeldungen einander zuordnen. Der Chattext bleibt bei den Clients.

## Setup unter Windows

Der zentrale Starter benötigt Windows, Python ab 3.10 mit TLS 1.3 und freie Loopback-Ports von 5001 bis 5004. Die folgenden Befehle werden im Ordner mit dieser README in PowerShell ausgeführt.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe start_lab.py --check
```

## Versuch ausführen

Der folgende Befehl startet alle fünf Prozesse, prüft die sechs Phasen in der angegebenen Reihenfolge und beendet das Labor. Er eignet sich für die Bewertung und benötigt keinen Paketmitschnitt.

```powershell
.\.venv\Scripts\python.exe -X utf8 start_lab.py --mode fresh --automated-demo --headless
```

| Phase | Erwartete Beobachtung |
| --- | --- |
| 1 · Normalbetrieb | Der Empfänger entschlüsselt den Chat. Der Collector erhält keine Prüfmeldung. |
| 2 · Serveridentität | Client 1 verwirft das Zertifikat eines lokalen Testdienstes. Die CA ist gültig, aber der Pin des Config-Servers stimmt nicht. |
| 3 · Paketprüfung | Beide Clients lehnen ein unsigniertes Update ab. Sie verwenden weiterhin Standard v1. |
| 4 · Signiertes Auditprofil | Beide Clients aktivieren Audit v2 im laufenden Prozess. Der Collector erhält je eine Prüfmeldung für Versand und Empfang mit derselben Nachrichten-ID. |
| 5 · Update-Dienst beendet | Der Config-Server meldet sich ab. Chat, Router und Auditprofil laufen weiter. |
| 6 · Fortdauer | Eine weitere Nachricht erreicht den Empfänger. Beide Prüfmeldungen treffen trotz beendetem Config-Server ein. |

Der Starter nennt den Ergebnisordner unter `demo-results/`. Dort stehen die Phasenergebnisse in `results.md`, die Messwerte in `results.json` und die Ansicht für die Präsentation in `phase-report.html`. Bei einem erfolgreichen automatischen Durchlauf haben alle sechs Phasen den Status `PASS` und der Prozess endet mit Exitcode 0.

### Interaktive Vorführung

```powershell
.\start_lab.cmd --mode fresh
```

In der Steuerkonsole führen die Tasten **1 bis 6** durch den Versuch. **S** zeigt den Zustand, **B** öffnet den Bericht und **Q** beendet die Laborprozesse. In den Clientfenstern lässt sich Text in beide Richtungen senden. `/status` zeigt das lokale Profil. Für vergleichbare Messergebnisse den automatischen Versuch ohne zusätzliche manuelle Nachrichten ausführen.

Ein frischer Start erzeugt Zertifikate, Signierschlüssel und Paketangebote unter `.lab/`. Einen vorherigen Stand sichert der Starter unter `.lab-backup-…/`. Mit `.\start_lab.cmd --mode resume` lässt sich der installierte Profilstand wieder öffnen.

Für die optionale Paketanalyse startet `.\start_lab.cmd --mode presentation` die Vorführung mit Mitschnitt. Dazu werden Wireshark, TShark und ein verfügbarer Npcap-Loopback-Adapter benötigt. **W** öffnet die Auswertung. Die Filter `tcp.port == 5001`, `tcp.port == 5002` und `tcp.port == 5003` trennen Chat, Update und Audit. Mitschnitte und TLS-Debugschlüssel bleiben lokal im jeweiligen Ergebnisordner.

## Aufbau und Vertrauensmodell

| Dateien | Aufgabe |
| --- | --- |
| `start_lab.cmd`, `start_lab.py`, `setup_lab.py` | Laufzeitverzeichnis vorbereiten, Prozesse starten und kontrolliert beenden |
| `client_1.py`, `client_2.py`, `chat_client.py` | Zwei Identitäten mit gemeinsamer Chatimplementierung. AES-GCM authentisiert auch die Nachrichtenmetadaten. |
| `routing_server.py` | Leitet über Port 5001 Metadaten, Nonce und verschlüsselten Inhalt an den Empfänger weiter. |
| `config_server.py`, `plugin_runtime.py` | Verteilen über Port 5002 und aktivieren signierte Betriebsprofile. Jeder Client speichert den geprüften Stand atomar. |
| `audit_event.py`, `audit_collector.py` | Erzeugen und prüfen den festen Marker und die Ereignismetadaten auf Port 5003. |
| `offline_signer/sign.py`, `update_protocol.py` | Signieren und prüfen Profilname, Hash, Version und Ziel mit Ed25519. |
| `provision_tls.py`, `tls_transport.py` | Erzeugen die Labor-PKI und prüfen TLS-1.3-Verbindungen. Für den Config-Dienst ist zusätzlich der Zertifikatsfingerabdruck hinterlegt. |
| `demo_*.py`, `window_layout.py`, `window_layout.json` | Steuern Phasen, Ereignisprotokolle, Berichte, Mitschnitt und Konsolenfenster. |
| `tests/` | Prüft Protokolle, Profilwechsel, Fehlerfälle und den Start echter Prozesse. |

Die Updatepakete wählen zwischen den eingebauten Profilen `dummy` und `audit`. Der Client prüft Signatur, SHA-256 des Profilnamens, Ziel und steigende Versionsnummer. Der private Signierschlüssel liegt im separaten Offline-Verzeichnis. Für den Chat verwenden beide Clients eine gemeinsam erzeugte lokale Schlüsseldatei. Der Versuch setzt einen vertrauenswürdigen Rechner voraus und modelliert keinen Schlüsselaustausch zwischen unabhängigen Geräten. [Historische Einordnung](ENCROCHAT.md)

## Tests

Ein laufendes Labor zuerst mit **Q** beenden, damit die festen Ports frei sind.

```powershell
.\.venv\Scripts\python.exe -X utf8 -m unittest discover -s tests -v
```

Die Integrationsprüfungen erzeugen eigene temporäre Laborverzeichnisse. Der Mitschnitttest setzt TShark und den Npcap-Loopback-Adapter voraus. Die Fenstertests verwenden echte Windows-Konsolen.
