# Historische Einordnung und Grenzen der EncroChat-Analogie

Diese Python-Simulation ist ein Lehrmodell. Sie rekonstruiert weder einen
EncroChat-Exploit noch dessen Software, Kryptoprotokoll oder vollständigen
Ermittlungsablauf.

## Öffentlich dokumentierte Merkmale

Der EuGH beschreibt im Urteil vom 30. April 2024, C-670/22, Randnummern 19–20,
modifizierte Telefone mit Ende-zu-Ende-verschlüsselter Kommunikation über einen
Server in Roubaix. Nach richterlich genehmigter Sicherung von Serverdaten wurde
dem dort wiedergegebenen Sachverhalt zufolge Trojaner-Software entwickelt und
im Frühjahr 2020 über den Server mittels eines vorgetäuschten Updates auf den
Telefonen installiert. Das belegt die gerichtliche Darstellung dieses
Verteilungswegs, aber keine vollständige technische Offenlegung des Exploits.
[Quelle: EuGH, C-670/22, Rn. 19–20](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62022CJ0670).

Die gemeinsame Mitteilung von Europol und Eurojust vom 2. Juli 2020 beschreibt
das Abfangen und Auswerten von Nachrichten und teilweise deren Mitlesen in
Echtzeit. Sie spricht von einer technischen Überwindung der bisherigen
Zugangsbarrieren, legt aber kein vollständiges kryptographisches Angriffsverfahren
offen. Daraus folgt insbesondere kein Nachweis eines mathematischen Bruchs von
AES-GCM oder TLS.
[Quelle: Europol/Eurojust, 2. Juli 2020](https://www.europol.europa.eu/media-press/newsroom/news/dismantling-of-encrypted-network-sends-shockwaves-through-organised-crime-groups-across-europe).

## Bezug zum Versuch

Die Analogie betrifft die Vertrauensentscheidung am Endpunkt. Im Labor ändert eine gültige Offline-Signatur, welches der beiden eingebauten Profile die Clients verwenden. Das Auditprofil meldet zu jeder Nachricht den festen Prüftext und die Nachrichten-ID. Der Versuch macht damit die Verhaltensänderung bei weiterhin aktiver Verschlüsselung messbar. Die Wahl von AES-GCM, Ed25519, Zertifikat-Pinning und Loopback-Diensten gehört zum Lehrmodell.

[Versuchsablauf und Messgrößen](README.md)
