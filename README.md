# HTML Smuggling Detection v4.4.0

![Version](https://img.shields.io/badge/Version-4.4.0-green)
![Rspamd](https://img.shields.io/badge/Rspamd-Lua%20Local-blue)
![Security](https://img.shields.io/badge/Focus-Hardened%20Gate%20%26%20Entropy-red)


## Zweck

Dieses Modul erweitert Rspamd um eine praxisnahe Erkennung von HTML Smuggling, verschleierten JavaScript Payloads und ergänzenden Non HTML Vektoren. Die Version 4.3.7 baut auf der 4.3.6d auf und ergänzt zusätzliche Pfade für Attachments, Zertifikats Missbrauch und optionale Bild Indikatoren.

Das Ziel ist nicht eine forensische Vollanalyse jeder Datei, sondern eine robuste und performante Erkennung typischer Smuggling, Staging und Delivery Muster im Mail Gateway Betrieb.

## Abgedeckte Bereiche

Die Version v4.4.0 deckt insbesondere folgende Bereiche ab:

- HTML Smuggling mit JavaScript
- Base64 Decode Pfade
- Obfuskation und API Tarnung
- Uint8Array Payload Konstruktion
- externe Script Nachladungen
- CSS Exfiltration und CSS Code Execution Muster
- Geo Targeting und Evasion
- ClickFix ähnliche Lures
- WASM Staging
- Blockchain oder Web3 Staging
- PDF Active Content
- SVG mit aktivem Inhalt
- CHM, HTA, OneNote, LNK und Script Attachments
- Zertifikats und PKCS basierte Smuggling Kontexte
- optionale Bild Indikatoren als Info Only

## Nicht oder nur eingeschraenkt abgedeckt

Die Version v4.4.0 ist stark fuer Mail Gateway Erkennung optimiert. Folgende Bereiche sind nicht als vollstaendige Tiefenanalyse umgesetzt:

- echte Steganographie Analyse in Bildern
- vollstaendige PDF Objekt Rekonstruktion
- tiefes Office Parsing mit Makro Extraktion
- vollstaendige Zertifikats oder PKCS Validierung
- Headless Nachverfolgung externer URLs

Das ist bewusst so gehalten, damit das Modul produktiv auf Rspamd lauffaehig und wartbar bleibt.

## Hauptmodule

### appinstaller
Erkennt `ms-appinstaller` Kontexte und `.appinstaller` Hinweise.

### js_smuggling
Erkennt die typischen JavaScript Bausteine wie `atob`, `Blob`, `fetch`, `createObjectURL`, Split Payloads, Timer Verzoegerung und Decode Kontexte.

### obfuscation
Erkennt Tarnungsmuster wie `fromCharCode`, `_0x...` Variablen, hohe Entropie, Hex Arrays und aehnliche Konstrukte.

### decoded_payload
Versucht dekodierte Base64 Inhalte zu klassifizieren, zum Beispiel PE, ZIP, ISO, Script, HTML oder WASM.

### uint8array
Erkennt grosse `Uint8Array` Konstruktionen und prueft Header Hinweise auf PE, WASM, ZIP oder PDF.

### external_scripts
Erkennt externe Scripts im HTML und bewertet diese nur im passenden Smuggling Kontext.

### css_exfil
Erkennt missbraeuchliche CSS Konstrukte wie `@import`, `attr()` und grosse Base64 Bloecke in Style Bereichen.

### geo_targeting
Erkennt Geo APIs, Country Checks und Timezone basierte Selektionslogik.

### evasion
Erkennt Antisandbox und User Interaction Muster wie `navigator.webdriver`, Hardware Checks und erzwungene Maus oder Keyboard Interaktion.

### persistence
Erkennt `localStorage` und `sessionStorage` Nutzung im verdaechtigen Kontext.

### domain_rotation
Erkennt Redirect oder Domain Rotation Logik.

### clickfix
Erkennt typische ClickFix, Fake CAPTCHA und Run Dialog Lures.

### wasm_staging
Erkennt WebAssembly als Stage oder Payload Bruecke.

### blockchain_staging
Erkennt Web3 oder Ethers basierte Payload oder Remote Stage Muster.

### css_code_execution
Erkennt Konstrukte, bei denen CSS Inhalte spaeter durch JavaScript ausgelesen und missbraucht werden.

### attachment_vectors
Neu in v4.3.7. Erkennt Non HTML und Attachment Vektoren wie:
- PDF mit `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/RichMedia`
- SVG mit `<script>`, `onload`, `foreignObject`, `xlink:href`, `data:` Kontext
- CHM
- HTA
- OneNote
- LNK
- Script Dateien wie JS, VBS, PS1, BAT, CMD
- Office Macro Container wie DOCM, XLSM, PPTM

### certificate_smuggling
Neu in v4.3.7. Erkennt:
- inline PEM Bloecke
- PKCS Hinweise
- Zertifikats Dateitypen
- `data:` Kontexte mit Zertifikats oder PKCS Bezug
- grosse Base64 Bloecke im Zertifikats Kontext

### image_smuggling_info
Neu in v4.3.7. Standardmaessig deaktiviert und als Info Only gedacht. Erkennt nur einfache Indikatoren, keine echte Steganographie.

## Standardmaessige Modul Defaults

Die wichtigsten Defaults in v4.3.7 sind:

- `attachment_vectors = enabled`
- `certificate_smuggling = enabled`
- `image_smuggling_info = disabled`
- `push_abuse = info_only`

## Beispiel fuer eine lokale Konfiguration

Datei zum Beispiel unter:

`/etc/rspamd/local.d/html_smuggling.conf`

~~~lua
html_smuggling {
  enabled = true;
  debug = false;
  test_mode = false;

  log_score_threshold = 5.0;
  force_extended_log = true;
  force_extended_log_min_score = 5.0;
  log_simple_line = true;
  score_debug = false;
  enable_phase_debug = false;

  max_final_score = 15.0;
  soft_only_score_cap = 4.5;
  critical_boost = 0.0;
  min_score = 0.0;

  require_script_context_for_external = true;
  require_strong_gate_for_decode = true;

  modules {
    attachment_vectors {
      enabled = true;
      info_only = false;
    }
    certificate_smuggling {
      enabled = true;
      info_only = false;
    }
    image_smuggling_info {
      enabled = false;
      info_only = true;
    }
    rc4_detection {
      enabled = false;
      info_only = false;
    }
    wasm_binary_analysis {
      enabled = false;
      info_only = false;
    }
  }
}
~~~

## Installation

Die Lua Datei liegt produktiv typischerweise hier:

`/etc/rspamd/lua.local.d/html_smuggling.lua`

Danach sollte die Konfiguration geprueft werden:

~~~bash
rspamadm configtest
~~~

Anschliessend Rspamd neu laden oder neu starten:

~~~bash
systemctl restart rspamd
~~~

oder je nach Umgebung:

~~~bash
systemctl reload rspamd
~~~

## Empfohlene Inbetriebnahme

Fuer einen sauberen Rollout empfiehlt sich dieses Vorgehen:

1. Erst mit `test_mode = true` starten.
2. Logging fuer einige Tage beobachten.
3. False Positives gegen reale Newsletter, Marketing Mails und interne Systeme pruefen.
4. Danach in den produktiven Modus wechseln.
5. Gewichte und Caps nur gezielt anpassen, nicht pauschal.

## Ergebnis und Symbolik

Das Hauptsymbol ist:

`HTML_SMUGGLING_PAYLOAD`

Zusaetzlich werden Marker gesetzt, zum Beispiel:

- `HTML_SMUGGLING_MARKER_PDF_ACTIVE`
- `HTML_SMUGGLING_MARKER_SVG_ACTIVE`
- `HTML_SMUGGLING_MARKER_CERT_SMUGGLING`
- `HTML_SMUGGLING_MARKER_CLICKFIX`
- `HTML_SMUGGLING_MARKER_WASM_STAGING`
- `HTML_SMUGGLING_CLASS_CRITICAL`

Diese Marker helfen fuer Logging, Policies, Reports und spaetere Auswertungen.

## Wichtige Betriebs Hinweise

### 1. Performance
Das Modul ist auf produktive Laufzeit optimiert. Trotzdem sollte es auf echten Mail Daten beobachtet werden, speziell bei:
- grossen HTML Newslettern
- stark obfuskierten HTML Dateien
- vielen Attachments pro Nachricht

### 2. False Positives
Besonders im Blick behalten:
- Marketing und Newsletter Systeme
- SVG Dateien aus legitimen Design Tools
- PDF Dokumente mit aktiven Formular oder Medien Elementen
- technische Zertifikats Mails aus PKI oder Monitoring Umgebungen

### 3. Zertifikats Erkennung
Die Zertifikats Erkennung ist absichtlich konservativ. Eine legitime Zertifikats Mail kann Hinweise setzen. Entscheidend ist der Kontext mit Base64, Script, Blob, Fetch oder Data URI Missbrauch.

### 4. Bild Missbrauch
Das Modul `image_smuggling_info` ist nur ein Hinweis Modul. Es liefert keine verlaessliche Steganographie Erkennung.

## Was v4.3.7 verbessert

Im Vergleich zur 4.3.6d bringt v4.3.7 vor allem:

- bessere Abdeckung fuer Non HTML Angriffe
- mehr Sichtbarkeit auf smuggling relevante Attachments
- Erkennung von PDF Active Content
- Erkennung von aktivem SVG Missbrauch
- einfache Zertifikats und PKCS Kontexte
- optionale Bild Hinweise fuer spaetere Erweiterung

## Grenzen der Erkennung

Die Version 4.3.7 erreicht in der Praxis eine deutlich breitere Abdeckung als die 4.3.6d. Trotzdem ersetzt sie keine Sandbox und keine tiefgehende Dateianalyse. Fuer hoch entwickelte Kampagnen mit echter Bild Steganographie, komplexem PDF Objekt Missbrauch oder mehrstufigem Remote Staging bleiben zusaetzliche Kontrollen sinnvoll.

## Empfehlung fuer produktiven Betrieb

Fuer ein sauberes Setup im Gateway Betrieb ist diese Kombination sinnvoll:

- Rspamd mit v4.3.7 als fruehe Erkennung
- URL Reputation und URL Rewrite Kontrollen
- Attachment Policy fuer CHM, HTA, LNK, OneNote und Script Dateien
- AV oder Sandbox fuer tiefe Dateianalyse
- separates Monitoring fuer False Positives und neue Taktiken

## Kurzfazit

Die v4.3.7 ist eine saubere, produktionsnahe Weiterentwicklung der 4.3.6d. Sie bleibt wartbar, erweitert aber die Erkennung spuerbar in Richtung moderner Non HTML und Attachment Vektoren. Fuer einen produktiven Mail Gateway Betrieb ist das ein guter, ausgewogener Stand zwischen Abdeckung, Performance und Pflegeaufwand.
