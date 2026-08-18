# HTML Smuggling Detection v4.8.1 – Vollständiges Test-README 01–72

## 1. Zweck

Dieses README dokumentiert die vollständige HTML-/JavaScript-Regression-Suite für `html_smuggling.lua` **v4.8.1**.
Die Suite enthält **72 einzelne HTML-Testdateien**. Dieses Dokument beschreibt nicht nur die Soll-Reasons,
sondern auch den Zweck jedes Tests, den erwarteten Analysepfad und wie Abweichungen zu interpretieren sind.

Die Testdaten sind synthetisch. PE-, WASM-, ZIP-, PDF-, CHM-, GZIP-, XOR- und RC4-Inhalte dienen ausschliesslich
zur Prüfung von Magic-Headern, Rekonstruktionslogik und Klassifikationspfaden.


## v4.8.0 / v4.8.1 – Sandbox-Handoff und konfigurierbare Reason-Liste

v4.8.0 führte den score-unabhängigen virtuellen Marker
`HTML_SMUGGLING_SANDBOX_CANDIDATE` ein. v4.8.1 macht die auslösende Reason-Liste
optional per `sandbox_escalation.reasons` konfigurierbar.

Semantik:

```ucl
sandbox_escalation {
  enabled = true;
  log = true;
  reasons = [
    "xor_constant_payload",
    "rc4_constant_payload"
  ];
}
```

- `reasons` nicht gesetzt → eingebaute konservative Defaults.
- `reasons` gesetzt → exakter Replace der Defaults.
- `reasons = []` → gültig, aber kein Sandbox-Reason aktiv.
- unbekannte oder ungültige Reasons → Config-Validierungsfehler.
- bei ungültiger Config wird `HTML_SMUGGLING_PAYLOAD` nicht registriert.
- der Sandbox-Marker bleibt Score `0` und beeinflusst den normalen Detection-Score nicht.

Die Tests 01–70 verwenden das Default-Profil. Tests 71–72 verwenden
`sandbox_escalation_override_crypto.conf.example`.


## 2. Was diese Suite abdeckt

- klassisches HTML Smuggling (`atob`, Blob, ObjectURL, Fetch)
- Split- und Join-Rekonstruktion
- JavaScript-Obfuskation und Uint8Array
- rekursive Decode-Pfade
- PDF/SVG/CHM/HTA-Active-Content
- Zertifikats-/PKCS-Kontext
- CSS Exfiltration und CSS→JS-Ausführung
- Geo-Targeting, Evasion und Persistenz
- Domain Rotation, ClickFix, Push Abuse und Blockchain Staging
- Script-Prescan und globale Budgets
- strukturierte ZIP-Central-Directory-/Local-Header-Analyse
- XOR-/RC4-Rekonstruktion
- v4.7 DOM-Sinks, Dynamic Import, Worker-/ServiceWorker-Staging
- WebSocket-Portscan, JSFuck, Unicode- und Template-Literal-Obfuskation
- ZIP-Kommentare, ZIP-Entropie und begrenzte ZIP-in-ZIP-Rekursion
- SharedArrayBuffer-/Atomics-Timing
- v4.7.1 Regression des rekursiven JS-Scope-Bugs

## 3. Was weiterhin eine separate EML-/MIME-Suite benötigt

| Bereich | Warum HTML-Tests nicht genügen |
|---|---|
| echte Attachment-Dateinamen | Dateiname und MIME-Part-Metadaten existieren erst in einer echten Nachricht |
| OneNote/Office-Macro/LNK als echter Attachment-Pfad | ein Blob im HTML ist kein realer MIME-Part |
| Attachment-Magic-Mismatch | benötigt Dateiendung plus tatsächlichen Part-Inhalt |
| Image-Tail-Carving | muss mit echten PNG/JPEG/GIF/WebP-Mailparts geprüft werden |
| Newsletter-Header | `List-Id`, `List-Unsubscribe`, `Precedence`, `X-Mailer` brauchen Mail-Header |
| Trusted Sender/Domain Maps | benötigt reale Rspamd-Task-/Map-Konfiguration |

## 4. Interpretation der Sollwerte

`ExpectedDetection` beschreibt, ob der Test grundsätzlich positiv sein soll. `ExpectedCoreReasons` sind die
zentralen Reasons des Tests; zusätzliche Reasons sind erlaubt, solange sie fachlich plausibel sind.
`ExpectedInfoReasons` enthält bewusst nicht-scorebildende oder schwache Budget-/Anomaliehinweise.

Die Score-Spalte ist **kein exakter Unit-Test-Wert**, sondern ein realistischer Bereich. Der Lua-Code besitzt
einen internen Score-Cap; zusätzlich kann die Rspamd-Gruppe den sichtbar resultierenden Score begrenzen.

## 5. Empfohlener Ablauf

1. `rspamadm configtest` ausführen.
2. Modul zunächst in `test_mode` bzw. einer isolierten Testinstanz laden.
3. Negativtests 36 und 37 zuerst ausführen.
4. Tests 01–15 als Kernregression prüfen.
5. Tests 16–40 für erweiterte Module prüfen.
6. Tests 41–56 als v4.6-Regressionsblock prüfen.
7. Tests 57–68 als v4.7-Regressionsblock prüfen.
8. Test 69 immer bei Änderungen am rekursiven Decode-/JS-Pfad ausführen.
9. Neben Score und Reasons auch `ctx.errors` bzw. `HTML_SMUGGLING_SCRIPT_ERROR` beobachten.

---

# 6. Detaillierte Tests 01–69

## Test 01 – Klassischer HTML-Smuggling-Basispfad

**Datei:** `test01_basic_pe_smuggling.html`  
**Kategorie:** `JS_SMUGGLING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `atob,blob,createObjectURL,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Basis: atob plus Blob plus createObjectURL plus PE

### Testaufbau

Der Test enthält eine Base64-kodierte synthetische PE-Payload. JavaScript dekodiert sie mit `atob()`, erzeugt einen `Blob` und anschliessend eine Object-URL.

### Was geprüft wird

Der Test verifiziert gleichzeitig die JS-Smuggling-Heuristik und die Payload-Klassifikation nach dem Decode. Ein Ausfall von `dec_pe` bei vorhandenen JS-Reasons deutet auf ein Problem im Decode-/Sniff-Pfad hin.

### Prüfschritte

1. Datei `test01_basic_pe_smuggling.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `atob,blob,createObjectURL,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 02 – Fragmentierte Payload-Rekonstruktion

**Datei:** `test02_split_payload_pe_fixed.html`  
**Kategorie:** `JS_SMUGGLING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `split_payload,atob,blob,createObjectURL,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Korrigierter Split Payload mit mindestens sechs Fragmenten

### Testaufbau

Die Base64-Payload wird auf mindestens sechs Variablen verteilt und erst vor `atob()` zusammengesetzt.

### Was geprüft wird

Wichtig ist insbesondere `split_payload`. Fehlt nur dieser Reason, funktioniert zwar der Decode, aber die Split-Payload-Erkennung ist regressiert.

### Prüfschritte

1. Datei `test02_split_payload_pe_fixed.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `split_payload,atob,blob,createObjectURL,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 03 – Array-Join-Rekonstruktion

**Datei:** `test03_array_join_pe.html`  
**Kategorie:** `JS_SMUGGLING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `atob,blob,createObjectURL,b64_joined_parts,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Array.join Konstruktion mit PE Payload

### Testaufbau

Mehrere Base64-Fragmente liegen in einem Array und werden über `.join('')` verbunden.

### Was geprüft wird

Damit wird der `b64_joined_parts`-/Join-Pfad geprüft. Der Test soll nicht nur `atob`, sondern auch die Rekonstruktion der verteilten Daten erkennen.

### Prüfschritte

1. Datei `test03_array_join_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `atob,blob,createObjectURL,b64_joined_parts,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 04 – Obfuskierte API-Namen

**Datei:** `test04_obfuscated_pe.html`  
**Kategorie:** `OBFUSCATION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `atob_obfuscated or obfus_api,blob,createObjectURL,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Obfuskierter Zugriff ueber Array Indizes und Konstruktoren

### Testaufbau

API-Namen wie `atob`, `Blob` und `createObjectURL` werden indirekt über Array-Indizes verwendet.

### Was geprüft wird

Der Test prüft, ob Obfuskation nicht dazu führt, dass der eigentliche Smuggling-Pfad verloren geht. Erwartet wird mindestens ein Obfuskationsreason plus die PE-Klassifikation.

### Prüfschritte

1. Datei `test04_obfuscated_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `atob_obfuscated or obfus_api,blob,createObjectURL,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 05 – WebAssembly-Staging

**Datei:** `test05_wasm_smuggling.html`  
**Kategorie:** `WASM_STAGING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `fetch,webassembly or wasm_fetch_stage`  
**ExpectedInfoReasons:** `keine`

### Ziel

WASM Modul ueber fetch und WebAssembly.instantiate

### Testaufbau

Eine synthetische WASM-Payload wird aus Base64 dekodiert und über Blob/Fetch an `WebAssembly.instantiate()` weitergereicht.

### Was geprüft wird

Damit werden WASM-API-Erkennung und Staging-Kontext geprüft. Ein Fehlen des WASM-Reasons bei gleichzeitigem `fetch` wäre ein Problem im WASM-Modul.

### Prüfschritte

1. Datei `test05_wasm_smuggling.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `fetch,webassembly or wasm_fetch_stage` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 06 – Grosses dezimales Uint8Array

**Datei:** `test06_uint8array_pe_large.html`  
**Kategorie:** `UINT8ARRAY`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `uint8array_payload,pe_uint8array`  
**ExpectedInfoReasons:** `keine`

### Ziel

Korrigierter Uint8Array Test mit mehr als 1024 Bytewerten

### Testaufbau

Eine PE-artige Bytefolge wird als grosses `Uint8Array` mit mehr als 1024 Bytewerten aufgebaut.

### Was geprüft wird

Der Test deckt die Mindestgrösse `uint8array_large_min` ab und verifiziert `pe_uint8array`. Er ist gezielt gegen die frühere zu kleine Testvariante gebaut.

### Prüfschritte

1. Datei `test06_uint8array_pe_large.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `uint8array_payload,pe_uint8array` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 07 – Delayed Execution

**Datei:** `test07_delayed_execution_pe.html`  
**Kategorie:** `JS_SMUGGLING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `delayed_execution,timeout_b64_smuggling or timeout_b64_decode,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Verzoegertes Smuggling ueber setTimeout

### Testaufbau

Der Smuggling-Pfad liegt innerhalb von `setTimeout()`.

### Was geprüft wird

Geprüft wird, dass verzögerte Ausführung und Payload-Erkennung gemeinsam funktionieren. Ein Decode ohne `delayed_execution` zeigt eine Regression in der Kontextanalyse.

### Prüfschritte

1. Datei `test07_delayed_execution_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `delayed_execution,timeout_b64_smuggling or timeout_b64_decode,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 08 – Web Worker

**Datei:** `test08_webworker_pe.html`  
**Kategorie:** `WEBWORKER`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `webworker,atob,blob,createObjectURL,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Web Worker verarbeitet den Base64 Payload

### Testaufbau

Ein Worker verarbeitet die Payload und gibt sie an den Hauptkontext zurück, wo daraus ein Blob erzeugt wird.

### Was geprüft wird

Der Test prüft Worker-API-Erkennung sowie den Payload-Fluss. In v4.7.x ist dieser Test zusätzlich wichtig, weil Worker-Staging erweitert wurde.

### Prüfschritte

1. Datei `test08_webworker_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `webworker,atob,blob,createObjectURL,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 09 – Fetch-/Data-URI-Pfad

**Datei:** `test09_fetch_api_pe.html`  
**Kategorie:** `FETCH`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `fetch,data_uri or blob,createObjectURL or dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Fetch API plus Data URI Transport

### Testaufbau

Die Payload wird als Data-URI über `fetch()` geholt und danach in einen Blob überführt.

### Was geprüft wird

Der Test stellt sicher, dass moderne Fetch-basierte Varianten neben dem klassischen `atob()`-Pfad erkannt bleiben.

### Prüfschritte

1. Datei `test09_fetch_api_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `fetch,data_uri or blob,createObjectURL or dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 10 – Microsoft AppInstaller

**Datei:** `test10_appinstaller_schema.html`  
**Kategorie:** `APPINSTALLER`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `ms_appinstaller_uri or ms_appinstaller_word`  
**ExpectedInfoReasons:** `keine`

### Ziel

AppInstaller Schema und XML Kontext

### Testaufbau

Der HTML-/JavaScript-Inhalt enthält `ms-appinstaller:` und AppInstaller-XML.

### Was geprüft wird

Der Test soll den AppInstaller-Vektor erkennen, ohne dass dafür eine PE-Payload nötig ist. Er prüft damit einen eigenständigen kritischen Delivery-Pfad.

### Prüfschritte

1. Datei `test10_appinstaller_schema.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `ms_appinstaller_uri or ms_appinstaller_word` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 11 – PDF JavaScript

**Datei:** `test11_pdf_javascript_payload.html`  
**Kategorie:** `PDF_ACTIVE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `dec_pdf,att_pdf_javascript`  
**ExpectedInfoReasons:** `keine`

### Ziel

PDF mit JavaScript Action im Decode Pfad

### Testaufbau

Eine synthetische PDF-Struktur enthält `/JavaScript` bzw. `/OpenAction` und wird aus Base64 dekodiert.

### Was geprüft wird

Geprüft werden PDF-Klassifikation und Active-Content-Erkennung. `dec_pdf` allein reicht nicht; der aktive PDF-Reason muss ebenfalls erscheinen.

### Prüfschritte

1. Datei `test11_pdf_javascript_payload.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_pdf,att_pdf_javascript` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 12 – PDF Launch / EmbeddedFile

**Datei:** `test12_pdf_launch_payload.html`  
**Kategorie:** `PDF_ACTIVE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `dec_pdf,att_pdf_launch,att_pdf_embeddedfile`  
**ExpectedInfoReasons:** `keine`

### Ziel

PDF mit Launch und EmbeddedFile im Decode Pfad

### Testaufbau

Die PDF-Teststruktur enthält `/Launch` und `/EmbeddedFile`.

### Was geprüft wird

Dieser Test ist stärker als Test 11 und prüft mehrere aktive PDF-Konstrukte. Fehlt nur ein einzelner PDF-Subreason, sollte die konkrete PDF-Erkennung geprüft werden.

### Prüfschritte

1. Datei `test12_pdf_launch_payload.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_pdf,att_pdf_launch,att_pdf_embeddedfile` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 13 – Aktives SVG

**Datei:** `test13_svg_active_content.html`  
**Kategorie:** `SVG_ACTIVE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `att_svg_script,att_svg_event_handler,att_svg_foreignobject,att_svg_data_uri,att_svg_smuggling_context`  
**ExpectedInfoReasons:** `keine`

### Ziel

Aktives SVG in eingebetteter object data URI Form

### Testaufbau

Ein eingebettetes SVG enthält `<script>`, Event-Handler, `foreignObject` und eine Data-URI.

### Was geprüft wird

Der Test prüft mehrere SVG-Active-Content-Indikatoren gemeinsam und verhindert Regressionen in der SVG-spezifischen Analyse.

### Prüfschritte

1. Datei `test13_svg_active_content.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `att_svg_script,att_svg_event_handler,att_svg_foreignobject,att_svg_data_uri,att_svg_smuggling_context` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 14 – CHM Decode

**Datei:** `test14_chm_payload.html`  
**Kategorie:** `ATTACHMENT_VECTOR_DECODE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `att_chm_attachment or CHM decode indicator`  
**ExpectedInfoReasons:** `keine`

### Ziel

CHM Payload ueber Base64 und Blob

### Testaufbau

Eine synthetische CHM-Magic-Struktur wird über Base64 in den Decode-Pfad gebracht.

### Was geprüft wird

Der Test prüft die Container-/Attachment-Klassifikation für CHM im HTML-Payload-Pfad.

### Prüfschritte

1. Datei `test14_chm_payload.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `att_chm_attachment or CHM decode indicator` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 15 – HTA Decode

**Datei:** `test15_hta_payload.html`  
**Kategorie:** `ATTACHMENT_VECTOR_DECODE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `att_hta_attachment or dec_script`  
**ExpectedInfoReasons:** `keine`

### Ziel

HTA Payload ueber Base64 und Blob

### Testaufbau

HTA-artiger Script-Inhalt wird als Base64-Payload in einen Blob überführt.

### Was geprüft wird

Geprüft wird, ob HTA/Script als harter Script-Pfad klassifiziert wird.

### Prüfschritte

1. Datei `test15_hta_payload.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `att_hta_attachment or dec_script` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 16 – Inline PEM

**Datei:** `test16_certificate_inline_pem.html`  
**Kategorie:** `CERT_SMUGGLING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-5`  
**ExpectedCoreReasons:** `cert_inline_pem or cert_base64_block`  
**ExpectedInfoReasons:** `keine`

### Ziel

Inline PEM Zertifikat ohne starken Smuggling Kontext

### Testaufbau

Ein PEM-Zertifikatsblock steht direkt im HTML.

### Was geprüft wird

Dieser Test ist absichtlich schwächer und dient der Basiserkennung von Zertifikatsmaterial. Der Score darf deutlich unter PE-/Script-Payloads liegen.

### Prüfschritte

1. Datei `test16_certificate_inline_pem.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `cert_inline_pem or cert_base64_block` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 17 – Inline PKCS7

**Datei:** `test17_certificate_pkcs7_inline.html`  
**Kategorie:** `CERT_SMUGGLING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-5`  
**ExpectedCoreReasons:** `cert_inline_pkcs or cert_base64_block`  
**ExpectedInfoReasons:** `keine`

### Ziel

Inline PKCS7 Block ohne starken Smuggling Kontext

### Testaufbau

Ein PKCS7-artiger Block wird direkt eingebettet.

### Was geprüft wird

Der Test prüft die PKCS-Erkennung getrennt vom starken Smuggling-Kontext.

### Prüfschritte

1. Datei `test17_certificate_pkcs7_inline.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `cert_inline_pkcs or cert_base64_block` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 18 – Zertifikat plus Smuggling-Kontext

**Datei:** `test18_certificate_smuggling_context.html`  
**Kategorie:** `CERT_SMUGGLING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `cert_inline_pem or cert_base64_block plus Smuggling Kontext`  
**ExpectedInfoReasons:** `keine`

### Ziel

Zertifikatsblock zusammen mit Smuggling Kontext

### Testaufbau

Ein Zertifikatsblock wird mit einem klassischen Base64-/Blob-Smuggling-Pfad kombiniert.

### Was geprüft wird

Dieser Test prüft, dass die FP-arme Zertifikatslogik bei vorhandenem starken Kontext höher gewichtet bzw. sicher erkannt wird.

### Prüfschritte

1. Datei `test18_certificate_smuggling_context.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `cert_inline_pem or cert_base64_block plus Smuggling Kontext` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 19 – CSS Code Execution

**Datei:** `test19_css_code_execution.html`  
**Kategorie:** `CSS_CODE_EXEC`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `css_before_after_content,css_hidden_code_string,css_function_bridge,css_code_execution`  
**ExpectedInfoReasons:** `keine`

### Ziel

CSS Inhalte werden spaeter als Code missbraucht

### Testaufbau

CSS `content:` speichert codeähnliche Daten, die über JavaScript gelesen und ausgeführt werden.

### Was geprüft wird

Geprüft werden die Brücke CSS → JavaScript sowie `css_hidden_code_string` und `css_code_execution`.

### Prüfschritte

1. Datei `test19_css_code_execution.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `css_before_after_content,css_hidden_code_string,css_function_bridge,css_code_execution` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 20 – ComputedStyle Execution

**Datei:** `test20_css_computedstyle_exec.html`  
**Kategorie:** `CSS_CODE_EXEC`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `css_computedstyle_exec,css_function_bridge`  
**ExpectedInfoReasons:** `keine`

### Ziel

getComputedStyle liest versteckten Inhalt aus

### Testaufbau

JavaScript liest CSS-Inhalt via `getComputedStyle()` aus und führt ihn weiter.

### Was geprüft wird

Der Test deckt gezielt `css_computedstyle_exec` und die Function-/Eval-Brücke ab.

### Prüfschritte

1. Datei `test20_css_computedstyle_exec.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `css_computedstyle_exec,css_function_bridge` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 21 – Externe Scripts im Smuggling-Kontext

**Datei:** `test21_external_scripts_positive.html`  
**Kategorie:** `EXTERNAL_SCRIPTS`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `atob,external_scripts`  
**ExpectedInfoReasons:** `keine`

### Ziel

Externes Script im vorhandenen Smuggling Kontext

### Testaufbau

Ein externes Script ist mit einem vorhandenen Smuggling-Indikator kombiniert.

### Was geprüft wird

Der Test prüft das Context-Gate für `external_scripts`: externe Scripts alleine sollen nicht unnötig hoch gewertet werden.

### Prüfschritte

1. Datei `test21_external_scripts_positive.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `atob,external_scripts` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 22 – CSS Attribute Exfiltration

**Datei:** `test22_css_exfil_attr.html`  
**Kategorie:** `CSS_EXFIL`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `css_attr_exfil,css_exfiltration`  
**ExpectedInfoReasons:** `keine`

### Ziel

CSS attr Exfiltration ueber background url

### Testaufbau

CSS verwendet `attr(...)` innerhalb einer externen URL.

### Was geprüft wird

Geprüft werden `css_attr_exfil` und `css_exfiltration`. Der Test ist bewusst kein klassischer JS-Smuggling-Fall.

### Prüfschritte

1. Datei `test22_css_exfil_attr.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `css_attr_exfil,css_exfiltration` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 23 – Externer CSS Import

**Datei:** `test23_css_import_external.html`  
**Kategorie:** `CSS_EXFIL`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `0-3`  
**ExpectedCoreReasons:** `css_import_external`  
**ExpectedInfoReasons:** `keine`

### Ziel

Externer CSS Import

### Testaufbau

`@import url(https://...)` wird verwendet.

### Was geprüft wird

Dies ist ein Soft-/Info-orientierter Test. Er stellt sicher, dass externe CSS-Imports weiterhin erkannt werden, ohne sie automatisch als kritisch einzustufen.

### Prüfschritte

1. Datei `test23_css_import_external.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `css_import_external` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 24 – Geo-Targeting API

**Datei:** `test24_geo_targeting_api.html`  
**Kategorie:** `GEO_TARGETING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `geo_targeting_api,geo_location_api`  
**ExpectedInfoReasons:** `keine`

### Ziel

Geo API und Geolocation in einem Script

### Testaufbau

Der Code verwendet einen IP-Geolocation-Dienst und Browser-Geolocation.

### Was geprüft wird

Der Test prüft, dass geografische Zielauswahl als verdächtiger Kontext erkannt wird.

### Prüfschritte

1. Datei `test24_geo_targeting_api.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `geo_targeting_api,geo_location_api` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 25 – Timezone Targeting

**Datei:** `test25_timezone_targeting.html`  
**Kategorie:** `GEO_TARGETING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `timezone_targeting`  
**ExpectedInfoReasons:** `keine`

### Ziel

Timezone basierte Selektionslogik

### Testaufbau

Der Code verwendet `Intl.DateTimeFormat().resolvedOptions().timeZone` bzw. Zeitzonenlogik.

### Was geprüft wird

Damit wird ein alternativer Geo-/Targeting-Pfad ohne externe IP-API getestet.

### Prüfschritte

1. Datei `test25_timezone_targeting.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `timezone_targeting` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 26 – WebDriver Evasion

**Datei:** `test26_evasion_webdriver.html`  
**Kategorie:** `EVASION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `antisandbox_webdriver`  
**ExpectedInfoReasons:** `keine`

### Ziel

Antisandbox ueber navigator.webdriver

### Testaufbau

`navigator.webdriver` wird geprüft.

### Was geprüft wird

Der Test soll den klassischen Anti-Automation-/Sandbox-Indikator erkennen.

### Prüfschritte

1. Datei `test26_evasion_webdriver.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `antisandbox_webdriver` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 27 – Hardware Evasion

**Datei:** `test27_evasion_hardware_check.html`  
**Kategorie:** `EVASION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `hardware_check_evasion`  
**ExpectedInfoReasons:** `keine`

### Ziel

Hardware Checks fuer kleine oder virtuelle Systeme

### Testaufbau

Der Code prüft CPU-Kerne, Gerätespeicher und Bildschirmgrösse.

### Was geprüft wird

Geprüft wird die heuristische Erkennung kleiner/virtueller Umgebungen.

### Prüfschritte

1. Datei `test27_evasion_hardware_check.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `hardware_check_evasion` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 28 – LocalStorage Persistence

**Datei:** `test28_persistence_localstorage.html`  
**Kategorie:** `PERSISTENCE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `localstorage_persistence`  
**ExpectedInfoReasons:** `keine`

### Ziel

LocalStorage Speicherung und Wiederverwendung

### Testaufbau

Payload-/Stage-Zustand wird in `localStorage` geschrieben und gelesen.

### Was geprüft wird

Der Test prüft clientseitige Persistenzindikatoren.

### Prüfschritte

1. Datei `test28_persistence_localstorage.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `localstorage_persistence` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 29 – SessionStorage Persistence

**Datei:** `test29_persistence_sessionstorage.html`  
**Kategorie:** `PERSISTENCE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `sessionstorage_persistence`  
**ExpectedInfoReasons:** `keine`

### Ziel

SessionStorage Persistenz

### Testaufbau

Stage-Zustand wird in `sessionStorage` gespeichert.

### Was geprüft wird

Der Test ergänzt LocalStorage um die zweite unterstützte Storage-Variante.

### Prüfschritte

1. Datei `test29_persistence_sessionstorage.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `sessionstorage_persistence` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 30 – Domain Rotation

**Datei:** `test30_domain_rotation.html`  
**Kategorie:** `DOMAIN_ROTATION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `domain_rotation`  
**ExpectedInfoReasons:** `keine`

### Ziel

Drei Domains und Redirect Logik

### Testaufbau

Mehrere unterschiedliche Domains werden vorbereitet und für Redirects verwendet.

### Was geprüft wird

Geprüft wird, ob der Rotationskontext erkannt wird.

### Prüfschritte

1. Datei `test30_domain_rotation.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `domain_rotation` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 31 – Computed Redirect

**Datei:** `test31_computed_redirect.html`  
**Kategorie:** `DOMAIN_ROTATION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `computed_redirect`  
**ExpectedInfoReasons:** `keine`

### Ziel

Redirect Ziel wird dynamisch zusammengesetzt

### Testaufbau

Das Redirect-Ziel wird aus mehreren Stringteilen zusammengesetzt.

### Was geprüft wird

Der Test deckt berechnete Redirects ab, auch wenn die komplette URL nicht als Literal vorliegt.

### Prüfschritte

1. Datei `test31_computed_redirect.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `computed_redirect` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 32 – ClickFix / Run Dialog

**Datei:** `test32_clickfix_run_dialog.html`  
**Kategorie:** `CLICKFIX`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `run_dialog_lure,powershell_lure or clickfix_lure`  
**ExpectedInfoReasons:** `keine`

### Ziel

Run Dialog und PowerShell Lure

### Testaufbau

Der Inhalt fordert zum Öffnen des Windows-Run-Dialogs und zur PowerShell-Nutzung auf.

### Was geprüft wird

Der Test prüft Social-Engineering-/ClickFix-Lures, nicht nur technische Payload-Muster.

### Prüfschritte

1. Datei `test32_clickfix_run_dialog.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `run_dialog_lure,powershell_lure or clickfix_lure` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 33 – Fake CAPTCHA / Clipboard

**Datei:** `test33_fake_captcha_clipboard.html`  
**Kategorie:** `CLICKFIX`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `fake_captcha_lure,clipboard_exec_lure,clickfix_lure`  
**ExpectedInfoReasons:** `keine`

### Ziel

Fake CAPTCHA mit Clipboard und Exec Kontext

### Testaufbau

Ein Fake-CAPTCHA fordert zum Kopieren/Ausführen eines Befehls auf und nutzt Clipboard APIs.

### Was geprüft wird

Geprüft werden Fake-CAPTCHA-, Clipboard- und ClickFix-Kontext gemeinsam.

### Prüfschritte

1. Datei `test33_fake_captcha_clipboard.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `fake_captcha_lure,clipboard_exec_lure,clickfix_lure` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 34 – Push Abuse

**Datei:** `test34_push_abuse.html`  
**Kategorie:** `PUSH_ABUSE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `0-3`  
**ExpectedCoreReasons:** `push_permission_request,push_serviceworker_combo,push_notification_flow`  
**ExpectedInfoReasons:** `keine`

### Ziel

Notification Permission plus Service Worker und PushManager

### Testaufbau

`Notification.requestPermission()`, Service Worker und `PushManager` werden kombiniert.

### Was geprüft wird

Der Test ist standardmässig eher Info-orientiert, soll aber zuverlässig die Push-Abuse-Reasons erzeugen.

### Prüfschritte

1. Datei `test34_push_abuse.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `push_permission_request,push_serviceworker_combo,push_notification_flow` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 35 – Blockchain Staging

**Datei:** `test35_blockchain_staging.html`  
**Kategorie:** `BLOCKCHAIN_STAGING`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `web3_api_usage,ethers_contract_payload,blockchain_remote_stage or blockchain_staged_payload`  
**ExpectedInfoReasons:** `keine`

### Ziel

Web3 oder Ethers basierte Staging Logik

### Testaufbau

Web3-/Ethers-artige Konstrukte werden für Remote-Staging simuliert.

### Was geprüft wird

Geprüft wird die Erkennung blockchainbasierter Staging-Logik.

### Prüfschritte

1. Datei `test35_blockchain_staging.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `web3_api_usage,ethers_contract_payload,blockchain_remote_stage or blockchain_staged_payload` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 36 – Legitimer Negativtest

**Datei:** `test36_legitimate_negative.html`  
**Kategorie:** `NEGATIVE`  
**ExpectedDetection:** `NO`  
**ExpectedScore:** `0-1`  
**ExpectedCoreReasons:** `none`  
**ExpectedInfoReasons:** `keine`

### Ziel

Legitime einfache Seite ohne verdaechtige APIs

### Testaufbau

Eine einfache normale HTML-Seite enthält keine verdächtigen APIs oder Payloads.

### Was geprüft wird

Dieser Test ist besonders wichtig: ein positiver Fund ist ein potentielles False Positive und muss untersucht werden.

### Prüfschritte

1. Datei `test36_legitimate_negative.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = NO` fachlich erreicht wird.
3. Die Kern-Reasons `none` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Ein positiver Score oder ein starker Reason ist hier primär als **False-Positive-Regressionssignal** zu behandeln.
Zuerst sollte geprüft werden, welcher Reason ausgelöst wurde und ob ein neues allgemeines Pattern zu breit greift.

## Test 37 – Sichere externe Libraries

**Datei:** `test37_safe_external_negative.html`  
**Kategorie:** `NEGATIVE`  
**ExpectedDetection:** `NO`  
**ExpectedScore:** `0-2`  
**ExpectedCoreReasons:** `none`  
**ExpectedInfoReasons:** `keine`

### Ziel

Externe Scripts ohne Smuggling Kontext

### Testaufbau

Bekannte externe Bibliotheken werden eingebunden, aber ohne Smuggling-Kontext.

### Was geprüft wird

Der Test prüft das Context-Gate für externe Scripts. Ein `external_scripts`-Fund wäre hier unerwünscht.

### Prüfschritte

1. Datei `test37_safe_external_negative.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = NO` fachlich erreicht wird.
3. Die Kern-Reasons `none` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Ein positiver Score oder ein starker Reason ist hier primär als **False-Positive-Regressionssignal** zu behandeln.
Zuerst sollte geprüft werden, welcher Reason ausgelöst wurde und ob ein neues allgemeines Pattern zu breit greift.

## Test 38 – Newsletter-artiges HTML

**Datei:** `test38_html_keyword_newsletter_like.html`  
**Kategorie:** `NEWSLETTER_HTML_ONLY`  
**ExpectedDetection:** `LOW_OR_NONE`  
**ExpectedScore:** `0-2`  
**ExpectedCoreReasons:** `html_keyword newsletter heuristic only`  
**ExpectedInfoReasons:** `keine`

### Ziel

Nur HTML Keyword, kein echter Header Newsletter Test

### Testaufbau

Der HTML-Inhalt enthält Newsletter-Wörter, jedoch keine echten Mail-Header.

### Was geprüft wird

Der Test darf höchstens schwach anschlagen. Vollständige Newsletter-Logik gehört in die EML-Suite.

### Prüfschritte

1. Datei `test38_html_keyword_newsletter_like.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = LOW_OR_NONE` fachlich erreicht wird.
3. Die Kern-Reasons `html_keyword newsletter heuristic only` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 39 – All-in-One / Score-Cap

**Datei:** `test39_all_in_one_capped.html`  
**Kategorie:** `ALL_IN_ONE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 internal capped`  
**ExpectedCoreReasons:** `mehrere Klassen, intern gedeckelt`  
**ExpectedInfoReasons:** `keine`

### Ziel

Kombinierter Test fuer mehrere Module mit realistischer Cap Erwartung

### Testaufbau

Mehrere Erkennungsklassen werden in einer Datei kombiniert.

### Was geprüft wird

Der Test prüft vor allem, dass die interne Score-Begrenzung greift und Kombinationen nicht zu unrealistischen Scores führen.

### Prüfschritte

1. Datei `test39_all_in_one_capped.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `mehrere Klassen, intern gedeckelt` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 40 – Direktes SVG Data URI

**Datei:** `test40_svg_data_uri_pe_direct.html`  
**Kategorie:** `SVG_ACTIVE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `att_svg_data_uri,att_svg_script,att_svg_event_handler,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Direkter SVG Data URI Test fuer den eingebetteten SVG Extraktionspfad

### Testaufbau

Ein aktives SVG wird unmittelbar als Data-URI eingebettet.

### Was geprüft wird

Damit wird der SVG-Extraktionspfad unabhängig vom vorherigen SVG-Test abgesichert.

### Prüfschritte

1. Datei `test40_svg_data_uri_pe_direct.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `att_svg_data_uri,att_svg_script,att_svg_event_handler,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 41 – v4.6 Script-Prescan

**Datei:** `test41_v46_script_prescan_magic_late.html`  
**Kategorie:** `V46_SCRIPT_PRESCAN`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `script_prescan_payload,b64_magic_prefix,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

v4.6: billiger Vorscan erkennt Magic-Prefix in spaetem Script

### Testaufbau

Ein PE-Magic-Payload liegt in einem späteren Script-Block.

### Was geprüft wird

Der billige Prescan muss diesen Block priorisieren, obwohl nur eine begrenzte Zahl Scripts tief analysiert wird.

### Prüfschritte

1. Datei `test41_v46_script_prescan_magic_late.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `script_prescan_payload,b64_magic_prefix,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 42 – v4.6 Prescan-Budget

**Datei:** `test42_v46_script_prescan_budget.html`  
**Kategorie:** `V46_BUDGET`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `script_prescan_payload,dec_pe`  
**ExpectedInfoReasons:** `script_prescan_budget`

### Ziel

v4.6: kontrolliertes Prescan-Budget bei >64 Scripts

### Testaufbau

Mehr als 64 Inline-Scripts provozieren das Prescan-Limit.

### Was geprüft wird

Erwartet wird weiterhin die Erkennung des frühen Payloads plus `script_prescan_budget` als Info-Reason.

### Prüfschritte

1. Datei `test42_v46_script_prescan_budget.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `script_prescan_payload,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `script_prescan_budget` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 43 – Hexadezimales Uint8Array

**Datei:** `test43_v46_uint8array_hex_pe.html`  
**Kategorie:** `V46_UINT8ARRAY`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `uint8array_payload,pe_uint8array`  
**ExpectedInfoReasons:** `keine`

### Ziel

Hexadezimale Uint8Array Bytefolge mit PE Magic

### Testaufbau

PE-Bytes werden als `0xNN`-Werte in einem `Uint8Array` abgelegt.

### Was geprüft wird

Der Test ergänzt den dezimalen Uint8Array-Test und prüft die Hex-Erkennung.

### Prüfschritte

1. Datei `test43_v46_uint8array_hex_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `uint8array_payload,pe_uint8array` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 44 – Nested Base64

**Datei:** `test44_v46_nested_base64_pe.html`  
**Kategorie:** `V46_RECURSIVE_DECODE`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `nested_base64_payload,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Rekursiver Base64 Decode mit PE in zweiter Stufe

### Testaufbau

Die erste Base64-Stufe enthält erneut Base64, die schliesslich eine PE-Payload ergibt.

### Was geprüft wird

Geprüft wird die rekursive Decode-Tiefe und `nested_base64_payload`.

### Prüfschritte

1. Datei `test44_v46_nested_base64_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `nested_base64_payload,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 45 – GZIP Magic

**Datei:** `test45_v46_gzip_magic_payload.html`  
**Kategorie:** `V46_COMPRESSED`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `dec_compressed`  
**ExpectedInfoReasons:** `keine`

### Ziel

GZIP Magic Header fuer erweiterte Content Klassifikation

### Testaufbau

Eine dekodierte Payload beginnt mit einem GZIP-Magic-Header.

### Was geprüft wird

Der Test prüft `dec_compressed` und damit die erweiterte Content-Klassifikation.

### Prüfschritte

1. Datei `test45_v46_gzip_magic_payload.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_compressed` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 46 – ZIP Executable Member

**Datei:** `test46_v46_zip_executable_member.html`  
**Kategorie:** `V46_ZIP`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_executable_member`  
**ExpectedInfoReasons:** `keine`

### Ziel

ZIP mit payload.exe

### Testaufbau

Ein strukturell gültiges Test-ZIP enthält `payload.exe`.

### Was geprüft wird

Der Central-Directory-Parser und `zip_executable_member` werden gemeinsam geprüft.

### Prüfschritte

1. Datei `test46_v46_zip_executable_member.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip,zip_executable_member` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 47 – ZIP Script Member

**Datei:** `test47_v46_zip_script_member.html`  
**Kategorie:** `V46_ZIP`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_script_member`  
**ExpectedInfoReasons:** `keine`

### Ziel

ZIP mit stage.ps1

### Testaufbau

Das ZIP enthält `stage.ps1`.

### Was geprüft wird

Geprüft wird die Script-Dateiendungsanalyse im ZIP.

### Prüfschritte

1. Datei `test47_v46_zip_script_member.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip,zip_script_member` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 48 – ZIP Double Extension

**Datei:** `test48_v46_zip_double_extension.html`  
**Kategorie:** `V46_ZIP`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_executable_member,zip_double_extension`  
**ExpectedInfoReasons:** `keine`

### Ziel

ZIP mit invoice.pdf.exe

### Testaufbau

Das ZIP enthält `invoice.pdf.exe`.

### Was geprüft wird

Der Test prüft Cover-Extension plus gefährliche finale Extension.

### Prüfschritte

1. Datei `test48_v46_zip_double_extension.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip,zip_executable_member,zip_double_extension` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 49 – ZIP Path Traversal

**Datei:** `test49_v46_zip_path_traversal.html`  
**Kategorie:** `V46_ZIP`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_script_member,zip_path_traversal`  
**ExpectedInfoReasons:** `keine`

### Ziel

ZIP mit ../dropper.ps1

### Testaufbau

Ein Mitglied heisst `../dropper.ps1`.

### Was geprüft wird

Geprüft wird die Pfad-Traversal-Erkennung zusätzlich zum Script-Member.

### Prüfschritte

1. Datei `test49_v46_zip_path_traversal.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip,zip_script_member,zip_path_traversal` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 50 – Nested Archive Metadata

**Datei:** `test50_v46_zip_nested_archive.html`  
**Kategorie:** `V46_ZIP`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-12`  
**ExpectedCoreReasons:** `dec_zip,zip_nested_archive`  
**ExpectedInfoReasons:** `keine`

### Ziel

ZIP mit inner.zip

### Testaufbau

Das ZIP enthält `inner.zip`.

### Was geprüft wird

Der Test prüft zunächst die Erkennung verschachtelter Archive; die echte stored-ZIP-Rekursion wird später mit Test 67 geprüft.

### Prüfschritte

1. Datei `test50_v46_zip_nested_archive.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip,zip_nested_archive` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 51 – Hohe ZIP-Kompressionsrate

**Datei:** `test51_v46_zip_high_ratio.html`  
**Kategorie:** `V46_ZIP_INFO`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-10`  
**ExpectedCoreReasons:** `dec_zip`  
**ExpectedInfoReasons:** `zip_high_compression_ratio`

### Ziel

ZIP Metadaten mit hoher Kompressionsrate

### Testaufbau

ZIP-Metadaten deklarieren eine sehr grosse unkomprimierte Grösse bei kleiner komprimierter Grösse.

### Was geprüft wird

`zip_high_compression_ratio` ist bewusst ein Info-Reason und dient ZIP-Bomb-/Anomaliehinweisen.

### Prüfschritte

1. Datei `test51_v46_zip_high_ratio.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `zip_high_compression_ratio` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 52 – Stored PE in ZIP

**Datei:** `test52_v46_zip_stored_pe.html`  
**Kategorie:** `V46_ZIP_STORED`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_stored_payload,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Stored ZIP Mitglied enthaelt PE Payload

### Testaufbau

Ein unkomprimiertes ZIP-Mitglied enthält direkt eine PE-Testpayload.

### Was geprüft wird

Der Parser muss das Stored-Member extrahieren und über `analyze_decoded_blob` als PE weiteranalysieren.

### Prüfschritte

1. Datei `test52_v46_zip_stored_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip,zip_stored_payload,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 53 – ZIP Encryption Flag

**Datei:** `test53_v46_zip_encrypted_flag.html`  
**Kategorie:** `V46_ZIP`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-12`  
**ExpectedCoreReasons:** `dec_zip,zip_encrypted`  
**ExpectedInfoReasons:** `keine`

### Ziel

ZIP mit Encryption Flag

### Testaufbau

Das General-Purpose-Encryption-Flag ist gesetzt.

### Was geprüft wird

Geprüft wird `zip_encrypted` als Soft-/Container-Kontext.

### Prüfschritte

1. Datei `test53_v46_zip_encrypted_flag.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip,zip_encrypted` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 54 – Viele ZIP-Einträge

**Datei:** `test54_v46_zip_many_entries.html`  
**Kategorie:** `V46_ZIP_INFO`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-10`  
**ExpectedCoreReasons:** `dec_zip`  
**ExpectedInfoReasons:** `zip_many_entries`

### Ziel

ZIP mit 257 Eintraegen

### Testaufbau

Das Test-ZIP enthält 257 Einträge und überschreitet damit das Standardlimit 256.

### Was geprüft wird

Erwartet wird `zip_many_entries` als Info-Reason; die Analyse darf dabei nicht unkontrolliert weiterlaufen.

### Prüfschritte

1. Datei `test54_v46_zip_many_entries.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `zip_many_entries` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 55 – Konstante XOR-Rekonstruktion

**Datei:** `test55_v46_xor_constant_pe.html`  
**Kategorie:** `V46_CRYPTO`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `xor_constant_payload,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Konstantes XOR Bytearray wird als PE rekonstruiert

### Testaufbau

Eine PE-Payload ist mit einem konstanten XOR-Key geschützt und wird in JavaScript wiederhergestellt.

### Was geprüft wird

Der Test prüft die v4.6-Crypto-Rekonstruktion plus anschliessendes `dec_pe`.

### Prüfschritte

1. Datei `test55_v46_xor_constant_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `xor_constant_payload,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 56 – Konstante RC4-Rekonstruktion

**Datei:** `test56_v46_rc4_constant_pe.html`  
**Kategorie:** `V46_CRYPTO`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `rc4_constant_payload,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Konstantes RC4 Bytearray wird als PE rekonstruiert

### Testaufbau

Eine PE-Payload ist mit einem festen RC4-Key verschlüsselt und im Script als Bytearray vorhanden.

### Was geprüft wird

Geprüft werden RC4-Rekonstruktion und Payload-Klassifikation.

### Prüfschritte

1. Datei `test56_v46_rc4_constant_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `rc4_constant_payload,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Wenn die JavaScript-/Obfuskations-Reasons vorhanden sind, aber `dec_pe` fehlt, liegt die Regression wahrscheinlich
im Rekonstruktions-, Base64-Decode- oder `sniff_decoded()`-Pfad. Fehlen bereits die JS-Reasons, ist früher im
Script-Scanner bzw. Prescan anzusetzen.

## Test 57 – v4.7 DOM Dynamic Sink

**Datei:** `test57_v47_dom_dynamic_sink.html`  
**Kategorie:** `V47_DOM`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `dom_dynamic_sink,atob`  
**ExpectedInfoReasons:** `keine`

### Ziel

DOM Sink innerHTML zusammen mit Base64/Payload-Kontext

### Testaufbau

Payload-/Script-Inhalt fliesst in einen dynamischen DOM-Sink wie `innerHTML` oder `insertAdjacentHTML`.

### Was geprüft wird

Der Test prüft `dom_dynamic_sink` nur im passenden Payload-/Exec-Kontext, damit normale DOM-Manipulation nicht pauschal bestraft wird.

### Prüfschritte

1. Datei `test57_v47_dom_dynamic_sink.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dom_dynamic_sink,atob` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 58 – v4.7 Dynamic Import Data

**Datei:** `test58_v47_dynamic_import_data.html`  
**Kategorie:** `V47_DYNAMIC_IMPORT`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `7-15 capped`  
**ExpectedCoreReasons:** `dynamic_import_data`  
**ExpectedInfoReasons:** `keine`

### Ziel

Dynamischer import() direkt aus einer data: JavaScript URL

### Testaufbau

`import()` lädt JavaScript aus einer `data:`-URL.

### Was geprüft wird

Dieser Pfad ist als harter Script-Indikator gedacht und muss `dynamic_import_data` erzeugen.

### Prüfschritte

1. Datei `test58_v47_dynamic_import_data.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dynamic_import_data` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 59 – v4.7 Worker Blob Reconstruction

**Datei:** `test59_v47_worker_blob_reconstruction.html`  
**Kategorie:** `V47_WORKER`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-10`  
**ExpectedCoreReasons:** `worker_blob_stage,worker_inline_script,webworker`  
**ExpectedInfoReasons:** `keine`

### Ziel

Worker wird aus statischem Blob-Script erzeugt; Worker-Code ist begrenzt rekonstruierbar

### Testaufbau

Ein Worker wird aus einem lokal erzeugten Blob-Script gestartet.

### Was geprüft wird

Geprüft werden `worker_blob_stage` und die begrenzte Rekonstruktion des statischen Worker-Scriptstrings.

### Prüfschritte

1. Datei `test59_v47_worker_blob_reconstruction.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `worker_blob_stage,worker_inline_script,webworker` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 60 – v4.7 ServiceWorker Broad Scope

**Datei:** `test60_v47_serviceworker_broad_scope.html`  
**Kategorie:** `V47_SERVICEWORKER`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `3-8`  
**ExpectedCoreReasons:** `serviceworker_register,serviceworker_broad_scope,serviceworker_api`  
**ExpectedInfoReasons:** `keine`

### Ziel

ServiceWorker Registrierung mit Root-Scope

### Testaufbau

`serviceWorker.register()` wird mit auffälligem Scope-/URL-Kontext verwendet.

### Was geprüft wird

Der Test prüft Registrierung plus Evasion-/Persistenzcharakter eines zu breiten Scopes.

### Prüfschritte

1. Datei `test60_v47_serviceworker_broad_scope.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `serviceworker_register,serviceworker_broad_scope,serviceworker_api` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 61 – v4.7 WebSocket Port Scan

**Datei:** `test61_v47_websocket_portscan.html`  
**Kategorie:** `V47_EVASION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `3-8`  
**ExpectedCoreReasons:** `websocket_portscan`  
**ExpectedInfoReasons:** `keine`

### Ziel

Mehrere WebSocket-Verbindungen auf verschiedene lokale Ports als Portscan-Heuristik

### Testaufbau

Mehrere WebSocket-Verbindungen bzw. Port-Schleifen simulieren Browser-Portscanning.

### Was geprüft wird

Geprüft wird die heuristische Erkennung mehrerer Ports/Targets, nicht jede einzelne WebSocket-Nutzung.

### Prüfschritte

1. Datei `test61_v47_websocket_portscan.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `websocket_portscan` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 62 – v4.7 JSFuck

**Datei:** `test62_v47_jsfuck_obfuscation.html`  
**Kategorie:** `V47_OBFUSCATION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `jsfuck_obfuscation`  
**ExpectedInfoReasons:** `keine`

### Ziel

JSFuck-typische Tokenkombinationen werden als Obfuskation erkannt

### Testaufbau

Typische JSFuck-Zeichen-/Arraykonstruktionen werden verwendet.

### Was geprüft wird

Der Test soll `jsfuck_obfuscation` setzen, ohne dass jede ungewöhnliche Array-Syntax als JSFuck gilt.

### Prüfschritte

1. Datei `test62_v47_jsfuck_obfuscation.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `jsfuck_obfuscation` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 63 – v4.7 Unicode Escape Payload

**Datei:** `test63_v47_unicode_escape_payload.html`  
**Kategorie:** `V47_OBFUSCATION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `3-8`  
**ExpectedCoreReasons:** `unicode_escape_payload,obfus_api`  
**ExpectedInfoReasons:** `keine`

### Ziel

Unicode-Escapes rekonstruieren einen verschleierten API-Namen

### Testaufbau

JavaScript-Schlüsselwörter/Payloadteile sind als `\uXXXX` bzw. Unicode-Escapes kodiert.

### Was geprüft wird

Geprüft wird die tatsächliche Escape-Rekonstruktion und nicht nur die Zählung von Escape-Sequenzen.

### Prüfschritte

1. Datei `test63_v47_unicode_escape_payload.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `unicode_escape_payload,obfus_api` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 64 – v4.7 Template Literal Obfuscation

**Datei:** `test64_v47_template_literal_obfuscation.html`  
**Kategorie:** `V47_OBFUSCATION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `template_literal_obfuscation,eval_call`  
**ExpectedInfoReasons:** `keine`

### Ziel

Template Literal mit ${...}-Konstruktion und Exec-Kontext

### Testaufbau

Template Literals mit `${...}` setzen codeähnliche Strings dynamisch zusammen.

### Was geprüft wird

Der Test prüft `template_literal_obfuscation` in Verbindung mit Exec-/Payload-Kontext.

### Prüfschritte

1. Datei `test64_v47_template_literal_obfuscation.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `template_literal_obfuscation,eval_call` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 65 – v4.7 ZIP Comment Payload

**Datei:** `test65_v47_zip_comment_payload.html`  
**Kategorie:** `V47_ZIP`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_comment_payload,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

ZIP Central-Directory-Kommentar enthaelt Base64-codierte synthetische PE-Payload

### Testaufbau

Der ZIP-Central-Directory-Kommentar enthält script- oder Base64-artigen Payload-Kontext.

### Was geprüft wird

Der Test prüft die neu ergänzte begrenzte Kommentaranalyse.

### Prüfschritte

1. Datei `test65_v47_zip_comment_payload.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip,zip_comment_payload,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 66 – v4.7 High Entropy Stored Member

**Datei:** `test66_v47_zip_high_entropy_stored.html`  
**Kategorie:** `V47_ZIP_INFO`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-10`  
**ExpectedCoreReasons:** `dec_zip`  
**ExpectedInfoReasons:** `zip_high_entropy_member`

### Ziel

Stored ZIP-Mitglied mit hoher Entropie setzt einen Info-Reason

### Testaufbau

Ein stored ZIP-Mitglied enthält hochentropische synthetische Daten.

### Was geprüft wird

Der Test erwartet `zip_high_entropy_member` nur als Info-Reason und soll nicht automatisch eine kritische Malwareklassifikation erzeugen.

### Prüfschritte

1. Datei `test66_v47_zip_high_entropy_stored.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `zip_high_entropy_member` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 67 – v4.7 Nested Stored ZIP

**Datei:** `test67_v47_nested_stored_zip_pe.html`  
**Kategorie:** `V47_ZIP_RECURSION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_nested_archive,zip_stored_payload,dec_pe`  
**ExpectedInfoReasons:** `keine`

### Ziel

Stored ZIP-in-ZIP wird unter Decode-/Container-Budget rekursiv bis zur PE-Payload analysiert

### Testaufbau

Ein unkomprimiertes ZIP enthält ein weiteres stored ZIP, das wiederum eine PE-Testpayload enthält.

### Was geprüft wird

Dieser Test prüft die begrenzte ZIP-in-ZIP-Rekursion unter Decode-/Container-Budgets.

### Prüfschritte

1. Datei `test67_v47_nested_stored_zip_pe.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_zip,zip_nested_archive,zip_stored_payload,dec_pe` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dec_zip`, liegt das Problem wahrscheinlich bereits vor der strukturierten ZIP-Analyse.
Ist `dec_zip` vorhanden, aber der ZIP-spezifische Reason fehlt, sollte `parse_zip_entries()` bzw.
`classify_zip_member()`/die v4.7-ZIP-Erweiterung geprüft werden.

## Test 68 – v4.7 SharedArrayBuffer Timing

**Datei:** `test68_v47_sharedarraybuffer_timing.html`  
**Kategorie:** `V47_EVASION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `3-8`  
**ExpectedCoreReasons:** `sharedarraybuffer_timing`  
**ExpectedInfoReasons:** `keine`

### Ziel

SharedArrayBuffer + Atomics + performance.now als Sidechannel/Evasion-Indikator

### Testaufbau

`SharedArrayBuffer`, `Atomics` und hochauflösende Zeitmessung werden kombiniert.

### Was geprüft wird

Der Test prüft einen Sidechannel-/Evasion-Indikator, nicht die tatsächliche Ausführung eines Spectre-Angriffs.

### Prüfschritte

1. Datei `test68_v47_sharedarraybuffer_timing.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `sharedarraybuffer_timing` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt der zentrale Reason, sollte zuerst geprüft werden, ob das zuständige Modul aktiviert ist und der Test den
entsprechenden Gate-/Kontextpfad erreicht. Zusätzliche plausible Reasons sind nicht automatisch ein Fehler.

## Test 69 – v4.7.1 Recursive Decoded JS Scope Regression

**Datei:** `test69_v471_recursive_decoded_js_scope_regression.html`  
**Kategorie:** `V471_RECURSIVE_JS_REGRESSION`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_js,dynamic_import_data`  
**ExpectedInfoReasons:** `keine`

### Ziel

Regression fuer Forward-Declaration: Base64-dekodiertes JavaScript muss den v4.7 Deep-Scan ohne Scope-Fehler erreichen

### Testaufbau

Ein Base64-Blob dekodiert zu JavaScript, das `import('data:...')` enthält. Dadurch muss der rekursive JS-Pfad bis `scan_v47_script_risk_module()` laufen.

### Was geprüft wird

Dieser Test wurde speziell für den Forward-Declaration-Bug ergänzt. Erwartet werden `dec_js` und `dynamic_import_data`; in einem Mock-Unittest sollte zusätzlich `#ctx.errors == 0` gelten.

### Prüfschritte

1. Datei `test69_v471_recursive_decoded_js_scope_regression.html` durch die Testinstanz von Rspamd schicken.
2. Prüfen, ob `ExpectedDetection = YES` fachlich erreicht wird.
3. Die Kern-Reasons `dec_js,dynamic_import_data` mit Log/Symbolausgabe vergleichen.
4. Info-Reasons `keine` separat betrachten; sie dürfen je nach Budget-/Parserpfad zusätzlich auftreten.
5. `HTML_SMUGGLING_SCRIPT_ERROR` bzw. interne Fehlerlisten dürfen bei einem regulären Positivtest nicht auftreten.

### Fehlerinterpretation

Fehlt `dynamic_import_data`, obwohl `dec_js` vorhanden ist, ist der dekodierte JavaScript-Inhalt zwar erkannt,
aber der v4.7-Risk-Scanner wurde im rekursiven Pfad nicht vollständig ausgeführt. Ein `nil value`/Script-Fehler
weist direkt auf eine erneute Scope-/Forward-Declaration-Regression hin.

---


## Test 70 – v4.8 Score-unabhängiger Sandbox Candidate

**Datei:** `test70_v48_sandbox_candidate_low_score.html`  
**Kategorie:** `V48_SANDBOX_HANDOFF`  
**SandboxConfigProfile:** `default`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `0-3`  
**ExpectedCoreReasons:** `antisandbox_webdriver`  
**ExpectedSandboxCandidate:** `YES`  
**ExpectedMarkers:** `HTML_SMUGGLING_SANDBOX_CANDIDATE`

### Ziel

Der Test verifiziert den zentralen v4.8-Vertrag: ein Evasion-Fund muss zur Sandbox
eskalieren können, obwohl sein normaler Detection-Score niedrig bleibt.

### Testaufbau

Der JavaScript-Code prüft `navigator.webdriver`, enthält aber absichtlich keinen
PE-, ZIP-, Base64- oder sonstigen Critical-Payload. Dadurch bleibt der Score klein.

### Was geprüft wird

1. `antisandbox_webdriver` muss erkannt werden.
2. `HTML_SMUGGLING_SANDBOX_CANDIDATE` muss gesetzt werden.
3. Die Entscheidung darf nicht von `final_score` oder `log_score_threshold` abhängen.
4. Bei aktiviertem Sandbox-Logging wird `HTML_SMUGGLING_SANDBOX_ESCALATION` erwartet.

### Fehlerinterpretation

Ist `antisandbox_webdriver` vorhanden, aber der Sandbox-Marker fehlt, ist die
score-unabhängige Handoff-Logik regressiert. Fehlt bereits der Reason, liegt der
Fehler im Evasion-Scanner und nicht im Handoff.

---

## Test 71 – v4.8.1 Config-Override nimmt XOR auf

**Datei:** `test71_v481_sandbox_override_xor.html`  
**Kategorie:** `V481_SANDBOX_REASON_OVERRIDE`  
**SandboxConfigProfile:** `override_crypto`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `xor_constant_payload,dec_pe`  
**ExpectedSandboxCandidate:** `YES`  
**ExpectedMarkers:** `HTML_SMUGGLING_SANDBOX_CANDIDATE`

### Benötigte Config

```ucl
sandbox_escalation {
  enabled = true;
  log = true;
  reasons = [
    "xor_constant_payload",
    "rc4_constant_payload"
  ];
}
```

### Ziel

`xor_constant_payload` gehört bewusst **nicht** zum eingebauten konservativen
Default. Durch den Config-Override muss dieser Reason trotzdem zum Sandbox-Handoff führen.

### Testaufbau

Der Test verwendet denselben synthetischen XOR→PE-Rekonstruktionspfad wie der
bestehende XOR-Test. Entscheidend ist nicht der hohe PE-Score, sondern dass
`sandbox_escalation_hits()` den konfigurierten Reason `xor_constant_payload` findet.

### Fehlerinterpretation

Ist `xor_constant_payload` vorhanden, aber `HTML_SMUGGLING_SANDBOX_CANDIDATE`
fehlt, wurde der Config-Override nicht korrekt in das effektive Reason-Set übernommen.

---

## Test 72 – v4.8.1 Override ersetzt Defaults

**Datei:** `test72_v481_sandbox_override_replaces_defaults.html`  
**Kategorie:** `V481_SANDBOX_REASON_REPLACE`  
**SandboxConfigProfile:** `override_crypto`  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `0-3`  
**ExpectedCoreReasons:** `antisandbox_webdriver`  
**ExpectedSandboxCandidate:** `NO`  
**ExpectedMarkers:** `keine`

### Ziel

Dieser Test beweist, dass `sandbox_escalation.reasons` ein **exakter Replace**
und keine additive Liste ist.

### Testaufbau

Unter dem Profil `override_crypto` sind nur `xor_constant_payload` und
`rc4_constant_payload` aktiv. `antisandbox_webdriver` ist zwar ein eingebauter
Default-Reason, wird durch den Override aber entfernt.

### Erwartung

`antisandbox_webdriver` wird weiterhin normal als Detection-Reason erkannt.
Der virtuelle Marker `HTML_SMUGGLING_SANDBOX_CANDIDATE` darf jedoch **nicht**
gesetzt werden.

### Fehlerinterpretation

Wird der Sandbox-Marker trotzdem gesetzt, wurden Default- und Config-Reasons
fälschlich zusammengeführt. Das wäre eine Regression der ausdrücklich gewählten
Replace-Semantik.


# 7. Besonders wichtige Regressionstests

| Test | Bedeutung |
|---:|---|
| 01 | klassischer HTML-Smuggling-/PE-Basispfad |
| 02 | Split-Payload-Rekonstruktion |
| 06 | grosses Uint8Array |
| 36–37 | False-Positive-Negativkontrollen |
| 39 | Score-Cap und Modul-Kombination |
| 41–42 | Script-Prescan und Budget |
| 44 | rekursives Base64 |
| 46–54 | strukturierter ZIP-Parser |
| 55–56 | XOR-/RC4-Rekonstruktion |
| 57–60 | DOM, Dynamic Import, Worker, ServiceWorker |
| 65–67 | ZIP-Kommentar, Entropie, Nested ZIP |
| 69 | v4.7.1 rekursiver JS-Scope-Bug |
| 70 | score-unabhängiger Sandbox-Handoff |
| 71 | v4.8.1 Reason-Override nimmt XOR auf |
| 72 | v4.8.1 Replace-Semantik entfernt Default-Reason |

# 8. v4.7.1 Scope-Bug – technische Regression

Der kritische Fix in v4.7.1 besteht aus einer echten Forward-Declaration:

```lua
local scan_v47_script_risk_module
```

und der späteren Zuweisung:

```lua
scan_v47_script_risk_module = function(ctx, script_raw)
```

Damit referenziert `scan_decoded_script_blob()` dasselbe Local-Closure. Test 69 ist der gezielte End-to-End-Test
für diesen Pfad.

Für einen zukünftigen Lua-Mock-Unittest sollte zusätzlich direkt geprüft werden:

```text
#ctx.errors == 0
ctx.reasons.dec_js == true
ctx.reasons.dynamic_import_data == true
```

# 9. Dateien der v4.7.1-r1 Suite

- `html_smuggling_v4.8.1.lua`
- `create_html_pattern_test_suite_v4_8_1_r1.ps1`
- `HTML_Smuggling_v4.8.1_Tests_01-72.zip`
- `test_manifest_01-72.csv`
- `test_manifest_01-72.json`
- `README.md` – dieses vollständige Test-README
- `README_html_smuggling_v4.7.1.md` – Modul-/Betriebsdokumentation

# 10. Abschluss

Die HTML-Suite 01–69 bildet die Regressionsebene für die Script-, Decode-, Container- und modernen v4.7.x-Pfade.
Für eine vollständige Mail-Security-Prüfung sollte sie gemeinsam mit einer separaten EML-/MIME-Suite verwendet werden.

# 11. Sandbox-Configprofile v4.8.1

Die Suite enthält vier Beispiele:

- `sandbox_escalation_default.conf.example` – `reasons` nicht gesetzt, eingebaute Defaults.
- `sandbox_escalation_override_crypto.conf.example` – exakter Override nur mit XOR/RC4; für Tests 71–72.
- `sandbox_escalation_override_extended.conf.example` – Defaults plus WASM-inline, Blockchain, XOR und RC4.
- `sandbox_escalation_empty.conf.example` – gültige leere Reason-Liste; kein Sandbox-Handoff.

Für produktive Änderungen sollte `rspamadm configtest` vor Reload/Restart verwendet werden.
Ein unbekannter Reason in `sandbox_escalation.reasons` muss v4.8.1 als ungültige Konfiguration ablehnen.
