# HTML Smuggling Test Suite -- Laboratory Cases

Diese Testsuite enthält 10 spezialisierte HTML-Dokumente, die entwickelt
wurden, um die Erkennungsrate und Granularität der **Rspamd HTML
Smuggling Detection Suite (v2.9-r1)** zu prüfen.

Jede Datei simuliert eine spezifische Technik, die von modernen
Malware-Stämmen wie Qakbot oder Emotet verwendet wird.

------------------------------------------------------------------------

## Test-Matrix & Abdeckung

  ------------------------------------------------------------------------
  Datei     Fokus-Technik                     Erwartete Symbole (v2.9-r1)
  --------- --------------------------------- ----------------------------
  test1     Blob Construction                 atob, blob, createObjectURL,
                                              dec_pe

  test2     JS Obfuscation                    atob, array_index_api,
                                              polymorphic_obfuscation

  test3     Drive-by / Meta                   iframe_src, data_uri,
                                              eval_call, atob

  test4     Magic Byte Sniffing               dec_pe, dec_zip, dec_pdf,
                                              sniff_decoded

  test5     Async Workers                     webworker_api, blob,
                                              uint8array

  test6     Windows Vectors                   ms_appinstaller_uri,
                                              dec_lnk,
                                              dec_xml_appinstaller

  test7     Anti-Analysis                     delayed_execution,
                                              high_entropy

  test8     DOM Manipulation                  fetch, event_handler_api,
                                              dec_bin

  test9     Stealth / Unicode                 css_exfiltration (atob ggf.
                                              getarnt)

  test10    Advanced / All-in-One             svg_onload, wasm_uint8array,
                                              combo_hard


------------------------------------------------------------------------

## 🔬 Detailbeschreibung der Testfälle

### 1. Malware Blob Assembly (test1)

Simuliert das Bauen einer `.exe` Datei im Arbeitsspeicher aus einem
Base64-String.\
Nutzt die klassischen APIs `Blob` und `createObjectURL`.

### 2. Polymorphic Obfuscation (test2)

Nutzt Variablen-Mapping und Zeichen-Rotation (CharCode), um Funktionen
wie `atob` zu verstecken.\
Prüft die Entropie-Erkennung des Skripts.

### 3. Iframe & Meta-Refresh (test3)

Testet die Erkennung von versteckten Iframes und automatischen
Weiterleitungen auf `data:` URIs, die häufig für fileless Smuggling
verwendet werden.

### 4. The "Röntgen" Test (test4)

Enthält mehrere Blobs mit validen Datei-Headern für PDF, EXE und ZIP.\
Verifiziert, ob die `sniff_decoded`-Logik den tatsächlichen Inhalt
korrekt erkennt.

### 5. Web Worker Smuggling (test5)

Verlagert den Smuggling-Prozess in einen Hintergrund-Thread (Worker).\
Dient der Umgehung einfacher Browser-Plugins und statischer Filter.

### 6. Windows-Specific Delivery (test6)

Kombiniert den Missbrauch des `ms-appinstaller:` Schemas mit dem
Download bösartiger `.lnk` Dateien.

### 7. Anti-Sandbox Engine (test7)

Prüft Bildschirmauflösung, CPU-Geschwindigkeit und installierte
Plugins.\
Das Skript detoniert nur bei vermuteter echter User-Umgebung.

### 8. Form Hijacking & Event-Listeners (test8)

Simuliert Credential-Diebstahl kombiniert mit einem automatischen
Download nach Button-Klick.

### 9. The Stealth Case (test9)

Nutzt Zero-Width Characters in Funktionsnamen und versteckt
Base64-Payloads in CSS-Custom-Properties.\
Ein Härtetest für die Roadmap v3.0.

### 10. Advanced Threat Payload (test10)

Der Endgegner-Testfall.\
Kombiniert SVG-Tags, WebWorker, String-Reversing und
AppInstaller-Vektoren gleichzeitig.\
Erwartet maximales Risk-Scoring.

------------------------------------------------------------------------

##  Ziel der Suite

-   Validierung der Symbol-Abdeckung
-   Prüfung von False-Negatives
-   Evaluierung der Entropie-Analyse
-   Verifikation der Decoding-Engine
-   Belastungstest für Kombinations-Logik

------------------------------------------------------------------------

**Version:** Laboratory Edition v1.0\
**Engine Target:** Rspamd HTML Smuggling Detection v2.9-r1
