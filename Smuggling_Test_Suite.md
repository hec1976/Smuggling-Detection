# HTML Smuggling Detection v4.6.0 – Detaillierte Test-Suite 01–56

## Überblick

Dieses Dokument beschreibt die komplette HTML-/Script-Regression-Test-Suite für
`html_smuggling.lua` **v4.6.0**.

Die Suite enthält **56 einzelne HTML-Testdateien** und deckt die wesentlichen
Erkennungspfade der aktuellen Implementierung ab:

- HTML Smuggling und Base64-Decoding
- Blob / `URL.createObjectURL()` / Fetch
- Split Payloads und Array-Join-Rekonstruktion
- JavaScript-Obfuskation
- `Uint8Array` in dezimaler und hexadezimaler Form
- rekursive Base64-Decodierung
- WASM- und AppInstaller-Staging
- PDF- und SVG-Active-Content
- CHM / HTA / Script-Payloads
- Zertifikats- und PKCS-Smuggling-Indikatoren
- CSS Exfiltration und CSS Code Execution
- Geo-Targeting und Anti-Sandbox/Evasion
- Local-/SessionStorage-Persistenz
- Domain Rotation und berechnete Redirects
- ClickFix / Fake CAPTCHA / Clipboard-Lures
- Push Abuse und Blockchain-Staging
- Script-Prescan und globale Ressourcenbudgets
- strukturierte ZIP-Analyse
- konstante XOR- und RC4-Payload-Rekonstruktion

## Dateien

Die vollständige Suite besteht aus:

- `test01_...html` bis `test56_...html`
- `test_manifest_01-56.csv`
- `test_manifest_01-56.json`
- `README.md`
- diesem detaillierten README

## Wichtiger Hinweis

Die eingebetteten PE-, WASM-, ZIP-, GZIP-, PDF-, CHM-, LNK- und Crypto-Payloads
sind **synthetische Testdaten**. Sie dienen ausschliesslich dazu, Magic-Header,
Rekonstruktions- und Klassifikationspfade der Erkennung zu prüfen.

Die HTML-Suite ersetzt **keine vollständige MIME-/EML-Test-Suite**. Funktionen,
die echte Mail-Part-Metadaten, Attachment-Dateinamen, Header oder Rspamd-Maps
benötigen, müssen separat mit EML-Dateien geprüft werden.

## Erwartungswerte

Jeder Test besitzt folgende Felder:

- **ExpectedDetection** – ob der Test grundsätzlich erkannt werden soll
- **ExpectedScore** – grober erwarteter Score-Bereich
- **ExpectedCoreReasons** – zentrale Reasons, die erwartet werden
- **ExpectedInfoReasons** – optionale reine Info-/Budget-Reasons

Die Score-Werte sind bewusst als Bereiche angegeben. Für Regression-Tests sind
die **Reasons und Marker wichtiger als ein exakt identischer numerischer Score**.

Typische Bereiche:

| Bereich | Bedeutung |
|---|---|
| `0-1` / `0-2` | Negativtest bzw. praktisch kein verdächtiges Signal |
| `0-3` | Info-/Soft-Signal |
| `2-6` | schwache bis mittlere Heuristik |
| `4-8` | deutlicher positiver Pfad |
| `6-10` / `6-12` | starker Container-/Staging-Pfad |
| `8-10 group capped` | starker Pfad mit externer Gruppenbegrenzung |
| `8-15 capped` | starker Script-/Container-Pfad |
| `10-15 capped` | kritischer Pfad oder mehrere starke Klassen |
| `10-15 internal capped` | kombinierter Test bis zum internen Maximum |

Der Lua-Code verwendet standardmässig `max_final_score = 15.0`. Eine zusätzliche
Rspamd-Gruppenbegrenzung kann den sichtbaren Endscore weiter begrenzen.

## Testgruppen

### Tests 01–05 – Grundlegendes HTML Smuggling und WASM

- `test01_basic_pe_smuggling.html` – Basis: atob plus Blob plus createObjectURL plus PE
- `test02_split_payload_pe_fixed.html` – Korrigierter Split Payload mit mindestens sechs Fragmenten
- `test03_array_join_pe.html` – Array.join Konstruktion mit PE Payload
- `test04_obfuscated_pe.html` – Obfuskierter Zugriff ueber Array Indizes und Konstruktoren
- `test05_wasm_smuggling.html` – WASM Modul ueber fetch und WebAssembly.instantiate

### Tests 06–10 – Uint8Array, Delayed Execution, Worker, Fetch und AppInstaller

- `test06_uint8array_pe_large.html` – Korrigierter Uint8Array Test mit mehr als 1024 Bytewerten
- `test07_delayed_execution_pe.html` – Verzoegertes Smuggling ueber setTimeout
- `test08_webworker_pe.html` – Web Worker verarbeitet den Base64 Payload
- `test09_fetch_api_pe.html` – Fetch API plus Data URI Transport
- `test10_appinstaller_schema.html` – AppInstaller Schema und XML Kontext

### Tests 11–15 – PDF, SVG, CHM und HTA

- `test11_pdf_javascript_payload.html` – PDF mit JavaScript Action im Decode Pfad
- `test12_pdf_launch_payload.html` – PDF mit Launch und EmbeddedFile im Decode Pfad
- `test13_svg_active_content.html` – Aktives SVG in eingebetteter object data URI Form
- `test14_chm_payload.html` – CHM Payload ueber Base64 und Blob
- `test15_hta_payload.html` – HTA Payload ueber Base64 und Blob

### Tests 16–20 – Zertifikate und CSS Code Execution

- `test16_certificate_inline_pem.html` – Inline PEM Zertifikat ohne starken Smuggling Kontext
- `test17_certificate_pkcs7_inline.html` – Inline PKCS7 Block ohne starken Smuggling Kontext
- `test18_certificate_smuggling_context.html` – Zertifikatsblock zusammen mit Smuggling Kontext
- `test19_css_code_execution.html` – CSS Inhalte werden spaeter als Code missbraucht
- `test20_css_computedstyle_exec.html` – getComputedStyle liest versteckten Inhalt aus

### Tests 21–25 – External Scripts, CSS Exfiltration und Geo Targeting

- `test21_external_scripts_positive.html` – Externes Script im vorhandenen Smuggling Kontext
- `test22_css_exfil_attr.html` – CSS attr Exfiltration ueber background url
- `test23_css_import_external.html` – Externer CSS Import
- `test24_geo_targeting_api.html` – Geo API und Geolocation in einem Script
- `test25_timezone_targeting.html` – Timezone basierte Selektionslogik

### Tests 26–30 – Evasion, Persistence und Domain Rotation

- `test26_evasion_webdriver.html` – Antisandbox ueber navigator.webdriver
- `test27_evasion_hardware_check.html` – Hardware Checks fuer kleine oder virtuelle Systeme
- `test28_persistence_localstorage.html` – LocalStorage Speicherung und Wiederverwendung
- `test29_persistence_sessionstorage.html` – SessionStorage Persistenz
- `test30_domain_rotation.html` – Drei Domains und Redirect Logik

### Tests 31–35 – Redirect, ClickFix, Push Abuse und Blockchain Staging

- `test31_computed_redirect.html` – Redirect Ziel wird dynamisch zusammengesetzt
- `test32_clickfix_run_dialog.html` – Run Dialog und PowerShell Lure
- `test33_fake_captcha_clipboard.html` – Fake CAPTCHA mit Clipboard und Exec Kontext
- `test34_push_abuse.html` – Notification Permission plus Service Worker und PushManager
- `test35_blockchain_staging.html` – Web3 oder Ethers basierte Staging Logik

### Tests 36–40 – Negative Tests, Newsletter, All-in-One und SVG Data URI

- `test36_legitimate_negative.html` – Legitime einfache Seite ohne verdaechtige APIs
- `test37_safe_external_negative.html` – Externe Scripts ohne Smuggling Kontext
- `test38_html_keyword_newsletter_like.html` – Nur HTML Keyword, kein echter Header Newsletter Test
- `test39_all_in_one_capped.html` – Kombinierter Test fuer mehrere Module mit realistischer Cap Erwartung
- `test40_svg_data_uri_pe_direct.html` – Direkter SVG Data URI Test fuer den eingebetteten SVG Extraktionspfad

### Tests 41–45 – Neue v4.6.0 Prescan-, Decode- und Content-Pfade

- `test41_v46_script_prescan_magic_late.html` – v4.6: billiger Vorscan erkennt Magic-Prefix in spaetem Script
- `test42_v46_script_prescan_budget.html` – v4.6: kontrolliertes Prescan-Budget bei >64 Scripts
- `test43_v46_uint8array_hex_pe.html` – Hexadezimale Uint8Array Bytefolge mit PE Magic
- `test44_v46_nested_base64_pe.html` – Rekursiver Base64 Decode mit PE in zweiter Stufe
- `test45_v46_gzip_magic_payload.html` – GZIP Magic Header fuer erweiterte Content Klassifikation

### Tests 46–54 – Neuer v4.6.0 ZIP-Parser

- `test46_v46_zip_executable_member.html` – ZIP mit payload.exe
- `test47_v46_zip_script_member.html` – ZIP mit stage.ps1
- `test48_v46_zip_double_extension.html` – ZIP mit invoice.pdf.exe
- `test49_v46_zip_path_traversal.html` – ZIP mit ../dropper.ps1
- `test50_v46_zip_nested_archive.html` – ZIP mit inner.zip
- `test51_v46_zip_high_ratio.html` – ZIP Metadaten mit hoher Kompressionsrate
- `test52_v46_zip_stored_pe.html` – Stored ZIP Mitglied enthaelt PE Payload
- `test53_v46_zip_encrypted_flag.html` – ZIP mit Encryption Flag
- `test54_v46_zip_many_entries.html` – ZIP mit 257 Eintraegen

### Tests 55–56 – Konstante XOR-/RC4-Rekonstruktion

- `test55_v46_xor_constant_pe.html` – Konstantes XOR Bytearray wird als PE rekonstruiert
- `test56_v46_rc4_constant_pe.html` – Konstantes RC4 Bytearray wird als PE rekonstruiert

---

# Detaillierte Beschreibung aller Tests

## Test 01 – `test01_basic_pe_smuggling.html`

**Kategorie:** `JS_SMUGGLING`  
**Beschreibung:** Basis: atob plus Blob plus createObjectURL plus PE  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `atob,blob,createObjectURL,dec_pe`  

Prüft den klassischen HTML-Smuggling-Pfad aus Base64 → `atob()` → Blob → `createObjectURL()` und anschliessender PE-Klassifikation.

## Test 02 – `test02_split_payload_pe_fixed.html`

**Kategorie:** `JS_SMUGGLING`  
**Beschreibung:** Korrigierter Split Payload mit mindestens sechs Fragmenten  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `split_payload,atob,blob,createObjectURL,dec_pe`  

Prüft die Rekonstruktion einer in mindestens sechs Fragmente zerlegten Base64-Payload und den `split_payload`-Pfad.

## Test 03 – `test03_array_join_pe.html`

**Kategorie:** `JS_SMUGGLING`  
**Beschreibung:** Array.join Konstruktion mit PE Payload  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `atob,blob,createObjectURL,b64_joined_parts,dec_pe`  

Prüft Base64-Fragmente, die über ein Array und `.join('')` wieder zusammengesetzt werden.

## Test 04 – `test04_obfuscated_pe.html`

**Kategorie:** `OBFUSCATION`  
**Beschreibung:** Obfuskierter Zugriff ueber Array Indizes und Konstruktoren  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `atob_obfuscated or obfus_api,blob,createObjectURL,dec_pe`  

Prüft verschleierte API-Namen und indirekte Zugriffe auf `atob`, `Blob` und `createObjectURL`.

## Test 05 – `test05_wasm_smuggling.html`

**Kategorie:** `WASM_STAGING`  
**Beschreibung:** WASM Modul ueber fetch und WebAssembly.instantiate  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `fetch,webassembly or wasm_fetch_stage`  

Prüft WASM-Staging über Base64, Blob, Fetch und `WebAssembly.instantiate()`.

## Test 06 – `test06_uint8array_pe_large.html`

**Kategorie:** `UINT8ARRAY`  
**Beschreibung:** Korrigierter Uint8Array Test mit mehr als 1024 Bytewerten  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `uint8array_payload,pe_uint8array`  

Prüft ein grosses dezimales `Uint8Array` mit PE-Magic und mehr als 1024 Bytewerten.

## Test 07 – `test07_delayed_execution_pe.html`

**Kategorie:** `JS_SMUGGLING`  
**Beschreibung:** Verzoegertes Smuggling ueber setTimeout  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `delayed_execution,timeout_b64_smuggling or timeout_b64_decode,dec_pe`  

Prüft verzögerte Ausführung über `setTimeout()` zusammen mit einem Base64-PE-Payload.

## Test 08 – `test08_webworker_pe.html`

**Kategorie:** `WEBWORKER`  
**Beschreibung:** Web Worker verarbeitet den Base64 Payload  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `webworker,atob,blob,createObjectURL,dec_pe`  

Prüft Payload-Verarbeitung innerhalb eines Web Workers und anschliessende Blob-Erzeugung.

## Test 09 – `test09_fetch_api_pe.html`

**Kategorie:** `FETCH`  
**Beschreibung:** Fetch API plus Data URI Transport  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `fetch,data_uri or blob,createObjectURL or dec_pe`  

Prüft `fetch()` auf einer Data-URI sowie den anschliessenden Blob-/ObjectURL-Pfad.

## Test 10 – `test10_appinstaller_schema.html`

**Kategorie:** `APPINSTALLER`  
**Beschreibung:** AppInstaller Schema und XML Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `ms_appinstaller_uri or ms_appinstaller_word`  

Prüft `ms-appinstaller:` und XML-AppInstaller-Kontext.

## Test 11 – `test11_pdf_javascript_payload.html`

**Kategorie:** `PDF_ACTIVE`  
**Beschreibung:** PDF mit JavaScript Action im Decode Pfad  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `dec_pdf,att_pdf_javascript`  

Prüft eine Base64-dekodierte PDF-Datei mit eingebettetem JavaScript bzw. `/OpenAction`.

## Test 12 – `test12_pdf_launch_payload.html`

**Kategorie:** `PDF_ACTIVE`  
**Beschreibung:** PDF mit Launch und EmbeddedFile im Decode Pfad  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `dec_pdf,att_pdf_launch,att_pdf_embeddedfile`  

Prüft PDF-Active-Content mit `/Launch` und `/EmbeddedFile`.

## Test 13 – `test13_svg_active_content.html`

**Kategorie:** `SVG_ACTIVE`  
**Beschreibung:** Aktives SVG in eingebetteter object data URI Form  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `att_svg_script,att_svg_event_handler,att_svg_foreignobject,att_svg_data_uri,att_svg_smuggling_context`  

Prüft aktives SVG mit Script, Event Handler, `foreignObject` und Data-URI-Smuggling.

## Test 14 – `test14_chm_payload.html`

**Kategorie:** `ATTACHMENT_VECTOR_DECODE`  
**Beschreibung:** CHM Payload ueber Base64 und Blob  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `att_chm_attachment or CHM decode indicator`  

Prüft einen CHM-Magic-Header innerhalb des HTML-Decode-Pfads.

## Test 15 – `test15_hta_payload.html`

**Kategorie:** `ATTACHMENT_VECTOR_DECODE`  
**Beschreibung:** HTA Payload ueber Base64 und Blob  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `att_hta_attachment or dec_script`  

Prüft HTA-/Script-Inhalt innerhalb einer Base64-dekodierten Blob-Payload.

## Test 16 – `test16_certificate_inline_pem.html`

**Kategorie:** `CERT_SMUGGLING`  
**Beschreibung:** Inline PEM Zertifikat ohne starken Smuggling Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-5`  
**ExpectedCoreReasons:** `cert_inline_pem or cert_base64_block`  

Prüft Zertifikats-/PKCS-Indikatoren; Test 18 kombiniert diese zusätzlich mit starkem Smuggling-Kontext.

## Test 17 – `test17_certificate_pkcs7_inline.html`

**Kategorie:** `CERT_SMUGGLING`  
**Beschreibung:** Inline PKCS7 Block ohne starken Smuggling Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-5`  
**ExpectedCoreReasons:** `cert_inline_pkcs or cert_base64_block`  

Prüft Zertifikats-/PKCS-Indikatoren; Test 18 kombiniert diese zusätzlich mit starkem Smuggling-Kontext.

## Test 18 – `test18_certificate_smuggling_context.html`

**Kategorie:** `CERT_SMUGGLING`  
**Beschreibung:** Zertifikatsblock zusammen mit Smuggling Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `cert_inline_pem or cert_base64_block plus Smuggling Kontext`  

Prüft Zertifikats-/PKCS-Indikatoren; Test 18 kombiniert diese zusätzlich mit starkem Smuggling-Kontext.

## Test 19 – `test19_css_code_execution.html`

**Kategorie:** `CSS_CODE_EXEC`  
**Beschreibung:** CSS Inhalte werden spaeter als Code missbraucht  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `css_before_after_content,css_hidden_code_string,css_function_bridge,css_code_execution`  

Prüft CSS als versteckten Code-Speicher und die spätere Ausführung über JavaScript-/ComputedStyle-Brücken.

## Test 20 – `test20_css_computedstyle_exec.html`

**Kategorie:** `CSS_CODE_EXEC`  
**Beschreibung:** getComputedStyle liest versteckten Inhalt aus  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `css_computedstyle_exec,css_function_bridge`  

Prüft CSS als versteckten Code-Speicher und die spätere Ausführung über JavaScript-/ComputedStyle-Brücken.

## Test 21 – `test21_external_scripts_positive.html`

**Kategorie:** `EXTERNAL_SCRIPTS`  
**Beschreibung:** Externes Script im vorhandenen Smuggling Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `atob,external_scripts`  

Prüft, dass externe Scripts nur zusammen mit vorhandenem Smuggling-Kontext positiv gewertet werden.

## Test 22 – `test22_css_exfil_attr.html`

**Kategorie:** `CSS_EXFIL`  
**Beschreibung:** CSS attr Exfiltration ueber background url  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `css_attr_exfil,css_exfiltration`  

Prüft CSS-Exfiltrationsmuster bzw. externe CSS-Imports.

## Test 23 – `test23_css_import_external.html`

**Kategorie:** `CSS_EXFIL`  
**Beschreibung:** Externer CSS Import  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `0-3`  
**ExpectedCoreReasons:** `css_import_external`  

Prüft CSS-Exfiltrationsmuster bzw. externe CSS-Imports.

## Test 24 – `test24_geo_targeting_api.html`

**Kategorie:** `GEO_TARGETING`  
**Beschreibung:** Geo API und Geolocation in einem Script  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `geo_targeting_api,geo_location_api`  

Prüft Geo-/Timezone-basierte Zielauswahl.

## Test 25 – `test25_timezone_targeting.html`

**Kategorie:** `GEO_TARGETING`  
**Beschreibung:** Timezone basierte Selektionslogik  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `timezone_targeting`  

Prüft Geo-/Timezone-basierte Zielauswahl.

## Test 26 – `test26_evasion_webdriver.html`

**Kategorie:** `EVASION`  
**Beschreibung:** Antisandbox ueber navigator.webdriver  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `antisandbox_webdriver`  

Prüft typische Anti-Sandbox-/Evasion-Signale wie `navigator.webdriver`, CPU-/Memory- und Screen-Checks.

## Test 27 – `test27_evasion_hardware_check.html`

**Kategorie:** `EVASION`  
**Beschreibung:** Hardware Checks fuer kleine oder virtuelle Systeme  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `hardware_check_evasion`  

Prüft typische Anti-Sandbox-/Evasion-Signale wie `navigator.webdriver`, CPU-/Memory- und Screen-Checks.

## Test 28 – `test28_persistence_localstorage.html`

**Kategorie:** `PERSISTENCE`  
**Beschreibung:** LocalStorage Speicherung und Wiederverwendung  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `localstorage_persistence`  

Prüft Persistenzindikatoren über LocalStorage bzw. SessionStorage.

## Test 29 – `test29_persistence_sessionstorage.html`

**Kategorie:** `PERSISTENCE`  
**Beschreibung:** SessionStorage Persistenz  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `sessionstorage_persistence`  

Prüft Persistenzindikatoren über LocalStorage bzw. SessionStorage.

## Test 30 – `test30_domain_rotation.html`

**Kategorie:** `DOMAIN_ROTATION`  
**Beschreibung:** Drei Domains und Redirect Logik  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `domain_rotation`  

Prüft Domain-Rotation bzw. dynamisch zusammengesetzte Redirect-Ziele.

## Test 31 – `test31_computed_redirect.html`

**Kategorie:** `DOMAIN_ROTATION`  
**Beschreibung:** Redirect Ziel wird dynamisch zusammengesetzt  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `computed_redirect`  

Prüft Domain-Rotation bzw. dynamisch zusammengesetzte Redirect-Ziele.

## Test 32 – `test32_clickfix_run_dialog.html`

**Kategorie:** `CLICKFIX`  
**Beschreibung:** Run Dialog und PowerShell Lure  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `run_dialog_lure,powershell_lure or clickfix_lure`  

Prüft ClickFix-/Fake-CAPTCHA-Lures sowie PowerShell-/Clipboard-Kontext.

## Test 33 – `test33_fake_captcha_clipboard.html`

**Kategorie:** `CLICKFIX`  
**Beschreibung:** Fake CAPTCHA mit Clipboard und Exec Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `fake_captcha_lure,clipboard_exec_lure,clickfix_lure`  

Prüft ClickFix-/Fake-CAPTCHA-Lures sowie PowerShell-/Clipboard-Kontext.

## Test 34 – `test34_push_abuse.html`

**Kategorie:** `PUSH_ABUSE`  
**Beschreibung:** Notification Permission plus Service Worker und PushManager  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `0-3`  
**ExpectedCoreReasons:** `push_permission_request,push_serviceworker_combo,push_notification_flow`  

Prüft Notification Permission, Service Worker und PushManager als Push-Abuse-Kombination.

## Test 35 – `test35_blockchain_staging.html`

**Kategorie:** `BLOCKCHAIN_STAGING`  
**Beschreibung:** Web3 oder Ethers basierte Staging Logik  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `web3_api_usage,ethers_contract_payload,blockchain_remote_stage or blockchain_staged_payload`  

Prüft Web3-/Ethers-basierte Remote-Staging-Logik.

## Test 36 – `test36_legitimate_negative.html`

**Kategorie:** `NEGATIVE`  
**Beschreibung:** Legitime einfache Seite ohne verdaechtige APIs  
**ExpectedDetection:** `NO`  
**ExpectedScore:** `0-1`  
**ExpectedCoreReasons:** `none`  

Negativtest ohne verdächtige APIs oder Payload-Muster.

## Test 37 – `test37_safe_external_negative.html`

**Kategorie:** `NEGATIVE`  
**Beschreibung:** Externe Scripts ohne Smuggling Kontext  
**ExpectedDetection:** `NO`  
**ExpectedScore:** `0-2`  
**ExpectedCoreReasons:** `none`  

Negativtest mit bekannten externen Bibliotheken, aber ohne Smuggling-Kontext.

## Test 38 – `test38_html_keyword_newsletter_like.html`

**Kategorie:** `NEWSLETTER_HTML_ONLY`  
**Beschreibung:** Nur HTML Keyword, kein echter Header Newsletter Test  
**ExpectedDetection:** `LOW_OR_NONE`  
**ExpectedScore:** `0-2`  
**ExpectedCoreReasons:** `html_keyword newsletter heuristic only`  

Prüft Newsletter-artige HTML-Wörter ohne echte Mail-Header. Erwartet wird deshalb höchstens ein schwaches Signal.

## Test 39 – `test39_all_in_one_capped.html`

**Kategorie:** `ALL_IN_ONE`  
**Beschreibung:** Kombinierter Test fuer mehrere Module mit realistischer Cap Erwartung  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 internal capped`  
**ExpectedCoreReasons:** `mehrere Klassen, intern gedeckelt`  

Kombiniert mehrere Module und prüft insbesondere, dass der Endscore korrekt gedeckelt bleibt.

## Test 40 – `test40_svg_data_uri_pe_direct.html`

**Kategorie:** `SVG_ACTIVE`  
**Beschreibung:** Direkter SVG Data URI Test fuer den eingebetteten SVG Extraktionspfad  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `att_svg_data_uri,att_svg_script,att_svg_event_handler,dec_pe`  

Prüft den direkten eingebetteten SVG-Data-URI-Pfad inklusive enthaltener PE-Payload.

## Test 41 – `test41_v46_script_prescan_magic_late.html`

**Kategorie:** `V46_SCRIPT_PRESCAN`  
**Beschreibung:** v4.6: billiger Vorscan erkennt Magic-Prefix in spaetem Script  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `script_prescan_payload,b64_magic_prefix,dec_pe`  

Prüft den neuen v4.6-Script-Prescan. Eine Magic-Prefix-Payload in einem späteren Script muss trotzdem priorisiert werden.

## Test 42 – `test42_v46_script_prescan_budget.html`

**Kategorie:** `V46_BUDGET`  
**Beschreibung:** v4.6: kontrolliertes Prescan-Budget bei >64 Scripts  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `script_prescan_payload,dec_pe`  
**ExpectedInfoReasons:** `script_prescan_budget`  

Prüft die Prescan-Limits mit mehr als 64 Inline-Scripts und erwartet zusätzlich `script_prescan_budget` als Info-Reason.

## Test 43 – `test43_v46_uint8array_hex_pe.html`

**Kategorie:** `V46_UINT8ARRAY`  
**Beschreibung:** Hexadezimale Uint8Array Bytefolge mit PE Magic  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `uint8array_payload,pe_uint8array`  

Prüft die v4.6-Unterstützung hexadezimaler Bytewerte in `Uint8Array`.

## Test 44 – `test44_v46_nested_base64_pe.html`

**Kategorie:** `V46_RECURSIVE_DECODE`  
**Beschreibung:** Rekursiver Base64 Decode mit PE in zweiter Stufe  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `nested_base64_payload,dec_pe`  

Prüft rekursive Base64-Erkennung: die erste Decode-Stufe enthält erneut eine Base64-codierte PE-Payload.

## Test 45 – `test45_v46_gzip_magic_payload.html`

**Kategorie:** `V46_COMPRESSED`  
**Beschreibung:** GZIP Magic Header fuer erweiterte Content Klassifikation  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `dec_compressed`  

Prüft die zusätzliche Magic-Erkennung für komprimierte Inhalte anhand eines GZIP-Headers.

## Test 46 – `test46_v46_zip_executable_member.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit payload.exe  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_executable_member`  

Prüft das strukturierte ZIP-Parsing auf ein ausführbares Mitglied (`payload.exe`).

## Test 47 – `test47_v46_zip_script_member.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit stage.ps1  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_script_member`  

Prüft das strukturierte ZIP-Parsing auf ein Script-Mitglied (`stage.ps1`).

## Test 48 – `test48_v46_zip_double_extension.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit invoice.pdf.exe  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_executable_member,zip_double_extension`  

Prüft Double-Extension-Erkennung wie `invoice.pdf.exe`.

## Test 49 – `test49_v46_zip_path_traversal.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit ../dropper.ps1  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_script_member,zip_path_traversal`  

Prüft ZIP Path Traversal über einen Namen wie `../dropper.ps1`.

## Test 50 – `test50_v46_zip_nested_archive.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit inner.zip  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-12`  
**ExpectedCoreReasons:** `dec_zip,zip_nested_archive`  

Prüft ein verschachteltes Archiv (`inner.zip`) im ZIP Central Directory.

## Test 51 – `test51_v46_zip_high_ratio.html`

**Kategorie:** `V46_ZIP_INFO`  
**Beschreibung:** ZIP Metadaten mit hoher Kompressionsrate  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-10`  
**ExpectedCoreReasons:** `dec_zip`  
**ExpectedInfoReasons:** `zip_high_compression_ratio`  

Prüft auffällige ZIP-Kompressionsmetadaten und erwartet `zip_high_compression_ratio` als Info-Reason.

## Test 52 – `test52_v46_zip_stored_pe.html`

**Kategorie:** `V46_ZIP_STORED`  
**Beschreibung:** Stored ZIP Mitglied enthaelt PE Payload  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_stored_payload,dec_pe`  

Prüft einen unkomprimiert gespeicherten ZIP-Eintrag, dessen Inhalt direkt als PE erkannt und rekursiv analysiert wird.

## Test 53 – `test53_v46_zip_encrypted_flag.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit Encryption Flag  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-12`  
**ExpectedCoreReasons:** `dec_zip,zip_encrypted`  

Prüft das ZIP Encryption Flag und den zugehörigen Soft-Reason.

## Test 54 – `test54_v46_zip_many_entries.html`

**Kategorie:** `V46_ZIP_INFO`  
**Beschreibung:** ZIP mit 257 Eintraegen  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-10`  
**ExpectedCoreReasons:** `dec_zip`  
**ExpectedInfoReasons:** `zip_many_entries`  

Prüft das ZIP-Eintragslimit mit 257 Mitgliedern und erwartet `zip_many_entries` als Info-Reason.

## Test 55 – `test55_v46_xor_constant_pe.html`

**Kategorie:** `V46_CRYPTO`  
**Beschreibung:** Konstantes XOR Bytearray wird als PE rekonstruiert  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `xor_constant_payload,dec_pe`  

Prüft die v4.6-Rekonstruktion eines konstant XOR-codierten PE-Payloads.

## Test 56 – `test56_v46_rc4_constant_pe.html`

**Kategorie:** `V46_CRYPTO`  
**Beschreibung:** Konstantes RC4 Bytearray wird als PE rekonstruiert  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `rc4_constant_payload,dec_pe`  

Prüft die v4.6-Rekonstruktion eines konstant RC4-codierten PE-Payloads.

---

# Welche Bereiche benötigen weiterhin eine EML-/MIME-Suite?

| Bereich | Warum HTML allein nicht genügt |
|---|---|
| echte Attachment-Dateinamen | `att_script_attachment`, OneNote, Office-Macro-Container usw. hängen an MIME-Part-Metadaten |
| MIME Content-Type | Blob-Typen in HTML sind keine echten Mail-Part Content-Types |
| Attachment Magic vs. Dateiendung | benötigt echten Dateinamen plus echten Part-Inhalt |
| Image Tail Carving | sollte zusätzlich mit echten PNG/JPEG/GIF/WebP-Mailparts getestet werden |
| Newsletter-Erkennung | echte Header wie `List-Id`, `List-Unsubscribe`, `Precedence` fehlen in HTML-Dateien |
| Trusted Sender / Domain Maps | benötigen echte Rspamd-Task- und Map-Konfiguration |
| `image_smuggling_info` | basiert auf Attachment-Namen und Part-Inhalten |

# Empfohlener Regression-Ablauf

1. `rspamadm configtest` ausführen.
2. Lua-Modul mit `test_mode = true` oder kontrollierter Testkonfiguration laden.
3. Tests 36 und 37 zuerst als Negativkontrolle prüfen.
4. Tests 01–15 als Kernregression ausführen.
5. Tests 16–40 für die erweiterten Heuristiken ausführen.
6. Tests 41–56 separat als v4.6.0-Regressionsblock ausführen.
7. `ExpectedCoreReasons` und `ExpectedInfoReasons` mit den erzeugten Symbolen/Logs vergleichen.
8. Score-Abweichungen nur dann als Fehler werten, wenn sie ausserhalb der vorgesehenen Bereiche liegen oder ein erwarteter Reason fehlt.

# Besonders wichtige v4.6.0-Regressionen

Die folgenden Tests sollten bei jeder Änderung an Decode-, Script- oder Containerlogik zwingend mitlaufen:

- **41** – Script-Prescan / Magic-Priorisierung
- **42** – Prescan-Budget
- **43** – Hex-Uint8Array
- **44** – Nested Base64
- **46–54** – ZIP-Parser
- **55** – XOR-Rekonstruktion
- **56** – RC4-Rekonstruktion

# Versionierung

Empfohlene zusammengehörige Artefakte:

- `html_smuggling.lua` – v4.6.0
- `README_html_smuggling_v4.6.0.md`
- `create_html_pattern_test_suite_v4_6_0_r1.ps1`
- `Testmatrix_HTML_Smuggling_v4.6.0-r1.md`
- `README_HTML_Smuggling_TestSuite_v4.6.0_01-56_detailed.md`
- `HTML_Smuggling_v4.6.0_Tests_01-56.zip`

Damit sind Implementierung, Testgenerator, Testmatrix, Einzeldaten und Dokumentation auf demselben Versionsstand.
