# HTML Smuggling Detection v4.7.0 – Detaillierte Test-Suite 01–68

## Überblick

Dieses Dokument beschreibt die vollständige HTML-/Script-Regressionssuite für `html_smuggling.lua` **v4.7.0**.

Die Suite enthält **68 einzelne HTML-Testdateien**. Tests 01–56 bilden den v4.6.0-Stand ab; Tests 57–68 prüfen die neuen v4.7.0-Pfade.

Die eingebetteten Binärdaten sind synthetische Testdaten. Echte MIME-/Attachment-Metadaten werden weiterhin in einer separaten EML-Suite benötigt.

## Testgruppen

### Tests 01–10

Basis-Smuggling, Obfuskation, WASM, Uint8Array, Delay, Worker, Fetch, AppInstaller

- `test01_basic_pe_smuggling.html` – Basis: atob plus Blob plus createObjectURL plus PE
- `test02_split_payload_pe_fixed.html` – Korrigierter Split Payload mit mindestens sechs Fragmenten
- `test03_array_join_pe.html` – Array.join Konstruktion mit PE Payload
- `test04_obfuscated_pe.html` – Obfuskierter Zugriff ueber Array Indizes und Konstruktoren
- `test05_wasm_smuggling.html` – WASM Modul ueber fetch und WebAssembly.instantiate
- `test06_uint8array_pe_large.html` – Korrigierter Uint8Array Test mit mehr als 1024 Bytewerten
- `test07_delayed_execution_pe.html` – Verzoegertes Smuggling ueber setTimeout
- `test08_webworker_pe.html` – Web Worker verarbeitet den Base64 Payload
- `test09_fetch_api_pe.html` – Fetch API plus Data URI Transport
- `test10_appinstaller_schema.html` – AppInstaller Schema und XML Kontext

### Tests 11–20

PDF, SVG, CHM, HTA, Zertifikat und CSS Code Execution

- `test11_pdf_javascript_payload.html` – PDF mit JavaScript Action im Decode Pfad
- `test12_pdf_launch_payload.html` – PDF mit Launch und EmbeddedFile im Decode Pfad
- `test13_svg_active_content.html` – Aktives SVG in eingebetteter object data URI Form
- `test14_chm_payload.html` – CHM Payload ueber Base64 und Blob
- `test15_hta_payload.html` – HTA Payload ueber Base64 und Blob
- `test16_certificate_inline_pem.html` – Inline PEM Zertifikat ohne starken Smuggling Kontext
- `test17_certificate_pkcs7_inline.html` – Inline PKCS7 Block ohne starken Smuggling Kontext
- `test18_certificate_smuggling_context.html` – Zertifikatsblock zusammen mit Smuggling Kontext
- `test19_css_code_execution.html` – CSS Inhalte werden spaeter als Code missbraucht
- `test20_css_computedstyle_exec.html` – getComputedStyle liest versteckten Inhalt aus

### Tests 21–35

External Scripts, CSS Exfil, Geo, Evasion, Persistence, Rotation, ClickFix, Push, Blockchain

- `test21_external_scripts_positive.html` – Externes Script im vorhandenen Smuggling Kontext
- `test22_css_exfil_attr.html` – CSS attr Exfiltration ueber background url
- `test23_css_import_external.html` – Externer CSS Import
- `test24_geo_targeting_api.html` – Geo API und Geolocation in einem Script
- `test25_timezone_targeting.html` – Timezone basierte Selektionslogik
- `test26_evasion_webdriver.html` – Antisandbox ueber navigator.webdriver
- `test27_evasion_hardware_check.html` – Hardware Checks fuer kleine oder virtuelle Systeme
- `test28_persistence_localstorage.html` – LocalStorage Speicherung und Wiederverwendung
- `test29_persistence_sessionstorage.html` – SessionStorage Persistenz
- `test30_domain_rotation.html` – Drei Domains und Redirect Logik
- `test31_computed_redirect.html` – Redirect Ziel wird dynamisch zusammengesetzt
- `test32_clickfix_run_dialog.html` – Run Dialog und PowerShell Lure
- `test33_fake_captcha_clipboard.html` – Fake CAPTCHA mit Clipboard und Exec Kontext
- `test34_push_abuse.html` – Notification Permission plus Service Worker und PushManager
- `test35_blockchain_staging.html` – Web3 oder Ethers basierte Staging Logik

### Tests 36–40

Negative Tests, Newsletter-HTML, All-in-One, SVG Data URI

- `test36_legitimate_negative.html` – Legitime einfache Seite ohne verdaechtige APIs
- `test37_safe_external_negative.html` – Externe Scripts ohne Smuggling Kontext
- `test38_html_keyword_newsletter_like.html` – Nur HTML Keyword, kein echter Header Newsletter Test
- `test39_all_in_one_capped.html` – Kombinierter Test fuer mehrere Module mit realistischer Cap Erwartung
- `test40_svg_data_uri_pe_direct.html` – Direkter SVG Data URI Test fuer den eingebetteten SVG Extraktionspfad

### Tests 41–56

v4.6 Prescan, Nested Decode, ZIP-Parser, XOR und RC4

- `test41_v46_script_prescan_magic_late.html` – v4.6: billiger Vorscan erkennt Magic-Prefix in spaetem Script
- `test42_v46_script_prescan_budget.html` – v4.6: kontrolliertes Prescan-Budget bei >64 Scripts
- `test43_v46_uint8array_hex_pe.html` – Hexadezimale Uint8Array Bytefolge mit PE Magic
- `test44_v46_nested_base64_pe.html` – Rekursiver Base64 Decode mit PE in zweiter Stufe
- `test45_v46_gzip_magic_payload.html` – GZIP Magic Header fuer erweiterte Content Klassifikation
- `test46_v46_zip_executable_member.html` – ZIP mit payload.exe
- `test47_v46_zip_script_member.html` – ZIP mit stage.ps1
- `test48_v46_zip_double_extension.html` – ZIP mit invoice.pdf.exe
- `test49_v46_zip_path_traversal.html` – ZIP mit ../dropper.ps1
- `test50_v46_zip_nested_archive.html` – ZIP mit inner.zip
- `test51_v46_zip_high_ratio.html` – ZIP Metadaten mit hoher Kompressionsrate
- `test52_v46_zip_stored_pe.html` – Stored ZIP Mitglied enthaelt PE Payload
- `test53_v46_zip_encrypted_flag.html` – ZIP mit Encryption Flag
- `test54_v46_zip_many_entries.html` – ZIP mit 257 Eintraegen
- `test55_v46_xor_constant_pe.html` – Konstantes XOR Bytearray wird als PE rekonstruiert
- `test56_v46_rc4_constant_pe.html` – Konstantes RC4 Bytearray wird als PE rekonstruiert

### Tests 57–68

v4.7 DOM, Imports, Worker/ServiceWorker, Evasion, Obfuskation und ZIP-Tiefenanalyse

- `test57_v47_dom_dynamic_sink.html` – DOM Sink innerHTML zusammen mit Base64/Payload-Kontext
- `test58_v47_dynamic_import_data.html` – Dynamischer import() direkt aus einer data: JavaScript URL
- `test59_v47_worker_blob_reconstruction.html` – Worker wird aus statischem Blob-Script erzeugt; Worker-Code ist begrenzt rekonstruierbar
- `test60_v47_serviceworker_broad_scope.html` – ServiceWorker Registrierung mit Root-Scope
- `test61_v47_websocket_portscan.html` – Mehrere WebSocket-Verbindungen auf verschiedene lokale Ports als Portscan-Heuristik
- `test62_v47_jsfuck_obfuscation.html` – JSFuck-typische Tokenkombinationen werden als Obfuskation erkannt
- `test63_v47_unicode_escape_payload.html` – Unicode-Escapes rekonstruieren einen verschleierten API-Namen
- `test64_v47_template_literal_obfuscation.html` – Template Literal mit ${...}-Konstruktion und Exec-Kontext
- `test65_v47_zip_comment_payload.html` – ZIP Central-Directory-Kommentar enthaelt Base64-codierte synthetische PE-Payload
- `test66_v47_zip_high_entropy_stored.html` – Stored ZIP-Mitglied mit hoher Entropie setzt einen Info-Reason
- `test67_v47_nested_stored_zip_pe.html` – Stored ZIP-in-ZIP wird unter Decode-/Container-Budget rekursiv bis zur PE-Payload analysiert
- `test68_v47_sharedarraybuffer_timing.html` – SharedArrayBuffer + Atomics + performance.now als Sidechannel/Evasion-Indikator

---

# Detaillierte Testfälle

## Test 01 – `test01_basic_pe_smuggling.html`

**Kategorie:** `JS_SMUGGLING`  
**Beschreibung:** Basis: atob plus Blob plus createObjectURL plus PE  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `atob,blob,createObjectURL,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 02 – `test02_split_payload_pe_fixed.html`

**Kategorie:** `JS_SMUGGLING`  
**Beschreibung:** Korrigierter Split Payload mit mindestens sechs Fragmenten  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `split_payload,atob,blob,createObjectURL,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 03 – `test03_array_join_pe.html`

**Kategorie:** `JS_SMUGGLING`  
**Beschreibung:** Array.join Konstruktion mit PE Payload  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `atob,blob,createObjectURL,b64_joined_parts,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 04 – `test04_obfuscated_pe.html`

**Kategorie:** `OBFUSCATION`  
**Beschreibung:** Obfuskierter Zugriff ueber Array Indizes und Konstruktoren  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `atob_obfuscated or obfus_api,blob,createObjectURL,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 05 – `test05_wasm_smuggling.html`

**Kategorie:** `WASM_STAGING`  
**Beschreibung:** WASM Modul ueber fetch und WebAssembly.instantiate  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `fetch,webassembly or wasm_fetch_stage`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 06 – `test06_uint8array_pe_large.html`

**Kategorie:** `UINT8ARRAY`  
**Beschreibung:** Korrigierter Uint8Array Test mit mehr als 1024 Bytewerten  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `uint8array_payload,pe_uint8array`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 07 – `test07_delayed_execution_pe.html`

**Kategorie:** `JS_SMUGGLING`  
**Beschreibung:** Verzoegertes Smuggling ueber setTimeout  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `delayed_execution,timeout_b64_smuggling or timeout_b64_decode,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 08 – `test08_webworker_pe.html`

**Kategorie:** `WEBWORKER`  
**Beschreibung:** Web Worker verarbeitet den Base64 Payload  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `webworker,atob,blob,createObjectURL,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 09 – `test09_fetch_api_pe.html`

**Kategorie:** `FETCH`  
**Beschreibung:** Fetch API plus Data URI Transport  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `fetch,data_uri or blob,createObjectURL or dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 10 – `test10_appinstaller_schema.html`

**Kategorie:** `APPINSTALLER`  
**Beschreibung:** AppInstaller Schema und XML Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `ms_appinstaller_uri or ms_appinstaller_word`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 11 – `test11_pdf_javascript_payload.html`

**Kategorie:** `PDF_ACTIVE`  
**Beschreibung:** PDF mit JavaScript Action im Decode Pfad  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `dec_pdf,att_pdf_javascript`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 12 – `test12_pdf_launch_payload.html`

**Kategorie:** `PDF_ACTIVE`  
**Beschreibung:** PDF mit Launch und EmbeddedFile im Decode Pfad  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `dec_pdf,att_pdf_launch,att_pdf_embeddedfile`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 13 – `test13_svg_active_content.html`

**Kategorie:** `SVG_ACTIVE`  
**Beschreibung:** Aktives SVG in eingebetteter object data URI Form  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `att_svg_script,att_svg_event_handler,att_svg_foreignobject,att_svg_data_uri,att_svg_smuggling_context`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 14 – `test14_chm_payload.html`

**Kategorie:** `ATTACHMENT_VECTOR_DECODE`  
**Beschreibung:** CHM Payload ueber Base64 und Blob  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `att_chm_attachment or CHM decode indicator`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 15 – `test15_hta_payload.html`

**Kategorie:** `ATTACHMENT_VECTOR_DECODE`  
**Beschreibung:** HTA Payload ueber Base64 und Blob  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `att_hta_attachment or dec_script`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 16 – `test16_certificate_inline_pem.html`

**Kategorie:** `CERT_SMUGGLING`  
**Beschreibung:** Inline PEM Zertifikat ohne starken Smuggling Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-5`  
**ExpectedCoreReasons:** `cert_inline_pem or cert_base64_block`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 17 – `test17_certificate_pkcs7_inline.html`

**Kategorie:** `CERT_SMUGGLING`  
**Beschreibung:** Inline PKCS7 Block ohne starken Smuggling Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-5`  
**ExpectedCoreReasons:** `cert_inline_pkcs or cert_base64_block`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 18 – `test18_certificate_smuggling_context.html`

**Kategorie:** `CERT_SMUGGLING`  
**Beschreibung:** Zertifikatsblock zusammen mit Smuggling Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `cert_inline_pem or cert_base64_block plus Smuggling Kontext`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 19 – `test19_css_code_execution.html`

**Kategorie:** `CSS_CODE_EXEC`  
**Beschreibung:** CSS Inhalte werden spaeter als Code missbraucht  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `css_before_after_content,css_hidden_code_string,css_function_bridge,css_code_execution`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 20 – `test20_css_computedstyle_exec.html`

**Kategorie:** `CSS_CODE_EXEC`  
**Beschreibung:** getComputedStyle liest versteckten Inhalt aus  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `css_computedstyle_exec,css_function_bridge`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 21 – `test21_external_scripts_positive.html`

**Kategorie:** `EXTERNAL_SCRIPTS`  
**Beschreibung:** Externes Script im vorhandenen Smuggling Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `atob,external_scripts`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 22 – `test22_css_exfil_attr.html`

**Kategorie:** `CSS_EXFIL`  
**Beschreibung:** CSS attr Exfiltration ueber background url  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `css_attr_exfil,css_exfiltration`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 23 – `test23_css_import_external.html`

**Kategorie:** `CSS_EXFIL`  
**Beschreibung:** Externer CSS Import  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `0-3`  
**ExpectedCoreReasons:** `css_import_external`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 24 – `test24_geo_targeting_api.html`

**Kategorie:** `GEO_TARGETING`  
**Beschreibung:** Geo API und Geolocation in einem Script  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `geo_targeting_api,geo_location_api`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 25 – `test25_timezone_targeting.html`

**Kategorie:** `GEO_TARGETING`  
**Beschreibung:** Timezone basierte Selektionslogik  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `timezone_targeting`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 26 – `test26_evasion_webdriver.html`

**Kategorie:** `EVASION`  
**Beschreibung:** Antisandbox ueber navigator.webdriver  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `antisandbox_webdriver`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 27 – `test27_evasion_hardware_check.html`

**Kategorie:** `EVASION`  
**Beschreibung:** Hardware Checks fuer kleine oder virtuelle Systeme  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `hardware_check_evasion`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 28 – `test28_persistence_localstorage.html`

**Kategorie:** `PERSISTENCE`  
**Beschreibung:** LocalStorage Speicherung und Wiederverwendung  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `localstorage_persistence`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 29 – `test29_persistence_sessionstorage.html`

**Kategorie:** `PERSISTENCE`  
**Beschreibung:** SessionStorage Persistenz  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `sessionstorage_persistence`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 30 – `test30_domain_rotation.html`

**Kategorie:** `DOMAIN_ROTATION`  
**Beschreibung:** Drei Domains und Redirect Logik  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `domain_rotation`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 31 – `test31_computed_redirect.html`

**Kategorie:** `DOMAIN_ROTATION`  
**Beschreibung:** Redirect Ziel wird dynamisch zusammengesetzt  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `computed_redirect`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 32 – `test32_clickfix_run_dialog.html`

**Kategorie:** `CLICKFIX`  
**Beschreibung:** Run Dialog und PowerShell Lure  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `run_dialog_lure,powershell_lure or clickfix_lure`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 33 – `test33_fake_captcha_clipboard.html`

**Kategorie:** `CLICKFIX`  
**Beschreibung:** Fake CAPTCHA mit Clipboard und Exec Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `fake_captcha_lure,clipboard_exec_lure,clickfix_lure`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 34 – `test34_push_abuse.html`

**Kategorie:** `PUSH_ABUSE`  
**Beschreibung:** Notification Permission plus Service Worker und PushManager  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `0-3`  
**ExpectedCoreReasons:** `push_permission_request,push_serviceworker_combo,push_notification_flow`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 35 – `test35_blockchain_staging.html`

**Kategorie:** `BLOCKCHAIN_STAGING`  
**Beschreibung:** Web3 oder Ethers basierte Staging Logik  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `web3_api_usage,ethers_contract_payload,blockchain_remote_stage or blockchain_staged_payload`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 36 – `test36_legitimate_negative.html`

**Kategorie:** `NEGATIVE`  
**Beschreibung:** Legitime einfache Seite ohne verdaechtige APIs  
**ExpectedDetection:** `NO`  
**ExpectedScore:** `0-1`  
**ExpectedCoreReasons:** `none`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 37 – `test37_safe_external_negative.html`

**Kategorie:** `NEGATIVE`  
**Beschreibung:** Externe Scripts ohne Smuggling Kontext  
**ExpectedDetection:** `NO`  
**ExpectedScore:** `0-2`  
**ExpectedCoreReasons:** `none`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 38 – `test38_html_keyword_newsletter_like.html`

**Kategorie:** `NEWSLETTER_HTML_ONLY`  
**Beschreibung:** Nur HTML Keyword, kein echter Header Newsletter Test  
**ExpectedDetection:** `LOW_OR_NONE`  
**ExpectedScore:** `0-2`  
**ExpectedCoreReasons:** `html_keyword newsletter heuristic only`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 39 – `test39_all_in_one_capped.html`

**Kategorie:** `ALL_IN_ONE`  
**Beschreibung:** Kombinierter Test fuer mehrere Module mit realistischer Cap Erwartung  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 internal capped`  
**ExpectedCoreReasons:** `mehrere Klassen, intern gedeckelt`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 40 – `test40_svg_data_uri_pe_direct.html`

**Kategorie:** `SVG_ACTIVE`  
**Beschreibung:** Direkter SVG Data URI Test fuer den eingebetteten SVG Extraktionspfad  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-10 group capped`  
**ExpectedCoreReasons:** `att_svg_data_uri,att_svg_script,att_svg_event_handler,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 41 – `test41_v46_script_prescan_magic_late.html`

**Kategorie:** `V46_SCRIPT_PRESCAN`  
**Beschreibung:** v4.6: billiger Vorscan erkennt Magic-Prefix in spaetem Script  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `script_prescan_payload,b64_magic_prefix,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 42 – `test42_v46_script_prescan_budget.html`

**Kategorie:** `V46_BUDGET`  
**Beschreibung:** v4.6: kontrolliertes Prescan-Budget bei >64 Scripts  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `script_prescan_payload,dec_pe`  
**ExpectedInfoReasons:** `script_prescan_budget`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 43 – `test43_v46_uint8array_hex_pe.html`

**Kategorie:** `V46_UINT8ARRAY`  
**Beschreibung:** Hexadezimale Uint8Array Bytefolge mit PE Magic  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `uint8array_payload,pe_uint8array`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 44 – `test44_v46_nested_base64_pe.html`

**Kategorie:** `V46_RECURSIVE_DECODE`  
**Beschreibung:** Rekursiver Base64 Decode mit PE in zweiter Stufe  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `nested_base64_payload,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 45 – `test45_v46_gzip_magic_payload.html`

**Kategorie:** `V46_COMPRESSED`  
**Beschreibung:** GZIP Magic Header fuer erweiterte Content Klassifikation  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-10`  
**ExpectedCoreReasons:** `dec_compressed`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 46 – `test46_v46_zip_executable_member.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit payload.exe  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_executable_member`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 47 – `test47_v46_zip_script_member.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit stage.ps1  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_script_member`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 48 – `test48_v46_zip_double_extension.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit invoice.pdf.exe  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_executable_member,zip_double_extension`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 49 – `test49_v46_zip_path_traversal.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit ../dropper.ps1  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_script_member,zip_path_traversal`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 50 – `test50_v46_zip_nested_archive.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit inner.zip  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-12`  
**ExpectedCoreReasons:** `dec_zip,zip_nested_archive`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 51 – `test51_v46_zip_high_ratio.html`

**Kategorie:** `V46_ZIP_INFO`  
**Beschreibung:** ZIP Metadaten mit hoher Kompressionsrate  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-10`  
**ExpectedCoreReasons:** `dec_zip`  
**ExpectedInfoReasons:** `zip_high_compression_ratio`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 52 – `test52_v46_zip_stored_pe.html`

**Kategorie:** `V46_ZIP_STORED`  
**Beschreibung:** Stored ZIP Mitglied enthaelt PE Payload  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_stored_payload,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 53 – `test53_v46_zip_encrypted_flag.html`

**Kategorie:** `V46_ZIP`  
**Beschreibung:** ZIP mit Encryption Flag  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `6-12`  
**ExpectedCoreReasons:** `dec_zip,zip_encrypted`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 54 – `test54_v46_zip_many_entries.html`

**Kategorie:** `V46_ZIP_INFO`  
**Beschreibung:** ZIP mit 257 Eintraegen  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-10`  
**ExpectedCoreReasons:** `dec_zip`  
**ExpectedInfoReasons:** `zip_many_entries`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 55 – `test55_v46_xor_constant_pe.html`

**Kategorie:** `V46_CRYPTO`  
**Beschreibung:** Konstantes XOR Bytearray wird als PE rekonstruiert  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `xor_constant_payload,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 56 – `test56_v46_rc4_constant_pe.html`

**Kategorie:** `V46_CRYPTO`  
**Beschreibung:** Konstantes RC4 Bytearray wird als PE rekonstruiert  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `rc4_constant_payload,dec_pe`  

Dieser Test gehört zum bewährten v4.6.0-Regressionsbestand und bleibt in v4.7.0 unverändert als Rückwärtskompatibilitätsprüfung erhalten.

## Test 57 – `test57_v47_dom_dynamic_sink.html`

**Kategorie:** `V47_DOM`  
**Beschreibung:** DOM Sink innerHTML zusammen mit Base64/Payload-Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-8`  
**ExpectedCoreReasons:** `dom_dynamic_sink,atob`  

Prüft dynamische DOM-Schreibpfade nur zusammen mit Payload-/Exec-Kontext, um normale DOM-Nutzung nicht unnötig hoch zu bewerten.

## Test 58 – `test58_v47_dynamic_import_data.html`

**Kategorie:** `V47_DYNAMIC_IMPORT`  
**Beschreibung:** Dynamischer import() direkt aus einer data: JavaScript URL  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `7-15 capped`  
**ExpectedCoreReasons:** `dynamic_import_data`  

Prüft `import()` direkt aus einer `data:`-JavaScript-URL. Dieser Pfad wird als harter Script-Indikator behandelt.

## Test 59 – `test59_v47_worker_blob_reconstruction.html`

**Kategorie:** `V47_WORKER`  
**Beschreibung:** Worker wird aus statischem Blob-Script erzeugt; Worker-Code ist begrenzt rekonstruierbar  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-10`  
**ExpectedCoreReasons:** `worker_blob_stage,worker_inline_script,webworker`  

Prüft Worker-Blob-Staging sowie die begrenzte Rekonstruktion eines statischen Worker-Scriptstrings.

## Test 60 – `test60_v47_serviceworker_broad_scope.html`

**Kategorie:** `V47_SERVICEWORKER`  
**Beschreibung:** ServiceWorker Registrierung mit Root-Scope  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `3-8`  
**ExpectedCoreReasons:** `serviceworker_register,serviceworker_broad_scope,serviceworker_api`  

Prüft ServiceWorker-Registrierung und eine auffällig breite Root-Scope-Konfiguration.

## Test 61 – `test61_v47_websocket_portscan.html`

**Kategorie:** `V47_EVASION`  
**Beschreibung:** Mehrere WebSocket-Verbindungen auf verschiedene lokale Ports als Portscan-Heuristik  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `3-8`  
**ExpectedCoreReasons:** `websocket_portscan`  

Prüft WebSocket-Verbindungen zu mehreren Ports bzw. Portlisten als browserseitige Portscan-Heuristik.

## Test 62 – `test62_v47_jsfuck_obfuscation.html`

**Kategorie:** `V47_OBFUSCATION`  
**Beschreibung:** JSFuck-typische Tokenkombinationen werden als Obfuskation erkannt  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `jsfuck_obfuscation`  

Prüft typische JSFuck-Tokenkombinationen und markiert sie als Obfuskation.

## Test 63 – `test63_v47_unicode_escape_payload.html`

**Kategorie:** `V47_OBFUSCATION`  
**Beschreibung:** Unicode-Escapes rekonstruieren einen verschleierten API-Namen  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `3-8`  
**ExpectedCoreReasons:** `unicode_escape_payload,obfus_api`  

Prüft die erweiterte `\uXXXX`-/`\u{...}`-Dekodierung und die Rekonstruktion verschleierter API-Namen.

## Test 64 – `test64_v47_template_literal_obfuscation.html`

**Kategorie:** `V47_OBFUSCATION`  
**Beschreibung:** Template Literal mit ${...}-Konstruktion und Exec-Kontext  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `2-6`  
**ExpectedCoreReasons:** `template_literal_obfuscation,eval_call`  

Prüft Template-Literal-Konstruktionen mit `${...}` in Kombination mit Exec-/Payload-Kontext.

## Test 65 – `test65_v47_zip_comment_payload.html`

**Kategorie:** `V47_ZIP`  
**Beschreibung:** ZIP Central-Directory-Kommentar enthaelt Base64-codierte synthetische PE-Payload  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_comment_payload,dec_pe`  

Prüft Base64-/Script-Payloads innerhalb von ZIP-Central-Directory-Kommentaren.

## Test 66 – `test66_v47_zip_high_entropy_stored.html`

**Kategorie:** `V47_ZIP_INFO`  
**Beschreibung:** Stored ZIP-Mitglied mit hoher Entropie setzt einen Info-Reason  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `4-10`  
**ExpectedCoreReasons:** `dec_zip`  
**ExpectedInfoReasons:** `zip_high_entropy_member`  

Prüft hohe Entropie in unkomprimiert gespeicherten ZIP-Mitgliedern als Info-Reason.

## Test 67 – `test67_v47_nested_stored_zip_pe.html`

**Kategorie:** `V47_ZIP_RECURSION`  
**Beschreibung:** Stored ZIP-in-ZIP wird unter Decode-/Container-Budget rekursiv bis zur PE-Payload analysiert  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `10-15 capped`  
**ExpectedCoreReasons:** `dec_zip,zip_nested_archive,zip_stored_payload,dec_pe`  

Prüft die begrenzte stored ZIP-in-ZIP-Rekursion unter Decode- und Container-Budget bis zur PE-Klassifikation.

## Test 68 – `test68_v47_sharedarraybuffer_timing.html`

**Kategorie:** `V47_EVASION`  
**Beschreibung:** SharedArrayBuffer + Atomics + performance.now als Sidechannel/Evasion-Indikator  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `3-8`  
**ExpectedCoreReasons:** `sharedarraybuffer_timing`  

Prüft `SharedArrayBuffer` + `Atomics` + hochauflösende Zeitmessung als Evasion-/Sidechannel-Indikator.

---

## v4.7.0-spezifische Bewertung

| Test | Schwerpunkt | Erwartung |
|---:|---|---|
| 57 | DOM Sink | Soft/Suspicious nur mit Payload-Kontext |
| 58 | Dynamic Import | harter Script-Pfad |
| 59 | Worker Blob | Suspicious + rekonstruierter Worker-Kontext |
| 60 | ServiceWorker Scope | Suspicious + Evasion |
| 61 | WebSocket Portscan | Evasion |
| 62 | JSFuck | Obfuskation |
| 63 | Unicode Escape | Obfuskation/Rekonstruktion |
| 64 | Template Literal | Obfuskation |
| 65 | ZIP Comment | Container/Soft + tatsächliche Payload-Klassifikation |
| 66 | ZIP Entropie | Info |
| 67 | ZIP-in-ZIP | begrenzte Container-Rekursion bis Payload |
| 68 | SharedArrayBuffer Timing | Evasion |

## Was weiterhin EML/MIME benötigt

- echte Attachment-Dateinamen und Content-Types
- Magic-/Extension-Mismatch an echten Mailparts
- Image-Tail-Carving an echten PNG/JPEG/GIF/WebP-Parts
- Newsletter-Header und Trusted-Sender-Maps
- realistische Multi-Part-Budgettests

## Empfohlener Ablauf

1. `rspamadm configtest`
2. Negativtests 36–37 prüfen
3. Kernregression 01–40
4. v4.6-Regressionsblock 41–56
5. v4.7-Regressionsblock 57–68
6. Core-/Info-Reasons gegen Manifest vergleichen
7. Score nur als Bereich bewerten; Reasons sind für Regression entscheidender

## Zusammengehörige Artefakte

- `html_smuggling_v4.7.0.lua`
- `README_html_smuggling_v4.7.0.md`
- `HTML_Smuggling_v4.7.0_Tests_01-68.zip`
- `README_HTML_Smuggling_TestSuite_v4.7.0_01-68_detailed.md`
