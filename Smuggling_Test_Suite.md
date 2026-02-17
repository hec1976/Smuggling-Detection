# HTML Smuggling Test Suite - Laboratory Cases

Diese Testsuite validiert die Rspamd HTML Smuggling Detection (v3.2). Ziel ist eine reproduzierbare Abdeckung moderner HTML Smuggling Techniken inklusive Split Payloads, Obfuscation und API Kombinationen.

## Aktuelle Test Matrix

Hinweise
- Erwartete Symbole sind die Kern Signale. Je nach Lua Logik koennen zusaetzliche Symbole erscheinen (z. B. combos, sniff_decoded, critical_boost_reason).


| Test | Datei | Fokus Technik | Erwartete Symbole (Kern) |
|---:|---|---|---|
| 01 | `test01_basic_pe_smuggling.html` | Basis atob plus Blob plus PE | `atob`, `blob`, `createObjectURL`, `dec_pe` | 
| 02 | `test02_split_payload_pe.html` | Split Payload per `+=` | `split_payload`, `atob`, `blob`, `createObjectURL`, `dec_pe` | 
| 03 | `test03_array_join_pe.html` | Split Payload per `Array.join()` | `split_payload`, `array_join_api`, `atob`, `blob`, `createObjectURL`, `dec_pe` | 
| 04 | `test04_obfuscated_pe.html` | Polymorphe Obfuscation plus PE | `polymorphic_obfuscation`, `atob`, `blob`, `createObjectURL`, `dec_pe` | 
| 05 | `test05_zip_smuggling.html` | ZIP Archive Smuggling | `atob`, `blob`, `createObjectURL`, `dec_zip` | 
| 06 | `test06_wasm_smuggling.html` | WASM Modul plus WebAssembly API | `atob`, `blob`, `createObjectURL`, `wasm_api`, `dec_wasm` |
| 07 | `test07_pdf_smuggling.html` | PDF Smuggling (window.open) | `atob`, `blob`, `createObjectURL`, `dec_pdf` | 
| 08 | `test08_webworker_pe.html` | Web Worker plus PE | `webworker_api`, `atob`, `blob`, `createObjectURL`, `dec_pe` | 
| 09 | `test09_delayed_execution_pe.html` | Delayed Execution (setTimeout) | `delayed_execution`, `atob`, `blob`, `createObjectURL`, `dec_pe` |
| 10 | `test10_appinstaller_schema.html` | ms appinstaller Schema plus XML | `ms_appinstaller_uri`, `dec_xml_appinstaller` |
| 11 | `test11_iframe_data_uri.html` | Iframe plus data URI | `iframe_src`, `data_uri` | 
| 12 | `test12_external_scripts.html` | External Script Loading | `script_src_external` |
| 13 | `test13_fetch_api_pe.html` | Fetch API plus Blob | `fetch_api`, `atob`, `blob`, `createObjectURL`, `dec_pe` | 
| 14 | `test14_qr_canvas_pe.html` | Canvas Lure plus Click Handler | `canvas_api`, `event_handler_api`, `atob`, `blob`, `createObjectURL`, `dec_pe` | 
| 15 | `test15_serviceworker_pe.html` | ServiceWorker Persistenz | `serviceworker_api`, `cache_api`, `atob`, `blob`, `createObjectURL`, `dec_pe` | 
| 16 | `test16_webcrypto_pe.html` | WebCrypto API (simuliert) | `webcrypto_api`, `atob`, `blob`, `createObjectURL`, `dec_pe` | 
| 17 | `test17_uint8array_pe.html` | Uint8Array Direct plus Blob | `uint8array_api`, `blob`, `createObjectURL`, `dec_pe` | 
| 18 | `test18_all_in_one_MAXIMUM.html` | ALL IN ONE Maximum | viele kombiniert plus `combos` plus `critical_boost` | 
| 19 | `test19_NEGATIVE_legitimate.html` | NEGATIVE legitime Website | ideal: keine oder nur Low Signal | 
| 20 | `test20_NEGATIVE_newsletter.html` | NEGATIVE Newsletter Tracking | ideal: keine oder nur Tracking | 

## Ziel der Suite

- Validierung der Symbol Abdeckung
- Identifikation von False Negatives
- Belastungstest der Kombinations Logik (Combos)
- Regression Tests bei Lua Aenderungen (v3.x)

## Ausfuehrung

PowerShell
- Erstlauf: `./create_realistic_test_suite.ps1`
- Neu generieren oder ueberschreiben: `./create_realistic_test_suite.ps1 -Force`

Output Ordner: `HTML_Smuggling_TestSuite_REALISTIC`

## Scoring Logik (Kurz)

Der Endscore setzt sich typischerweise zusammen aus
1. Raw Symbol Weights (Decoder, APIs, dec_ Erkennung)
2. Combos, wenn typische Smuggling Ketten auftreten (z. B. atob plus Blob plus createObjectURL)
3. Critical Boost, wenn ein harter Payload erkannt wird (z. B. PE, LNK, MSIX, ISO, WASM)
4. Optionaler Min Score Floor
5. Heuristiken, z. B. Newsletter Reduktion und optional SPF DKIM Multiplikator

Version: Laboratory Edition v1.5  
Engine Target: Rspamd HTML Smuggling Detection v3.2
