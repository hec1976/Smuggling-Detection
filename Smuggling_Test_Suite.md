# HTML Smuggling Test Suite, Laboratory Cases

Diese Testsuite validiert die Rspamd HTML Smuggling Detection v4.3.7a. Ziel ist eine reproduzierbare Abdeckung moderner HTML Smuggling Techniken inklusive Split Payloads, Obfuscation, Active Content, Zertifikats Kontext, Container Formate und API Kombinationen.

## Aktuelle Test Matrix

Hinweise

- Erwartete Symbole sind typische Kernsignale.
- Je nach Lua Logik können zusätzliche Symbole erscheinen, zum Beispiel `combos`, `critical_boost`, `sniff_decoded`, Marker oder modulinterne Zusatzgründe.
- Die Tabelle beschreibt die fachlich erwartete Hauptwirkung der Datei. Sie ist bewusst praxisnah und nicht auf eine einzige interne Implementierungsvariante fest verdrahtet.

| Test | Datei | Fokus Technik | Erwartete Symbole, Kern / typisch |
|---:|---|---|---|
| 01 | `test01_basic_pe_smuggling.html` | Basis mit `atob`, `Blob`, `createObjectURL`, PE Payload | `atob`, `blob`, `createObjectURL`, `dec_pe` |
| 02 | `test02_split_payload_pe.html` | Split Payload per `+=` | `split_payload`, `atob`, `blob`, `createObjectURL`, `dec_pe` |
| 03 | `test03_array_join_pe.html` | Split Payload per `Array.join()` | `split_payload`, `array_join_api`, `atob`, `blob`, `createObjectURL`, `dec_pe` |
| 04 | `test04_obfuscated_pe.html` | Polymorphe Obfuscation plus PE | `polymorphic_obfuscation`, `atob`, `blob`, `createObjectURL`, `dec_pe` |
| 05 | `test05_wasm_smuggling.html` | WASM Modul plus WebAssembly API | `atob`, `blob`, `createObjectURL`, `wasm_api`, `dec_wasm` |
| 06 | `test06_uint8array_pe.html` | Direkte `Uint8Array` Bytes plus Blob | `uint8array_api`, `blob`, `createObjectURL`, `dec_pe` |
| 07 | `test07_delayed_execution_pe.html` | Delayed Execution mit `setTimeout` | `delayed_execution`, `atob`, `blob`, `createObjectURL`, `dec_pe` |
| 08 | `test08_webworker_pe.html` | Web Worker plus PE Payload | `webworker_api`, `atob`, `blob`, `createObjectURL`, `dec_pe` |
| 09 | `test09_fetch_api_pe.html` | Fetch API plus Blob | `fetch_api`, `atob`, `blob`, `createObjectURL`, `dec_pe` |
| 10 | `test10_appinstaller_schema.html` | `ms-appinstaller` Schema plus XML / AppInstaller Kontext | `ms_appinstaller_uri`, `dec_xml_appinstaller` |
| 11 | `test11_pdf_javascript_attachment.html` | PDF mit `/JavaScript` Action | `pdf_active`, `pdf_javascript`, `dec_pdf` |
| 12 | `test12_pdf_launch_attachment.html` | PDF mit `/Launch` Action | `pdf_active`, `pdf_launch`, `dec_pdf` |
| 13 | `test13_svg_active_content.html` | SVG mit aktivem Content, Script und Embedded Data | `svg_active`, `svg_script`, `data_uri` |
| 14 | `test14_chm_attachment.html` | CHM Container als Attachment | `container_chm`, `dec_chm` |
| 15 | `test15_hta_attachment.html` | HTA Datei als aktiver Script Container | `script_hard`, `hta_attachment`, `dec_hta` |
| 16 | `test16_onenote_attachment.html` | OneNote Datei als Container Lure | `onenote_attachment`, `container_like` |
| 17 | `test17_office_macro_container.html` | Office Macro Container, z. B. DOCM | `office_macro_container`, `container_like` |
| 18 | `test18_lnk_attachment.html` | LNK Shortcut Datei | `lnk_attachment`, `dec_lnk` |
| 19 | `test19_script_attachment_js.html` | JavaScript Datei als Attachment | `script_hard`, `js_attachment` |
| 20 | `test20_certificate_inline_pem.html` | Inline PEM Zertifikat | `cert_smuggling`, `cert_pem_inline` |
| 21 | `test21_certificate_pkcs7_inline.html` | Inline PKCS7 Container | `cert_smuggling`, `cert_pkcs7_inline` |
| 22 | `test22_certificate_smuggling_context.html` | Zertifikat plus Smuggling Kontext | `cert_smuggling`, `atob`, `blob`, `createObjectURL`, `dec_pe` |
| 23 | `test23_image_double_ext.html` | Bildname mit doppelter Extension | `image_double_ext` |
| 24 | `test24_image_polyglot_hint.html` | Bildname mit Payload Hinweis | `image_polyglot_name` |
| 25 | `test25_css_code_execution.html` | CSS Content plus Script Auswertung | `css_code_exec`, `computedstyle_exec` |
| 26 | `test26_css_computedstyle_exec.html` | `getComputedStyle()` plus Base64 Decode plus `eval` | `css_code_exec`, `computedstyle_exec`, `atob` |
| 27 | `test27_NEGATIVE_legitimate.html` | Negative Case, legitime Website | ideal: keine oder nur Low Signal |
| 28 | `test28_NEGATIVE_newsletter.html` | Negative Case, Newsletter / Tracking | ideal: keine oder nur Tracking / Heuristik |
| 29 | `test29_NEGATIVE_safe_domain.html` | Negative Case, sichere externe Script Domains | ideal: keine oder nur Low Signal |
| 30 | `test30_ALL_IN_ONE_MAXIMUM.html` | Maximum Case mit mehreren Techniken kombiniert | viele kombiniert plus `combos`, Marker, `critical_boost` |

## Ziel der Suite

- Validierung der Symbol Abdeckung
- Identifikation von False Negatives
- Belastungstest der Kombinations Logik
- Regression Tests bei Lua Änderungen der Versionen 4.3.x
- Praxisnahe Prüfung von Attachment Vektoren und Active Content
- Prüfung der Negativfälle zur False Positive Kontrolle

## Ausführung

PowerShell

- Erstlauf: `./create_realistic_test_suite.ps1`
- Neu generieren oder überschreiben: `./create_realistic_test_suite.ps1 -Force`

Output Ordner: `HTML_Smuggling_TestSuite_v2`

## Erwartete Modul Abdeckung

- `JS_SMUGGLING`: Tests 01 bis 10
- `ATTACHMENT_VECTORS`: Tests 11 bis 19
- `CERT_SMUGGLING`: Tests 20 bis 22
- `IMAGE_SMUGGLING`: Tests 23 bis 24
- `CSS_CODE_EXEC`: Tests 25 bis 26
- `NEGATIVE TESTS`: Tests 27 bis 29
- `ALL IN ONE`: Test 30

## Scoring Logik, Kurz

Der Endscore setzt sich typischerweise zusammen aus

1. Raw Symbol Weights, zum Beispiel Decoder, APIs und `dec_*` Erkennung
2. Kombinations Logik, wenn typische Smuggling Ketten auftreten, zum Beispiel `atob` plus `Blob` plus `createObjectURL`
3. Critical Boost, wenn ein harter Payload oder ein klarer Container erkannt wird, zum Beispiel PE, LNK, HTA, CHM, aktives PDF oder WASM
4. Optionaler Min Score Floor
5. Zusatzheuristiken, zum Beispiel Reduktion bei Newsletter Mustern oder ungefährlichen Tracking Fällen
6. Modulspezifische Marker und Zusatzgründe je nach Lua Policy

## Interpretation der Resultate

- Ein Test gilt als fachlich bestanden, wenn die Kerntechnik sichtbar erkannt wird, auch wenn zusätzliche Symbole dazukommen.
- Bei Negativtests ist wenig bis kein Score das Ziel.
- Bei Maximum Tests ist nicht nur die Decoder Erkennung relevant, sondern vor allem die saubere Bündelung mehrerer Signale.

Version: Laboratory Edition v2.1  
Engine Target: Rspamd HTML Smuggling Detection v4.3.7a
