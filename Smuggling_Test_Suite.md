# HTML Smuggling Test Suite – Laboratory Cases

Diese Testsuite validiert die **Rspamd HTML Smuggling Detection Suite
(v3.1)**.

------------------------------------------------------------------------

##  Aktuelle Test-Matrix (ENTHALTEN)

| Test | Fokus-Technik | Erwartete Symbole | Erwarteter Score |
|------|---------------|-------------------|------------------|
| test01 | Basis atob + Blob + PE | atob, blob, createObjectURL, dec_pe | 15-20 |
| test02 | Split Payload (+= Concatenation) | atob, blob, createObjectURL, dec_pe | 20-25 |
| test03 | Array.join() Payload | atob, blob, createObjectURL, array_index_api | 20-25 |
| test04 | Polymorphe Obfuscation | atob, blob, polymorphic_obfuscation | 25-30 |
| test05 | ZIP Archive Smuggling | atob, blob, dec_zip | 12-18 |
| test06 | WebAssembly Module | atob, blob, wasm_uint8array | 15-20 |
| test07 | PDF Document Smuggling | atob, blob, dec_pdf | 4-8 |
| test08 | Web Worker + PE | webworker_api, blob, uint8array, atob | 18-24 |
| test09 | Delayed Execution (setTimeout) | delayed_execution, atob, blob | 20-26 |
| test10 | ms-appinstaller Schema | ms_appinstaller_uri, dec_xml_appinstaller | 8-12 |
| test11 | Iframe + data: URI | iframe_src, data_uri | 4-8 |
| test12 | External Script Loading | script_src_external | 1-3 |
| test13 | Fetch API + Blob | fetch, blob, createObjectURL | 16-22 |
| test14 | Canvas QR Code Lure | qr_canvas_or_svg, event_handler_api | 17-23 |
| test15 | ServiceWorker Persistence | serviceworker_api, cache_api | 18-24 |
| test16 | WebCrypto + PE | webcrypto_api, aes_decrypt, high_entropy | 17-23 |
| test17 | Uint8Array Direct | uint8array, blob, dec_pe | 20-28 |
| test18 | ALL-IN-ONE Maximum | alle Symbole kombiniert | 35-45 |
| test19 | NEGATIVE: Legitime Website | keine (heur_mul reduziert) | 0-2 |
| test20 | NEGATIVE: Newsletter | keine (Tracking only) | 0-1 |

---




## Ziel der Suite

-   Validierung der Symbol-Abdeckung  
-   Identifikation von False-Negatives  
-   Belastungstest der Kombinations-Logik  
-   Vorbereitung auf moderne Stage- und OAuth-basierte Angriffsmuster

------------------------------------------------------------------------

**Version:** Laboratory Edition v1.4  
**Engine Target:** Rspamd HTML Smuggling Detection v2.9-r1
