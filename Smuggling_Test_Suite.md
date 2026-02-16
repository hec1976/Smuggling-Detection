# HTML Smuggling Test Suite – Laboratory Cases

Diese Testsuite validiert die **Rspamd HTML Smuggling Detection Suite
(v2.9-r1)**.

------------------------------------------------------------------------

##  Aktuelle Test-Matrix (ENTHALTEN)

| Test   | Fokus-Technik         | Erwartete Symbole                                  |
|--------|-----------------------|----------------------------------------------------|
| test1  | Blob Construction     | atob, blob, createObjectURL, dec_pe                |
| test2  | JS Obfuscation        | atob, array_index_api, polymorphic_obfuscation     |
| test3  | Drive-by / Meta       | iframe_src, data_uri, eval_call, atob              |
| test4  | Magic Byte Sniffing   | dec_pe, dec_zip, dec_pdf, sniff_decoded            |
| test5  | Async Workers         | webworker_api, blob, uint8array                    |
| test6  | Windows Vectors       | ms_appinstaller_uri, dec_lnk, dec_xml_appinstaller |
| test7  | Anti-Analysis         | delayed_execution, high_entropy                    |
| test8  | DOM Manipulation      | fetch, event_handler_api, dec_bin                  |
| test9  | Stealth / Unicode     | css_exfiltration, atob (getarnt)                   |
| test10 | Advanced / All-in-One | svg_onload, wasm_uint8array, combo_hard            |
| test11 | External Stage Loader      | script_src_external, fetch, blob, createObjectURL      |
| test12 | WebCrypto AES Payload      | webcrypto_api, aes_decrypt, uint8array, high_entropy   |
| test13 | QR HTML Hybrid             | qr_canvas_or_svg, event_handler_api, stealth_css       |
| test14 | Service Worker Persistence | serviceworker_api, cache_api, persistence_behavior     |
| test15 | OAuth / Device Code Lure   | oauth_lure, device_code_flow, m365_brand_impersonation |

------------------------------------------------------------------------


## Ziel der Suite

-   Validierung der Symbol-Abdeckung  
-   Identifikation von False-Negatives  
-   Belastungstest der Kombinations-Logik  
-   Vorbereitung auf moderne Stage- und OAuth-basierte Angriffsmuster

------------------------------------------------------------------------

**Version:** Laboratory Edition v1.4  
**Engine Target:** Rspamd HTML Smuggling Detection v2.9-r1
