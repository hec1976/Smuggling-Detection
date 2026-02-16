# HTML Smuggling Test Suite -- Laboratory Cases

Diese Testsuite validiert die Rspamd HTML Smuggling Detection Suite
(v2.9-r1).

  -------------------------------------
  1\. AKTUELLE TESTFAELLE (ENTHALTEN)
  -------------------------------------

test1 Fokus: Blob Construction Erwartete Symbole: atob, blob,
createObjectURL, dec_pe

test2 Fokus: JS Obfuscation Erwartete Symbole: atob, array_index_api,
polymorphic_obfuscation

test3 Fokus: Drive-by / Meta Erwartete Symbole: iframe_src, data_uri,
eval_call, atob

test4 Fokus: Magic Byte Sniffing Erwartete Symbole: dec_pe, dec_zip,
dec_pdf, sniff_decoded

test5 Fokus: Async Workers Erwartete Symbole: webworker_api, blob,
uint8array

test6 Fokus: Windows Vectors Erwartete Symbole: ms_appinstaller_uri,
dec_lnk, dec_xml_appinstaller

test7 Fokus: Anti-Analysis Erwartete Symbole: delayed_execution,
high_entropy

test8 Fokus: DOM Manipulation Erwartete Symbole: fetch,
event_handler_api, dec_bin

test9 Fokus: Stealth / Unicode Erwartete Symbole: css_exfiltration, atob
(getarnt)

test10 Fokus: Advanced / All-in-One Erwartete Symbole: svg_onload,
wasm_uint8array, combo_hard

  -------------------------------------------------
  2\. GEPLANTE ERWEITERUNG (NOCH NICHT ENTHALTEN)
  -------------------------------------------------

test11 Fokus: External Stage Loader Erwartete Symbole:
script_src_external, fetch, blob, createObjectURL

test12 Fokus: WebCrypto AES Payload Erwartete Symbole: webcrypto_api,
aes_decrypt, uint8array, high_entropy

test13 Fokus: QR HTML Hybrid Erwartete Symbole: qr_canvas_or_svg,
event_handler_api, stealth_css

test14 Fokus: Service Worker Persistence Erwartete Symbole:
serviceworker_api, cache_api, persistence_behavior

test15 Fokus: OAuth / Device Code Lure Erwartete Symbole: oauth_lure,
device_code_flow, m365_brand_impersonation

------------------------------------------------------------------------

Version: Laboratory Edition v1.3 Engine Target: Rspamd HTML Smuggling
Detection v2.9-r1
