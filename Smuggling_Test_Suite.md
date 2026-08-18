# HTML Smuggling Detection v4.7.1 – Detaillierte Test-Suite 01–69

## v4.7.1 Bugfix

v4.7.1 behebt einen funktional relevanten Lua-Scope-Fehler im rekursiven JavaScript-Deep-Scan.

Der Forward-Declaration-Block enthält nun zusätzlich:

```lua
local scan_v47_script_risk_module
```

Die spätere Definition verwendet:

```lua
scan_v47_script_risk_module = function(ctx, script_raw)
```

Damit bindet `scan_decoded_script_blob()` den Aufruf an dasselbe lokale Closure und nicht an
eine globale, zur Laufzeit `nil` bleibende Variable.

## Regressionstest 69

**Datei:** `test69_v471_recursive_decoded_js_scope_regression.html`  
**Pfad:** Base64 → dekodiertes JS → `analyze_decoded_blob()` → `scan_decoded_script_blob()` → v4.7-Risk-Scanner  
**ExpectedDetection:** `YES`  
**ExpectedScore:** `8-15 capped`  
**ExpectedCoreReasons:** `dec_js,dynamic_import_data`  

Der Test ist absichtlich so aufgebaut, dass der v4.7-Risk-Scanner im **dekodierten JavaScript**
`dynamic_import_data` setzen muss. Mit dem alten Scope-Bug bricht dieser Pfad vorher ab.

Für einen Lua-/Mock-Unittest sollte zusätzlich geprüft werden:

```text
#ctx.errors == 0
ctx.reasons.dec_js == true
ctx.reasons.dynamic_import_data == true
```

## Gesamte Matrix

| Test | Datei | Kategorie | Detection | Score | Core Reasons | Info Reasons |
|---:|---|---|---|---|---|---|
| 01 | `test01_basic_pe_smuggling.html` | `JS_SMUGGLING` | `YES` | `8-10 group capped` | `atob,blob,createObjectURL,dec_pe` | `-` |
| 02 | `test02_split_payload_pe_fixed.html` | `JS_SMUGGLING` | `YES` | `8-10 group capped` | `split_payload,atob,blob,createObjectURL,dec_pe` | `-` |
| 03 | `test03_array_join_pe.html` | `JS_SMUGGLING` | `YES` | `8-10 group capped` | `atob,blob,createObjectURL,b64_joined_parts,dec_pe` | `-` |
| 04 | `test04_obfuscated_pe.html` | `OBFUSCATION` | `YES` | `8-10 group capped` | `atob_obfuscated or obfus_api,blob,createObjectURL,dec_pe` | `-` |
| 05 | `test05_wasm_smuggling.html` | `WASM_STAGING` | `YES` | `6-10` | `fetch,webassembly or wasm_fetch_stage` | `-` |
| 06 | `test06_uint8array_pe_large.html` | `UINT8ARRAY` | `YES` | `8-10 group capped` | `uint8array_payload,pe_uint8array` | `-` |
| 07 | `test07_delayed_execution_pe.html` | `JS_SMUGGLING` | `YES` | `8-10 group capped` | `delayed_execution,timeout_b64_smuggling or timeout_b64_decode,dec_pe` | `-` |
| 08 | `test08_webworker_pe.html` | `WEBWORKER` | `YES` | `8-10 group capped` | `webworker,atob,blob,createObjectURL,dec_pe` | `-` |
| 09 | `test09_fetch_api_pe.html` | `FETCH` | `YES` | `6-10` | `fetch,data_uri or blob,createObjectURL or dec_pe` | `-` |
| 10 | `test10_appinstaller_schema.html` | `APPINSTALLER` | `YES` | `4-8` | `ms_appinstaller_uri or ms_appinstaller_word` | `-` |
| 11 | `test11_pdf_javascript_payload.html` | `PDF_ACTIVE` | `YES` | `4-8` | `dec_pdf,att_pdf_javascript` | `-` |
| 12 | `test12_pdf_launch_payload.html` | `PDF_ACTIVE` | `YES` | `6-10` | `dec_pdf,att_pdf_launch,att_pdf_embeddedfile` | `-` |
| 13 | `test13_svg_active_content.html` | `SVG_ACTIVE` | `YES` | `8-10 group capped` | `att_svg_script,att_svg_event_handler,att_svg_foreignobject,att_svg_data_uri,att_svg_smuggling_context` | `-` |
| 14 | `test14_chm_payload.html` | `ATTACHMENT_VECTOR_DECODE` | `YES` | `6-10` | `att_chm_attachment or CHM decode indicator` | `-` |
| 15 | `test15_hta_payload.html` | `ATTACHMENT_VECTOR_DECODE` | `YES` | `8-10 group capped` | `att_hta_attachment or dec_script` | `-` |
| 16 | `test16_certificate_inline_pem.html` | `CERT_SMUGGLING` | `YES` | `2-5` | `cert_inline_pem or cert_base64_block` | `-` |
| 17 | `test17_certificate_pkcs7_inline.html` | `CERT_SMUGGLING` | `YES` | `2-5` | `cert_inline_pkcs or cert_base64_block` | `-` |
| 18 | `test18_certificate_smuggling_context.html` | `CERT_SMUGGLING` | `YES` | `4-8` | `cert_inline_pem or cert_base64_block plus Smuggling Kontext` | `-` |
| 19 | `test19_css_code_execution.html` | `CSS_CODE_EXEC` | `YES` | `4-8` | `css_before_after_content,css_hidden_code_string,css_function_bridge,css_code_execution` | `-` |
| 20 | `test20_css_computedstyle_exec.html` | `CSS_CODE_EXEC` | `YES` | `4-8` | `css_computedstyle_exec,css_function_bridge` | `-` |
| 21 | `test21_external_scripts_positive.html` | `EXTERNAL_SCRIPTS` | `YES` | `4-8` | `atob,external_scripts` | `-` |
| 22 | `test22_css_exfil_attr.html` | `CSS_EXFIL` | `YES` | `2-6` | `css_attr_exfil,css_exfiltration` | `-` |
| 23 | `test23_css_import_external.html` | `CSS_EXFIL` | `YES` | `0-3` | `css_import_external` | `-` |
| 24 | `test24_geo_targeting_api.html` | `GEO_TARGETING` | `YES` | `2-6` | `geo_targeting_api,geo_location_api` | `-` |
| 25 | `test25_timezone_targeting.html` | `GEO_TARGETING` | `YES` | `2-6` | `timezone_targeting` | `-` |
| 26 | `test26_evasion_webdriver.html` | `EVASION` | `YES` | `2-6` | `antisandbox_webdriver` | `-` |
| 27 | `test27_evasion_hardware_check.html` | `EVASION` | `YES` | `2-6` | `hardware_check_evasion` | `-` |
| 28 | `test28_persistence_localstorage.html` | `PERSISTENCE` | `YES` | `2-6` | `localstorage_persistence` | `-` |
| 29 | `test29_persistence_sessionstorage.html` | `PERSISTENCE` | `YES` | `2-6` | `sessionstorage_persistence` | `-` |
| 30 | `test30_domain_rotation.html` | `DOMAIN_ROTATION` | `YES` | `2-6` | `domain_rotation` | `-` |
| 31 | `test31_computed_redirect.html` | `DOMAIN_ROTATION` | `YES` | `2-6` | `computed_redirect` | `-` |
| 32 | `test32_clickfix_run_dialog.html` | `CLICKFIX` | `YES` | `2-6` | `run_dialog_lure,powershell_lure or clickfix_lure` | `-` |
| 33 | `test33_fake_captcha_clipboard.html` | `CLICKFIX` | `YES` | `2-6` | `fake_captcha_lure,clipboard_exec_lure,clickfix_lure` | `-` |
| 34 | `test34_push_abuse.html` | `PUSH_ABUSE` | `YES` | `0-3` | `push_permission_request,push_serviceworker_combo,push_notification_flow` | `-` |
| 35 | `test35_blockchain_staging.html` | `BLOCKCHAIN_STAGING` | `YES` | `2-6` | `web3_api_usage,ethers_contract_payload,blockchain_remote_stage or blockchain_staged_payload` | `-` |
| 36 | `test36_legitimate_negative.html` | `NEGATIVE` | `NO` | `0-1` | `none` | `-` |
| 37 | `test37_safe_external_negative.html` | `NEGATIVE` | `NO` | `0-2` | `none` | `-` |
| 38 | `test38_html_keyword_newsletter_like.html` | `NEWSLETTER_HTML_ONLY` | `LOW_OR_NONE` | `0-2` | `html_keyword newsletter heuristic only` | `-` |
| 39 | `test39_all_in_one_capped.html` | `ALL_IN_ONE` | `YES` | `10-15 internal capped` | `mehrere Klassen, intern gedeckelt` | `-` |
| 40 | `test40_svg_data_uri_pe_direct.html` | `SVG_ACTIVE` | `YES` | `8-10 group capped` | `att_svg_data_uri,att_svg_script,att_svg_event_handler,dec_pe` | `-` |
| 41 | `test41_v46_script_prescan_magic_late.html` | `V46_SCRIPT_PRESCAN` | `YES` | `10-15 capped` | `script_prescan_payload,b64_magic_prefix,dec_pe` | `-` |
| 42 | `test42_v46_script_prescan_budget.html` | `V46_BUDGET` | `YES` | `10-15 capped` | `script_prescan_payload,dec_pe` | `script_prescan_budget` |
| 43 | `test43_v46_uint8array_hex_pe.html` | `V46_UINT8ARRAY` | `YES` | `10-15 capped` | `uint8array_payload,pe_uint8array` | `-` |
| 44 | `test44_v46_nested_base64_pe.html` | `V46_RECURSIVE_DECODE` | `YES` | `10-15 capped` | `nested_base64_payload,dec_pe` | `-` |
| 45 | `test45_v46_gzip_magic_payload.html` | `V46_COMPRESSED` | `YES` | `6-10` | `dec_compressed` | `-` |
| 46 | `test46_v46_zip_executable_member.html` | `V46_ZIP` | `YES` | `8-15 capped` | `dec_zip,zip_executable_member` | `-` |
| 47 | `test47_v46_zip_script_member.html` | `V46_ZIP` | `YES` | `8-15 capped` | `dec_zip,zip_script_member` | `-` |
| 48 | `test48_v46_zip_double_extension.html` | `V46_ZIP` | `YES` | `8-15 capped` | `dec_zip,zip_executable_member,zip_double_extension` | `-` |
| 49 | `test49_v46_zip_path_traversal.html` | `V46_ZIP` | `YES` | `8-15 capped` | `dec_zip,zip_script_member,zip_path_traversal` | `-` |
| 50 | `test50_v46_zip_nested_archive.html` | `V46_ZIP` | `YES` | `6-12` | `dec_zip,zip_nested_archive` | `-` |
| 51 | `test51_v46_zip_high_ratio.html` | `V46_ZIP_INFO` | `YES` | `4-10` | `dec_zip` | `zip_high_compression_ratio` |
| 52 | `test52_v46_zip_stored_pe.html` | `V46_ZIP_STORED` | `YES` | `10-15 capped` | `dec_zip,zip_stored_payload,dec_pe` | `-` |
| 53 | `test53_v46_zip_encrypted_flag.html` | `V46_ZIP` | `YES` | `6-12` | `dec_zip,zip_encrypted` | `-` |
| 54 | `test54_v46_zip_many_entries.html` | `V46_ZIP_INFO` | `YES` | `4-10` | `dec_zip` | `zip_many_entries` |
| 55 | `test55_v46_xor_constant_pe.html` | `V46_CRYPTO` | `YES` | `10-15 capped` | `xor_constant_payload,dec_pe` | `-` |
| 56 | `test56_v46_rc4_constant_pe.html` | `V46_CRYPTO` | `YES` | `10-15 capped` | `rc4_constant_payload,dec_pe` | `-` |
| 57 | `test57_v47_dom_dynamic_sink.html` | `V47_DOM` | `YES` | `4-8` | `dom_dynamic_sink,atob` | `-` |
| 58 | `test58_v47_dynamic_import_data.html` | `V47_DYNAMIC_IMPORT` | `YES` | `7-15 capped` | `dynamic_import_data` | `-` |
| 59 | `test59_v47_worker_blob_reconstruction.html` | `V47_WORKER` | `YES` | `4-10` | `worker_blob_stage,worker_inline_script,webworker` | `-` |
| 60 | `test60_v47_serviceworker_broad_scope.html` | `V47_SERVICEWORKER` | `YES` | `3-8` | `serviceworker_register,serviceworker_broad_scope,serviceworker_api` | `-` |
| 61 | `test61_v47_websocket_portscan.html` | `V47_EVASION` | `YES` | `3-8` | `websocket_portscan` | `-` |
| 62 | `test62_v47_jsfuck_obfuscation.html` | `V47_OBFUSCATION` | `YES` | `2-6` | `jsfuck_obfuscation` | `-` |
| 63 | `test63_v47_unicode_escape_payload.html` | `V47_OBFUSCATION` | `YES` | `3-8` | `unicode_escape_payload,obfus_api` | `-` |
| 64 | `test64_v47_template_literal_obfuscation.html` | `V47_OBFUSCATION` | `YES` | `2-6` | `template_literal_obfuscation,eval_call` | `-` |
| 65 | `test65_v47_zip_comment_payload.html` | `V47_ZIP` | `YES` | `8-15 capped` | `dec_zip,zip_comment_payload,dec_pe` | `-` |
| 66 | `test66_v47_zip_high_entropy_stored.html` | `V47_ZIP_INFO` | `YES` | `4-10` | `dec_zip` | `zip_high_entropy_member` |
| 67 | `test67_v47_nested_stored_zip_pe.html` | `V47_ZIP_RECURSION` | `YES` | `10-15 capped` | `dec_zip,zip_nested_archive,zip_stored_payload,dec_pe` | `-` |
| 68 | `test68_v47_sharedarraybuffer_timing.html` | `V47_EVASION` | `YES` | `3-8` | `sharedarraybuffer_timing` | `-` |
| 69 | `test69_v471_recursive_decoded_js_scope_regression.html` | `V471_RECURSIVE_JS_REGRESSION` | `YES` | `8-15 capped` | `dec_js,dynamic_import_data` | `-` |
