-- /etc/rspamd/lua.local.d/html_smuggling.lua
-- HTML Smuggling Detection v4.3.7c-r3
--
-- Erweiterungen gegenueber v4.3.6d:
--   15. attachment_vectors Modul fuer Non HTML und Attachment Vektoren
--   16. certificate_smuggling Modul fuer PEM, PKCS und Zertifikatscontainer im Kontext
--   17. image_smuggling_info Modul als optionales Info Only Modul fuer Bild Missbrauchsindikatoren
--   18. Attachment Pfad fuer PDF, SVG, CHM, HTA, OneNote, Office Macro Container, Script Dateien
--   19. PDF Active Content Erkennung fuer /JavaScript, /OpenAction, /Launch, /EmbeddedFile, /RichMedia
--   20. SVG Active Content Erkennung fuer <script>, onload, foreignObject, xlink:href, data URIs
--   21. Zertifikats Container und Inline PEM Erkennung mit FP armer Kontextlogik
--
-- Fixes gegenueber v4.3.7:
--   22. soft_only_cap wird korrekt aus CFG.soft_only_cap gelesen
--   23. is_safe_script_domain() ergaenzt fuer external_scripts Pfad
--   24. cert_inline_pkcs wird in HTML und Script Kontext korrekt gesetzt
--   25. Version und Description auf 4.3.7a angehoben
--
-- Fixes gegenueber v4.3.7a und v4.3.7b in v4.3.7c-r3:
--   26. Array-Join-Resolver in advanced_deobfuscate bleibt aktiv fuer var x=["f1","f2",...]; x.join('')
--   27. Kleine Labor und Stager Payloads werden wieder decodiert, min_decode_total Standard auf 400 gesenkt
--   28. detect_split_payload erkennt jetzt auch Array-Join Konstrukte robust
--   29. scan_decoded_payload_module nutzt ein explizites min_decode_total Fallback von 400
--   30. Join-Pattern zaehlt fuer Marker und Summary konsistent auch bei wenigen Fragmenten
--
-- Design:
--   Die Struktur bleibt nah an v4.3.6d.
--   HTML bleibt der Hauptpfad.
--   Neue Attachment und Zertifikats Scanner ergaenzen den bestehenden Flow.
--   Image Smuggling bleibt standardmaessig info_only.

local rspamd_logger = require "rspamd_logger"
local rspamd_util   = require "rspamd_util"
local VERSION = "4.3.7c-r3"

-- =========================
-- Config lesen
-- =========================
local CFG = rspamd_config:get_all_opt("html_smuggling") or {}
local ENABLED   = (CFG.enabled ~= false)
local DEBUG     = (CFG.debug == true)
local TEST_MODE = (CFG.test_mode == true)
local LOG_SCORE_THRESHOLD          = tonumber(CFG.log_score_threshold) or 5.0
local LOG_SIMPLE_LINE              = (CFG.log_simple_line == true)
local SCORE_DEBUG                  = (CFG.score_debug == true)
local FORCE_EXTENDED_LOG           = (CFG.force_extended_log == true)
local FORCE_EXTENDED_LOG_MIN_SCORE = tonumber(CFG.force_extended_log_min_score) or 5.0
local SLOW_LOG_MS                  = tonumber(CFG.slow_log_ms) or 150.0
local DEEP_SCAN_NEWSLETTER_HEADER  = (CFG.deep_scan_newsletter_header ~= false)
local MIN_SCORE      = tonumber(CFG.min_score) or 0.0
local CRITICAL_BOOST = tonumber(CFG.critical_boost) or 0.0
local MAX_FINAL_SCORE                     = tonumber(CFG.max_final_score) or 15.0
local REDACT_LOG_FIELDS                   = (CFG.redact_log_fields ~= false)
local REQUIRE_SCRIPT_CONTEXT_FOR_EXTERNAL = (CFG.require_script_context_for_external ~= false)
local REQUIRE_STRONG_GATE_FOR_DECODE      = (CFG.require_strong_gate_for_decode ~= false)
local MAX_EXTERNAL_REPORTED               = tonumber(CFG.max_external_reported) or 3
local SOFT_ONLY_SCORE_CAP                 = tonumber(CFG.soft_only_cap or CFG.soft_only_score_cap) or 4.5
local HEUR_MUL_DEFAULT            = tonumber(CFG.heur_mul_default) or 1.0
local HEUR_MUL_NEWSLETTER_HEADER  = tonumber(CFG.heur_mul_newsletter_header) or 0.3
local HEUR_MUL_NEWSLETTER_HEUR    = tonumber(CFG.heur_mul_newsletter_heuristic) or 0.4
local HEUR_MUL_TRUSTED_NEWSLETTER = tonumber(CFG.heur_mul_trusted_newsletter) or 0.1
local HARD_FAIL_ON_BAD_CONFIG   = (CFG.hard_fail_on_bad_config == true)
local ENABLE_PHASE_DEBUG        = (CFG.enable_phase_debug == true)
local SAFE_TASK_ACCESS          = (CFG.safe_task_access ~= false)
local SAFE_PART_ACCESS          = (CFG.safe_part_access ~= false)
local LOG_CONFIG_VALIDATION     = (CFG.log_config_validation ~= false)
local STRICT_WEIGHT_VALIDATION  = (CFG.strict_weight_validation == true)
local RUNTIME_MAX_FINAL_SCORE = MAX_FINAL_SCORE
local RUNTIME_SOFT_ONLY_CAP   = SOFT_ONLY_SCORE_CAP
local RUNTIME_MIN_SCORE       = MIN_SCORE
local RUNTIME_CRITICAL_BOOST  = CRITICAL_BOOST

-- =========================
-- Limits
-- =========================
local LIMITS = {
  scan = {
    max_bytes               = 200 * 1024,
    smart_chunk             = 50 * 1024,
    long_html_b64_threshold = 1200,
    max_attachment_text     = 300 * 1024,
  },
  b64 = {
    min_len          = 200,
    max_candidates   = 6,
    max_scan_bytes   = 500 * 1024,
    min_decode_total = 400,
    big_threshold    = 5000,
    huge_threshold   = 20000,
    join_max_parts   = 5,
    join_max_len     = 180000,
  },
  decode = {
    max_bytes      = 160 * 1024,
    joined_len_mul = 2,
  },
  script = {
    max_check              = 3,
    max_external           = 5,
    max_vars               = 20,
    smart_chunk            = 20000,
    max_script_len         = 80000,
    max_total_script_scan  = 120000,
    max_script_time_ms     = 80.0,
    deobfus_timeout_ms     = 50.0,
    split_payload_min_vars = 6,
  },
  obfus = {
    min_frag_len             = 4,
    virtual_trigger_len      = 120,
    virtual_max_payloads     = 3,
    resolve_passes           = 8,
    max_uint8array_bytes     = 2048,
    max_entropy_check_bytes  = 4096,
    css_max_style_size       = 10000,
    max_delayed_exec_context = 500,
  }
}

-- =========================
-- Thresholds
-- =========================
local THRESHOLDS = {
  entropy_high               = 4.5,
  entropy_very_high          = 5.0,
  hex_var_low                = 2,
  hex_var_high               = 5,
  array_storage_low          = 1,
  array_storage_high         = 3,
  uint8array_large_min       = 1024,
  deobfus_reduce_len_1       = 20000,
  deobfus_reduce_len_2       = 40000,
  b64_extract_loop_budget_ms = 25.0,
  script_min_len             = 20,
  normalized_script_min_len  = 40,
  delayed_exec_context       = 500,
}

-- =========================
-- Weights
-- =========================
local W = {
  JS_SMUGGLING       = 1.2,
  OBFUSCATION        = 2.5,
  SUSPICIOUS_API     = 0.8,
  EVASION_LOGIC      = 1.5,
  CONTAINER          = 6.0,
  SCRIPT_HARD        = 7.0,
  CRITICAL           = 12.0,
  COMBO_JS_OBFUS     = 1.5,
  COMBO_HARD_OBFUS   = 2.0,
  COMBO_JS_API       = 0.8,
  COMBO_JS_EVASION   = 0.7,
  EXTERNAL_SCRIPT    = 1.0,
  CSS_EXFIL          = 2.0,
  GEO_TARGETING      = 0.8,
  ROTATION_BONUS     = 1.0,
  CLICKFIX_LURE      = 1.2,
  WASM_STAGING       = 1.4,
  BLOCKCHAIN_STAGING = 1.2,
  CSS_CODE_EXEC      = 1.5,
  ATTACHMENT_VECTOR  = 1.4,
  CERT_SMUGGLING     = 1.1,
  IMAGE_SMUGGLING    = 0.7,
}

-- =========================
-- Modul Matrix
-- =========================
local DEFAULT_MODULES = {
  appinstaller = { enabled = true, info_only = false, weight_override = nil },
  js_smuggling = { enabled = true, info_only = false, weight_override = nil },
  obfuscation  = { enabled = true, info_only = false, weight_override = nil },
  decoded_payload = { enabled = true, info_only = false, weight_override = nil },
  uint8array   = { enabled = true, info_only = false, weight_override = nil },
  external_scripts = { enabled = true, info_only = false, weight_override = nil },
  css_exfil    = { enabled = true, info_only = false, weight_override = nil },
  geo_targeting = { enabled = true, info_only = false, weight_override = nil },
  evasion      = { enabled = true, info_only = false, weight_override = nil },
  persistence  = { enabled = true, info_only = false, weight_override = nil },
  domain_rotation = { enabled = true, info_only = false, weight_override = nil },
  clickfix     = { enabled = true, info_only = false, weight_override = nil },
  wasm_staging = { enabled = true, info_only = false, weight_override = nil },
  blockchain_staging = { enabled = true, info_only = false, weight_override = nil },
  css_code_execution = { enabled = true, info_only = false, weight_override = nil },
  attachment_vectors = { enabled = true, info_only = false, weight_override = nil },
  certificate_smuggling = { enabled = true, info_only = false, weight_override = nil },
  image_smuggling_info = { enabled = false, info_only = true, weight_override = nil },
  push_abuse   = { enabled = true, info_only = true,  weight_override = nil },
  link_analysis        = { enabled = false, info_only = true,  weight_override = nil },
  wasm_binary_analysis = { enabled = false, info_only = false, weight_override = nil },
  rc4_detection        = { enabled = false, info_only = false, weight_override = nil },
}

-- =========================
-- Reason -> Modul Mapping
-- =========================
local REASON_MODULE_MAP = {
  ms_appinstaller_uri     = "appinstaller",
  ms_appinstaller_word    = "appinstaller",
  appinstaller_file       = "appinstaller",
  dec_xml_appinstaller    = "appinstaller",

  atob                    = "js_smuggling",
  blob                    = "js_smuggling",
  createObjectURL         = "js_smuggling",
  fetch                   = "js_smuggling",
  filereader              = "js_smuggling",
  uint8array              = "js_smuggling",
  split_payload           = "js_smuggling",
  delayed_execution       = "js_smuggling",
  timeout_b64_smuggling   = "js_smuggling",
  timeout_b64_decode      = "js_smuggling",
  timeout_b64             = "js_smuggling",
  dom_clobbering          = "js_smuggling",
  data_uri                = "js_smuggling",
  iframe_src              = "js_smuggling",
  b64_long_html           = "js_smuggling",
  b64_total_len_big       = "js_smuggling",
  b64_total_len_huge      = "js_smuggling",
  b64_joined_parts        = "js_smuggling",
  virtual_b64_candidates  = "js_smuggling",
  array_index_atob        = "js_smuggling",
  array_index_blob        = "js_smuggling",
  array_index_fetch       = "js_smuggling",
  settimeout_call         = "js_smuggling",
  setinterval_call        = "js_smuggling",
  event_handler_api       = "js_smuggling",
  computed_redirect       = "js_smuggling",
  dec_js                  = "js_smuggling",
  dec_html                = "js_smuggling",
  dec_pdf                 = "js_smuggling",
  dec_xml                 = "js_smuggling",
  dec_bin                 = "js_smuggling",
  webcrypto_api           = "js_smuggling",
  serviceworker_api       = "js_smuggling",
  webworker               = "js_smuggling",
  webassembly             = "js_smuggling",
  qr_canvas_api           = "js_smuggling",

  obfus_api               = "obfuscation",
  atob_obfuscated         = "obfuscation",
  hex_array               = "obfuscation",
  array_join_concat       = "obfuscation",
  bracket_atob            = "obfuscation",
  fromcharcode_api        = "obfuscation",
  fromcharcode_heavy      = "obfuscation",
  function_constructor    = "obfuscation",
  eval_call               = "obfuscation",
  polymorphic_obfuscation = "obfuscation",
  hex_var_names           = "obfuscation",
  hex_vars                = "obfuscation",
  very_high_entropy       = "obfuscation",
  high_entropy            = "obfuscation",
  array_string_storage    = "obfuscation",
  array_storage           = "obfuscation",
  func_obfuscation        = "obfuscation",

  dec_pe               = "decoded_payload",
  dec_wasm             = "decoded_payload",
  dec_msix             = "decoded_payload",
  dec_appx             = "decoded_payload",
  dec_zip              = "decoded_payload",
  dec_iso              = "decoded_payload",
  dec_lnk              = "decoded_payload",
  dec_rar              = "decoded_payload",
  dec_7zip             = "decoded_payload",
  dec_cab              = "decoded_payload",
  dec_vhdx             = "decoded_payload",
  dec_ole              = "decoded_payload",
  dec_script           = "decoded_payload",

  uint8array_payload   = "uint8array",
  large_uint8array     = "uint8array",
  pdf_uint8array       = "uint8array",
  pe_uint8array        = "uint8array",
  wasm_uint8array      = "uint8array",
  zip_uint8array       = "uint8array",

  external_scripts     = "external_scripts",

  css_exfiltration     = "css_exfil",
  css_import_external  = "css_exfil",
  css_attr_exfil       = "css_exfil",
  css_large_b64        = "css_exfil",

  geo_targeting_api    = "geo_targeting",
  geo_location_api     = "geo_targeting",
  timezone_targeting   = "geo_targeting",

  antisandbox_webdriver      = "evasion",
  hardware_check_evasion     = "evasion",
  human_interaction_required = "evasion",

  localstorage_persistence   = "persistence",
  sessionstorage_persistence = "persistence",

  domain_rotation      = "domain_rotation",

  clickfix_lure        = "clickfix",
  fake_captcha_lure    = "clickfix",
  clipboard_exec_lure  = "clickfix",
  run_dialog_lure      = "clickfix",
  powershell_lure      = "clickfix",

  wasm_staged_payload     = "wasm_staging",
  wasm_fetch_stage        = "wasm_staging",
  wasm_inline_stage       = "wasm_staging",
  wasm_eval_bridge        = "wasm_staging",
  wasm_worker_stage       = "wasm_staging",
  wasm_suspicious_exports = "wasm_staging",

  blockchain_staged_payload = "blockchain_staging",
  web3_api_usage           = "blockchain_staging",
  ethers_contract_payload  = "blockchain_staging",
  web3_eth_call            = "blockchain_staging",
  blockchain_eval_bridge   = "blockchain_staging",
  blockchain_remote_stage  = "blockchain_staging",

  css_code_execution       = "css_code_execution",
  css_before_after_content = "css_code_execution",
  css_computedstyle_exec   = "css_code_execution",
  css_hidden_code_string   = "css_code_execution",
  css_function_bridge      = "css_code_execution",

  push_notification_flow   = "push_abuse",
  push_permission_request  = "push_abuse",
  push_serviceworker_combo = "push_abuse",

  rc4_ksa_pattern          = "rc4_detection",
  rc4_prga_pattern         = "rc4_detection",
  rc4_xor_loop             = "rc4_detection",
  rc4_decrypt_call         = "rc4_detection",
  rc4_key_material         = "rc4_detection",

  att_pdf_javascript          = "attachment_vectors",
  att_pdf_openaction          = "attachment_vectors",
  att_pdf_launch              = "attachment_vectors",
  att_pdf_embeddedfile        = "attachment_vectors",
  att_pdf_richmedia           = "attachment_vectors",
  att_svg_script              = "attachment_vectors",
  att_svg_event_handler       = "attachment_vectors",
  att_svg_foreignobject       = "attachment_vectors",
  att_svg_xlink_href          = "attachment_vectors",
  att_svg_data_uri            = "attachment_vectors",
  att_chm_attachment          = "attachment_vectors",
  att_hta_attachment          = "attachment_vectors",
  att_onenote_attachment      = "attachment_vectors",
  att_office_macro_container  = "attachment_vectors",
  att_lnk_attachment          = "attachment_vectors",
  att_script_attachment       = "attachment_vectors",
  att_html_attachment         = "attachment_vectors",
  att_svg_smuggling_context   = "attachment_vectors",

  cert_inline_pem             = "certificate_smuggling",
  cert_inline_pkcs            = "certificate_smuggling",
  cert_attachment_file        = "certificate_smuggling",
  cert_data_uri               = "certificate_smuggling",
  cert_base64_block           = "certificate_smuggling",

  image_polyglot_name         = "image_smuggling_info",
  image_embedded_payload_hint = "image_smuggling_info",
  image_double_ext            = "image_smuggling_info",
}

-- =========================
-- Reason Policy
-- =========================
local DEFAULT_REASON_POLICY = {
  dec_pe               = { class = "CRITICAL" },
  dec_wasm             = { class = "CRITICAL" },
  dec_msix             = { class = "CRITICAL" },
  dec_appx             = { class = "CRITICAL" },
  dec_xml_appinstaller = { class = "CRITICAL" },
  ms_appinstaller_uri  = { class = "CRITICAL" },
  pe_uint8array        = { class = "CRITICAL" },
  wasm_uint8array      = { class = "CRITICAL" },
  att_chm_attachment   = { class = "CONTAINER" },
  att_onenote_attachment = { class = "CONTAINER" },
  att_lnk_attachment   = { class = "CONTAINER" },
  att_office_macro_container = { class = "CONTAINER" },

  dec_zip              = { class = "CONTAINER" },
  dec_iso              = { class = "CONTAINER" },
  dec_lnk              = { class = "CONTAINER" },
  dec_rar              = { class = "CONTAINER" },
  dec_7zip             = { class = "CONTAINER" },
  dec_cab              = { class = "CONTAINER" },
  dec_vhdx             = { class = "CONTAINER" },
  dec_ole              = { class = "CONTAINER" },
  zip_uint8array       = { class = "CONTAINER" },

  dec_script           = { class = "SCRIPT_HARD" },
  att_hta_attachment   = { class = "SCRIPT_HARD" },
  att_script_attachment = { class = "SCRIPT_HARD" },

  obfus_api               = { class = "OBFUSCATION" },
  atob_obfuscated         = { class = "OBFUSCATION" },
  hex_array               = { class = "OBFUSCATION" },
  array_join_concat       = { class = "OBFUSCATION" },
  bracket_atob            = { class = "OBFUSCATION" },
  fromcharcode_api        = { class = "OBFUSCATION" },
  fromcharcode_heavy      = { class = "OBFUSCATION" },
  function_constructor    = { class = "OBFUSCATION" },
  eval_call               = { class = "OBFUSCATION" },
  polymorphic_obfuscation = { class = "OBFUSCATION" },
  hex_var_names           = { class = "OBFUSCATION" },
  hex_vars                = { class = "OBFUSCATION" },
  very_high_entropy       = { class = "OBFUSCATION" },
  high_entropy            = { class = "OBFUSCATION" },
  array_string_storage    = { class = "OBFUSCATION" },
  array_storage           = { class = "OBFUSCATION" },
  func_obfuscation        = { class = "OBFUSCATION" },
  wasm_eval_bridge        = { class = "OBFUSCATION" },
  blockchain_eval_bridge  = { class = "OBFUSCATION" },
  css_code_execution      = { class = "OBFUSCATION" },
  css_computedstyle_exec  = { class = "OBFUSCATION" },
  css_hidden_code_string  = { class = "OBFUSCATION" },
  css_function_bridge     = { class = "OBFUSCATION" },
  rc4_ksa_pattern         = { class = "OBFUSCATION" },
  rc4_prga_pattern        = { class = "OBFUSCATION" },
  rc4_xor_loop            = { class = "OBFUSCATION" },
  rc4_decrypt_call        = { class = "OBFUSCATION" },
  rc4_key_material        = { class = "OBFUSCATION" },

  webcrypto_api              = { class = "SUSPICIOUS_API" },
  serviceworker_api          = { class = "SUSPICIOUS_API" },
  webworker                  = { class = "SUSPICIOUS_API" },
  webassembly                = { class = "SUSPICIOUS_API" },
  qr_canvas_api              = { class = "SUSPICIOUS_API" },
  geo_targeting_api          = { class = "SUSPICIOUS_API" },
  geo_location_api           = { class = "SUSPICIOUS_API" },
  localstorage_persistence   = { class = "SUSPICIOUS_API" },
  sessionstorage_persistence = { class = "SUSPICIOUS_API" },
  wasm_staged_payload        = { class = "SUSPICIOUS_API" },
  wasm_fetch_stage           = { class = "SUSPICIOUS_API" },
  wasm_inline_stage          = { class = "SUSPICIOUS_API" },
  wasm_worker_stage          = { class = "SUSPICIOUS_API" },
  blockchain_staged_payload  = { class = "SUSPICIOUS_API" },
  web3_api_usage             = { class = "SUSPICIOUS_API" },
  ethers_contract_payload    = { class = "SUSPICIOUS_API" },
  web3_eth_call              = { class = "SUSPICIOUS_API" },
  att_pdf_javascript         = { class = "SUSPICIOUS_API" },
  att_pdf_openaction         = { class = "SUSPICIOUS_API" },
  att_pdf_launch             = { class = "SUSPICIOUS_API" },
  att_pdf_embeddedfile       = { class = "SUSPICIOUS_API" },
  att_pdf_richmedia          = { class = "SUSPICIOUS_API" },
  att_svg_script             = { class = "SUSPICIOUS_API" },
  att_svg_event_handler      = { class = "SUSPICIOUS_API" },
  att_svg_foreignobject      = { class = "SUSPICIOUS_API" },
  att_svg_xlink_href         = { class = "SUSPICIOUS_API" },
  att_svg_data_uri           = { class = "SUSPICIOUS_API" },

  antisandbox_webdriver      = { class = "EVASION" },
  hardware_check_evasion     = { class = "EVASION" },
  human_interaction_required = { class = "BONUS_SOFT", bonus_module = "evasion" },

  atob                    = { class = "JS_SMUGGLING" },
  blob                    = { class = "JS_SMUGGLING" },
  createObjectURL         = { class = "JS_SMUGGLING" },
  fetch                   = { class = "JS_SMUGGLING" },
  filereader              = { class = "JS_SMUGGLING" },
  uint8array              = { class = "JS_SMUGGLING" },
  uint8array_payload      = { class = "JS_SMUGGLING" },
  large_uint8array        = { class = "JS_SMUGGLING" },
  pdf_uint8array          = { class = "JS_SMUGGLING" },
  split_payload           = { class = "JS_SMUGGLING" },
  delayed_execution       = { class = "JS_SMUGGLING" },
  timeout_b64_smuggling   = { class = "JS_SMUGGLING" },
  timeout_b64_decode      = { class = "JS_SMUGGLING" },
  timeout_b64             = { class = "JS_SMUGGLING" },
  dom_clobbering          = { class = "JS_SMUGGLING" },
  data_uri                = { class = "JS_SMUGGLING" },
  iframe_src              = { class = "JS_SMUGGLING" },
  b64_long_html           = { class = "JS_SMUGGLING" },
  b64_total_len_big       = { class = "JS_SMUGGLING" },
  b64_total_len_huge      = { class = "JS_SMUGGLING" },
  b64_joined_parts        = { class = "JS_SMUGGLING" },
  virtual_b64_candidates  = { class = "JS_SMUGGLING" },
  array_index_atob        = { class = "JS_SMUGGLING" },
  array_index_blob        = { class = "JS_SMUGGLING" },
  array_index_fetch       = { class = "JS_SMUGGLING" },
  settimeout_call         = { class = "JS_SMUGGLING" },
  setinterval_call        = { class = "JS_SMUGGLING" },
  event_handler_api       = { class = "JS_SMUGGLING" },
  appinstaller_file       = { class = "JS_SMUGGLING" },
  ms_appinstaller_word    = { class = "JS_SMUGGLING" },
  dec_js                  = { class = "JS_SMUGGLING" },
  dec_html                = { class = "JS_SMUGGLING" },
  dec_pdf                 = { class = "JS_SMUGGLING" },
  dec_xml                 = { class = "JS_SMUGGLING" },
  dec_bin                 = { class = "JS_SMUGGLING" },
  computed_redirect       = { class = "JS_SMUGGLING" },
  att_html_attachment     = { class = "JS_SMUGGLING" },
  att_svg_smuggling_context = { class = "JS_SMUGGLING" },

  timezone_targeting      = { class = "BONUS_SOFT", bonus_module = "geo_targeting" },
  domain_rotation         = { class = "BONUS_SOFT", bonus_module = "domain_rotation" },
  external_scripts        = { class = "BONUS_SOFT", bonus_module = "external_scripts" },
  css_exfiltration        = { class = "BONUS_SOFT", bonus_module = "css_exfil" },
  clickfix_lure           = { class = "BONUS_SOFT", bonus_module = "clickfix" },
  fake_captcha_lure       = { class = "BONUS_SOFT", bonus_module = "clickfix" },
  clipboard_exec_lure     = { class = "BONUS_SOFT", bonus_module = "clickfix" },
  run_dialog_lure         = { class = "BONUS_SOFT", bonus_module = "clickfix" },
  powershell_lure         = { class = "BONUS_SOFT", bonus_module = "clickfix" },
  wasm_suspicious_exports = { class = "BONUS_SOFT", bonus_module = "wasm_staging" },
  blockchain_remote_stage = { class = "BONUS_SOFT", bonus_module = "blockchain_staging" },
  css_before_after_content = { class = "BONUS_SOFT", bonus_module = "css_code_execution" },
  cert_inline_pem         = { class = "BONUS_SOFT", bonus_module = "certificate_smuggling" },
  cert_inline_pkcs        = { class = "BONUS_SOFT", bonus_module = "certificate_smuggling" },
  cert_data_uri           = { class = "BONUS_SOFT", bonus_module = "certificate_smuggling" },
  cert_base64_block       = { class = "BONUS_SOFT", bonus_module = "certificate_smuggling" },

  css_import_external      = { class = "BONUS_INFO" },
  css_attr_exfil           = { class = "BONUS_INFO" },
  css_large_b64            = { class = "BONUS_INFO" },
  push_notification_flow   = { class = "BONUS_INFO" },
  push_permission_request  = { class = "BONUS_INFO" },
  push_serviceworker_combo = { class = "BONUS_INFO" },
  cert_attachment_file     = { class = "BONUS_INFO" },
  image_polyglot_name      = { class = "BONUS_INFO" },
  image_embedded_payload_hint = { class = "BONUS_INFO" },
  image_double_ext         = { class = "BONUS_INFO" },

  script_time_budget            = { class = "INFO" },
  script_total_budget           = { class = "INFO" },
  deobfus_timeout               = { class = "INFO" },
  decode_gate_not_strong_enough = { class = "INFO" },
  soft_only_cap                 = { class = "INFO" },
  max_final_score               = { class = "INFO" },
  min_score                     = { class = "INFO" },
  critical_boost                = { class = "INFO" },
  single_sniff_pe               = { class = "INFO" },
}

-- =========================
-- Merge Helpers
-- =========================
local function merge_numbers(dst, src)
  if type(dst) ~= "table" or type(src) ~= "table" then return end
  for k, v in pairs(src) do
    local n = tonumber(v)
    if n ~= nil and dst[k] ~= nil then dst[k] = n end
  end
end

local function validate_positive(val, default, min_val)
  local n = tonumber(val)
  local minv = tonumber(min_val) or 0
  if not n or n < minv then return default end
  return n
end

local function merge_numbers_deep_valid(dst, src, min_val)
  if type(dst) ~= "table" or type(src) ~= "table" then return end
  for k, v in pairs(src) do
    if type(v) == "table" and type(dst[k]) == "table" then
      merge_numbers_deep_valid(dst[k], v, min_val)
    else
      if dst[k] ~= nil then dst[k] = validate_positive(v, dst[k], min_val) end
    end
  end
end

local function deep_copy_table(src)
  local out = {}
  for k, v in pairs(src or {}) do
    if type(v) == "table" then out[k] = deep_copy_table(v) else out[k] = v end
  end
  return out
end

local function shallow_copy_table(src)
  local out = {}
  for k, v in pairs(src or {}) do
    if type(v) == "table" then
      local t = {}
      for k2, v2 in pairs(v) do t[k2] = v2 end
      out[k] = t
    else
      out[k] = v
    end
  end
  return out
end

local function merge_module_config(defaults, overrides)
  local out = deep_copy_table(defaults)
  if type(overrides) ~= "table" then return out end
  for mod_name, mod_cfg in pairs(overrides) do
    if type(mod_name) == "string" and type(mod_cfg) == "table" then
      if type(out[mod_name]) ~= "table" then out[mod_name] = {} end
      for k, v in pairs(mod_cfg) do out[mod_name][k] = v end
    end
  end
  return out
end

local function merge_reason_policy(defaults, overrides)
  local out = shallow_copy_table(defaults)
  if type(overrides) ~= "table" then return out end
  for reason, policy in pairs(overrides) do
    if type(reason) == "string" and type(policy) == "table" then
      if type(out[reason]) ~= "table" then out[reason] = {} end
      for k, v in pairs(policy) do out[reason][k] = v end
    end
  end
  return out
end

if type(CFG.limits) == "table" then merge_numbers_deep_valid(LIMITS, CFG.limits, 0) end
if type(CFG.thresholds) == "table" then merge_numbers(THRESHOLDS, CFG.thresholds) end
if type(CFG.weights) == "table" then merge_numbers(W, CFG.weights) end

local MODULES       = merge_module_config(DEFAULT_MODULES, CFG.modules)
local REASON_POLICY = merge_reason_policy(DEFAULT_REASON_POLICY, CFG.reason_policy)
local LSCAN   = LIMITS.scan
local LB64    = LIMITS.b64
local LDEC    = LIMITS.decode
local LSCRIPT = LIMITS.script
local LOBFUS  = LIMITS.obfus

-- =========================
-- Modul Helpers
-- =========================
local function module_cfg(name)
  local m = MODULES[name]
  if type(m) ~= "table" then return {} end
  return m
end

local function module_enabled(name)
  local m = module_cfg(name)
  return m.enabled ~= false
end

local function module_info_only(name)
  local m = module_cfg(name)
  return m.info_only == true
end

local function get_base_weight_map()
  return {
    js_smuggling       = W.JS_SMUGGLING,
    obfuscation        = W.OBFUSCATION,
    suspicious_api     = W.SUSPICIOUS_API,
    evasion            = W.EVASION_LOGIC,
    container          = W.CONTAINER,
    script_hard        = W.SCRIPT_HARD,
    critical           = W.CRITICAL,
    appinstaller       = W.JS_SMUGGLING,
    decoded_payload    = W.CONTAINER,
    external_scripts   = W.EXTERNAL_SCRIPT,
    css_exfil          = W.CSS_EXFIL,
    clickfix           = W.CLICKFIX_LURE,
    wasm_staging       = W.WASM_STAGING,
    blockchain_staging = W.BLOCKCHAIN_STAGING,
    css_code_execution = W.CSS_CODE_EXEC,
    domain_rotation    = W.ROTATION_BONUS,
    geo_targeting      = W.GEO_TARGETING,
    persistence        = W.SUSPICIOUS_API,
    attachment_vectors = W.ATTACHMENT_VECTOR,
    certificate_smuggling = W.CERT_SMUGGLING,
    image_smuggling_info  = W.IMAGE_SMUGGLING,
  }
end

local BASE_WEIGHT_MAP
local function get_effective_weight(module_name)
  local base = BASE_WEIGHT_MAP[module_name] or 0
  local m = module_cfg(module_name)
  if m.weight_override ~= nil then
    local n = tonumber(m.weight_override)
    if n ~= nil and n >= 0 then return n end
  end
  return tonumber(base) or 0
end
BASE_WEIGHT_MAP = get_base_weight_map()

-- =========================
-- Config Validierung
-- =========================
local VALID_MODULE_NAMES = {
  appinstaller = true, js_smuggling = true, obfuscation = true,
  decoded_payload = true, uint8array = true, external_scripts = true,
  css_exfil = true, geo_targeting = true, evasion = true,
  persistence = true, domain_rotation = true, clickfix = true,
  wasm_staging = true, blockchain_staging = true, css_code_execution = true,
  attachment_vectors = true, certificate_smuggling = true, image_smuggling_info = true,
  push_abuse = true, link_analysis = true, wasm_binary_analysis = true,
  rc4_detection = true,
}

local function validate_single_module(name, cfg, errs)
  if type(cfg) ~= "table" then
    errs[#errs + 1] = "modules." .. name .. " ist kein table"
    return
  end
  if cfg.enabled ~= nil and type(cfg.enabled) ~= "boolean" then
    errs[#errs + 1] = "modules." .. name .. ".enabled ist nicht boolean"
  end
  if cfg.info_only ~= nil and type(cfg.info_only) ~= "boolean" then
    errs[#errs + 1] = "modules." .. name .. ".info_only ist nicht boolean"
  end
  if cfg.weight_override ~= nil then
    local n = tonumber(cfg.weight_override)
    if n == nil then
      errs[#errs + 1] = "modules." .. name .. ".weight_override ist nicht numerisch"
    elseif n < 0 then
      errs[#errs + 1] = "modules." .. name .. ".weight_override ist negativ"
    elseif n > 50 then
      errs[#errs + 1] = "modules." .. name .. ".weight_override ist unrealistisch hoch"
    end
  end
end

local function validate_config_or_raise()
  local errs = {}
  local function add_err(msg) errs[#errs + 1] = msg end
  if MAX_FINAL_SCORE < 1.0 then add_err("max_final_score < 1.0 ist ungueltig") end
  if SOFT_ONLY_SCORE_CAP < 0 then add_err("soft_only_score_cap < 0 ist ungueltig") end
  if MIN_SCORE < 0 then add_err("min_score < 0 ist ungueltig") end
  if CRITICAL_BOOST < 0 then add_err("critical_boost < 0 ist ungueltig") end
  if (LSCAN.max_bytes or 0) < 4096 then add_err("limits.scan.max_bytes ist zu klein") end
  if (LB64.min_len or 0) < 40 then add_err("limits.b64.min_len ist zu klein") end
  if (LSCRIPT.max_check or 0) < 1 then add_err("limits.script.max_check muss >= 1 sein") end
  if (LSCRIPT.max_script_len or 0) < 2000 then add_err("limits.script.max_script_len ist zu klein") end
  if (LSCRIPT.split_payload_min_vars or 0) < 2 then add_err("limits.script.split_payload_min_vars ist zu klein") end
  if STRICT_WEIGHT_VALIDATION then
    for k, v in pairs(W or {}) do
      if tonumber(v) == nil then add_err("weight " .. tostring(k) .. " ist nicht numerisch")
      elseif tonumber(v) < 0 then add_err("weight " .. tostring(k) .. " ist negativ")
      elseif tonumber(v) > 50 then add_err("weight " .. tostring(k) .. " ist unrealistisch hoch") end
    end
  end
  for name, cfg in pairs(MODULES or {}) do
    if not VALID_MODULE_NAMES[name] then add_err("unbekanntes Modul: " .. tostring(name))
    else validate_single_module(name, cfg, errs) end
  end
  if #errs > 0 then
    local msg = "html_smuggling config validation failed: " .. table.concat(errs, " | ")
    if HARD_FAIL_ON_BAD_CONFIG then error(msg) end
    return false, msg
  end
  return true, "ok"
end

local function clamp_runtime_values()
  if RUNTIME_SOFT_ONLY_CAP > RUNTIME_MAX_FINAL_SCORE then RUNTIME_SOFT_ONLY_CAP = RUNTIME_MAX_FINAL_SCORE end
  if RUNTIME_MIN_SCORE < 0 then RUNTIME_MIN_SCORE = 0 end
  if RUNTIME_CRITICAL_BOOST < 0 then RUNTIME_CRITICAL_BOOST = 0 end
end

-- =========================
-- Maps
-- =========================
local SAFE_SCRIPT_DOMAINS_MAP = nil
if type(CFG.safe_script_domains_map) == "string" then
  SAFE_SCRIPT_DOMAINS_MAP = rspamd_config:add_map{ url = CFG.safe_script_domains_map, type = "set", description = "html_smuggling safe script domains" }
end

local TRUSTED_NEWSLETTER_DOMAINS_MAP = nil
if type(CFG.trusted_newsletter_domains_map) == "string" then
  TRUSTED_NEWSLETTER_DOMAINS_MAP = rspamd_config:add_map{ url = CFG.trusted_newsletter_domains_map, type = "set", description = "html_smuggling trusted newsletter domains" }
end

local UNSAFE_SCRIPT_DOMAINS_MAP = nil
if type(CFG.unsafe_script_domains_map) == "string" then
  UNSAFE_SCRIPT_DOMAINS_MAP = rspamd_config:add_map{ url = CFG.unsafe_script_domains_map, type = "set", description = "html_smuggling unsafe script domains" }
end

-- =========================
-- Allgemeine Helpers
-- =========================
local function safe_call(default, fn, ...)
  local ok, a, b, c, d = pcall(fn, ...)
  if not ok then return default end
  return a, b, c, d
end

local function safe_string_call(default, fn, ...)
  local ok, res = pcall(fn, ...)
  if not ok or res == nil then return default or "" end
  return tostring(res)
end

local function normalize_text(s)
  if s == nil then return "" end
  if type(s) == "string" then return s end
  if s.to_string then
    local ok, out = pcall(function() return s:to_string() end)
    if ok and out then return out end
  end
  return tostring(s) or ""
end

local function trim(s)
  if s == nil then return "" end
  if type(s) ~= "string" then s = tostring(s) end
  return s:match("^%s*(.-)%s*$") or ""
end

local function safe_str(v, default)
  if v == nil then return default or "none" end
  local tv = type(v)
  if tv == "string" then return v end
  if tv == "number" then return tostring(v) end
  if tv == "boolean" then return v and "true" or "false" end
  return default or "unknown"
end

local function table_keys_sorted(t)
  local keys = {}
  for k in pairs(t or {}) do keys[#keys + 1] = k end
  table.sort(keys)
  return keys
end

local function normalize_b64(s)
  local t = (s or ""):gsub("%s+", "")
  t = t:gsub("%-", "+"):gsub("_", "/")
  local mod = #t % 4
  if mod == 2 then t = t .. "==" elseif mod == 3 then t = t .. "=" end
  return t
end

local function is_frag_base64ish(s)
  if not s then return false end
  if #s < (LOBFUS.min_frag_len or 4) then return false end
  return s:match("^[A-Za-z0-9%+/_=-]+$") ~= nil
end

local function is_base64ish(s)
  if not s or #s < (LB64.min_len or 200) then return false end
  local t = s:gsub("%s+", "")
  if not t:match("^[A-Za-z0-9%+/_=-]+$") then return false end
  return true
end

local function safe_decode_base64(task, b64, limit)
  local ok, res = pcall(function() return rspamd_util.decode_base64(b64, limit) end)
  if not ok then
    if task then rspamd_logger.warnx(task, "Base64 decode failed") end
    return nil
  end
  return res
end

local function smart_text_scan(s, chunk)
  if not s then return "" end
  s = tostring(s)
  local c = tonumber(chunk) or 20000
  if #s <= c then return s end
  local parts = { s:sub(1, c), s:sub(-c) }
  if #s > (c * 4) then
    local mid = math.floor(#s / 2)
    local start = math.max(1, mid - math.floor(c / 2))
    parts[#parts + 1] = s:sub(start, start + c)
  end
  return table.concat(parts, "\n")
end

local function redact_value(s, keep)
  s = safe_str(s, "none")
  if not REDACT_LOG_FIELDS then return s end
  keep = tonumber(keep) or 3
  if #s <= keep then return string.rep("*", #s) end
  return s:sub(1, keep) .. string.rep("*", math.max(3, #s - keep))
end

local function dedupe_list_limit(items, max_items)
  local out, seen = {}, {}
  max_items = tonumber(max_items) or 10
  for _, v in ipairs(items or {}) do
    local k = tostring(v)
    if not seen[k] then
      seen[k] = true
      out[#out + 1] = v
      if #out >= max_items then break end
    end
  end
  return out
end

local function looks_like_tracking_or_inline_b64(s)
  if not s then return false end
  local l = (s or ""):lower()
  if l:find("^data:image/", 1, false) then return true end
  if l:find("^data:font/", 1, false) then return true end
  if l:find("^data:text/css", 1, false) then return true end
  if l:find("goog", 1, true) or l:find("analytics", 1, true) then return true end
  if l:find("tracking", 1, true) or l:find("pixel", 1, true) or l:find("beacon", 1, true) then return true end
  return false
end

local function has_long_base64_sequence(s, min_len)
  if not s or #s < min_len then return false end
  for match in s:gmatch("[A-Za-z0-9%+/_-]+") do if #match >= min_len then return true end end
  return false
end

local function host_from_url(u)
  if not u or u == "" then return nil end
  local s = tostring(u):lower()
  if s:match("^/") then return nil end
  s = s:gsub("^https?://", ""):gsub("^//", "")
  return s:match("^([^/%?#:]+)")
end

local function map_has_domain(map, host)
  if not map or not host or host == "" then return false end
  if map:get_key(host) then return true end
  local parts = {}
  for p in host:gmatch("([^.]+)") do parts[#parts + 1] = p end
  for i = 2, #parts do
    local cand = table.concat(parts, ".", i, #parts)
    if map:get_key(cand) then return true end
  end
  return false
end

local function is_safe_script_domain(u)
  local host = host_from_url(u)
  if not host then
    return false
  end
  if UNSAFE_SCRIPT_DOMAINS_MAP and map_has_domain(UNSAFE_SCRIPT_DOMAINS_MAP, host) then
    return false
  end
  if SAFE_SCRIPT_DOMAINS_MAP and map_has_domain(SAFE_SCRIPT_DOMAINS_MAP, host) then
    return true
  end
  return false
end

local function get_reason_policy(why)
  if not why or why == "" then return { class = "JS_SMUGGLING" } end
  local p = REASON_POLICY[why]
  if type(p) == "table" then return p end
  if why:find("^dec_pe") or why:find("^dec_wasm") or why:find("^ms_app") then return { class = "CRITICAL" } end
  if why:find("^dec_zip") or why:find("^dec_rar") or why:find("^dec_7zip") or why:find("^dec_cab") then return { class = "CONTAINER" } end
  if why:find("poly") or why:find("fromcharcode") then return { class = "OBFUSCATION" } end
  return { class = "JS_SMUGGLING" }
end

local function clamp_html_size(raw_html)
  if #raw_html > (LSCAN.max_bytes or (200 * 1024)) then return raw_html:sub(1, LSCAN.max_bytes) end
  return raw_html
end

local function clamp_script_size(script)
  local max_script_len = tonumber(LSCRIPT.max_script_len) or 80000
  if #script > max_script_len then return script:sub(1, max_script_len) end
  return script
end

local function build_html_views(raw_html)
  local html_scan = smart_text_scan(raw_html, LSCAN.smart_chunk)
  return { raw = raw_html, raw_lc = raw_html:lower(), scan = html_scan, scan_lc = html_scan:lower() }
end

local function build_script_views(script)
  local raw = clamp_script_size(script)
  return { raw = raw, lc = raw:lower() }
end

local function lower_limit_text(s, max_bytes)
  if not s then return "" end
  s = normalize_text(s)
  local maxb = tonumber(max_bytes) or tonumber(LSCAN.max_attachment_text) or (300 * 1024)
  if #s > maxb then s = s:sub(1, maxb) end
  return s:lower()
end

local function part_get_filename_lc(part)
  if not part or not part.get_filename then return "" end
  local name = safe_string_call("", function() return part:get_filename() end)
  return tostring(name or ""):lower()
end

local function part_get_type_lc(part)
  if not part or not part.get_type then return "" end
  local ctype = safe_string_call("", function() return part:get_type() end)
  return tostring(ctype or ""):lower()
end

local function part_get_content_text(part, max_bytes)
  if not part or not part.get_content then return "" end
  local ok, c = pcall(function() return part:get_content() end)
  if not ok or not c then return "" end
  local s = normalize_text(c)
  local maxb = tonumber(max_bytes) or tonumber(LSCAN.max_attachment_text) or (300 * 1024)
  if #s > maxb then s = s:sub(1, maxb) end
  return s
end

local function filename_has_ext(name, ext)
  if not name or name == "" then return false end
  return name:sub(-#ext) == ext
end

-- =========================
-- Entropy
-- =========================
local function calculate_entropy(s, max_bytes)
  if not s or #s == 0 then return 0 end
  local maxb = tonumber(max_bytes) or tonumber(LOBFUS.max_entropy_check_bytes) or 1024
  if #s > maxb then s = s:sub(1, maxb) end
  local freq = {}
  for i = 1, #s do
    local c = s:sub(i, i)
    freq[c] = (freq[c] or 0) + 1
  end
  local entropy = 0
  local len = #s
  for _, count in pairs(freq) do
    local p = count / len
    if p > 0 then entropy = entropy - (p * math.log(p) / math.log(2)) end
  end
  return entropy
end

local function base64_quality_score(s)
  if not s then return 0 end
  local t = (s or ""):gsub("%s+", "")
  if #t < 40 then return 0 end
  local score = 0
  if t:find("[+/=%-_]") then score = score + 1 end
  if #t >= (LB64.min_len or 200) then score = score + 1 end
  if score < 2 then return score end
  local ent = calculate_entropy(t, 1024)
  if ent >= 4.8 then score = score + 2 elseif ent >= 4.2 then score = score + 1 end
  if t:match("^[A-Za-z0-9%+/_=-]+$") then score = score + 1 end
  return score
end

-- =========================
-- Newsletter Detection
-- =========================
local function is_newsletter(task)
  local h = task:get_header("X-HEC-MailClass") or task:get_header("X-HEC-Category") or task:get_header("X-FortiMail-Profile")
  if h then
    local hl = tostring(h):lower()
    if hl:find("newsletter", 1, true) or hl:find("marketing", 1, true) or hl:find("bulk", 1, true) then
      return true, "header"
    end
  end
  if task:get_header("List-Id") then return true, "list-id" end
  if task:get_header("List-Unsubscribe") then return true, "list-unsub" end
  local prec = task:get_header("Precedence") or task:get_header("X-Precedence")
  if prec and tostring(prec):lower():find("bulk", 1, true) then return true, "precedence" end
  local xm = task:get_header("X-Mailer")
  if xm then
    local xml = tostring(xm):lower()
    if xml:find("mailchimp", 1, true) then return true, "mailer_mailchimp" end
    if xml:find("sendgrid", 1, true) then return true, "mailer_sendgrid" end
    if xml:find("salesforce", 1, true) or xml:find("marketing cloud", 1, true) then return true, "mailer_sfmc" end
  end
  return false, "none"
end

local function is_trusted_newsletter_sender(task)
  if not TRUSTED_NEWSLETTER_DOMAINS_MAP then return false end
  local fd = ""
  if task.get_from_domain then
    local ok, v = pcall(function() return task:get_from_domain() end)
    if ok and v then fd = tostring(v):lower() end
  end
  if fd == "" then return false end
  return map_has_domain(TRUSTED_NEWSLETTER_DOMAINS_MAP, fd)
end

local function compute_heur_mul(task, NL, NL_reason)
  if not NL then return HEUR_MUL_DEFAULT end
  if is_trusted_newsletter_sender(task) then return HEUR_MUL_TRUSTED_NEWSLETTER end
  if NL_reason == "header" then return HEUR_MUL_NEWSLETTER_HEADER end
  return HEUR_MUL_NEWSLETTER_HEUR
end

-- =========================
-- Detector Context
-- =========================
local Detector = {}
Detector.__index = Detector

function Detector.new(task)
  local self = setmetatable({}, Detector)
  self.task = task
  self.final_score = 0.0
  self.critical_kind = nil
  self.external_scripts = {}
  self.reasons = {}
  self.info_reasons = {}
  self.found_categories = {
    JS_SMUGGLING   = false,
    OBFUSCATION    = false,
    SUSPICIOUS_API = false,
    EVASION        = false,
    CONTAINER      = false,
    SCRIPT_HARD    = false,
    CRITICAL       = false,
  }
  self.soft_bonus_score = 0.0
  self.hard_bonus_score = 0.0
  self.raw_score = 0.0
  self.combo_soft = 0.0
  self.combo_hard = 0.0
  self.after_combos = 0.0
  self.after_boost = 0.0
  self.after_floor = 0.0
  self.newsletter = false
  self.newsletter_reason = "none"
  self.heur_mul = 1.0
  self.deep_scan = true
  self.total_script_scanned = 0
  self.started_at = rspamd_util.get_ticks()
  self.phase = {
    html_parts_seen = 0, html_parts_scanned = 0,
    attach_parts_seen = 0, attach_parts_scanned = 0,
    script_blocks_seen = 0, script_blocks_scanned = 0,
    decode_candidates = 0, decode_success = 0, decode_fail = 0,
  }
  self.errors = {}
  return self
end

function Detector:add_error(msg)
  if not msg or msg == "" then return end
  if #self.errors >= 20 then return end
  self.errors[#self.errors + 1] = tostring(msg)
end

function Detector:has_reason(why) return self.reasons[why] == true end
function Detector:has_info(why) return self.info_reasons[why] == true end

function Detector:set_critical(kind)
  if kind and kind ~= "" and not self.critical_kind then self.critical_kind = kind end
end

function Detector:add_info(why)
  if not why or why == "" then return end
  if self.info_reasons[why] then return end
  self.info_reasons[why] = true
end

function Detector:add_reason(why)
  if not why or why == "" then return end
  if self.reasons[why] then return end
  self.reasons[why] = true
  local policy = get_reason_policy(why)
  local class = policy.class or "JS_SMUGGLING"

  if class == "CRITICAL"       then self.found_categories.CRITICAL = true; return end
  if class == "CONTAINER"      then self.found_categories.CONTAINER = true; return end
  if class == "SCRIPT_HARD"    then self.found_categories.SCRIPT_HARD = true; return end
  if class == "OBFUSCATION"    then self.found_categories.OBFUSCATION = true; return end
  if class == "SUSPICIOUS_API" then self.found_categories.SUSPICIOUS_API = true; return end
  if class == "EVASION"        then self.found_categories.EVASION = true; return end
  if class == "JS_SMUGGLING"   then self.found_categories.JS_SMUGGLING = true; return end

  if class == "BONUS_SOFT" then
    local bonus_module = policy.bonus_module
    if bonus_module then self.soft_bonus_score = self.soft_bonus_score + get_effective_weight(bonus_module) end
    return
  end
  if class == "BONUS_HARD" then
    local bonus_module = policy.bonus_module
    if bonus_module then self.hard_bonus_score = self.hard_bonus_score + get_effective_weight(bonus_module) end
    return
  end
  if class == "INFO" or class == "BONUS_INFO" then
    self:add_info(why)
    self.reasons[why] = nil
    return
  end
  self.found_categories.JS_SMUGGLING = true
end

function Detector:add_module_reason(module_name, why)
  if not why or why == "" then return end
  if not module_enabled(module_name) then return end
  if module_info_only(module_name) then self:add_info(why); return end
  self:add_reason(why)
end

function Detector:add_module_reasons(module_name, list)
  if type(list) ~= "table" then return end
  for _, why in ipairs(list) do self:add_module_reason(module_name, why) end
end

-- =========================
-- Policy Layer
-- =========================
local Policy = {}

function Policy.has_basic_js_gate(raw_lc)
  if raw_lc:find("<script", 1, true) then return true end
  if raw_lc:find("</script>", 1, true) then return true end
  if raw_lc:find("atob%s*%(", 1, false) then return true end
  if raw_lc:find("createobjecturl", 1, true) then return true end
  if raw_lc:find("uint8array", 1, true) then return true end
  if raw_lc:find("blob%s*%(", 1, false) then return true end
  if raw_lc:find("fetch%s*%(", 1, false) then return true end
  if raw_lc:find("eval%s*%(", 1, false) then return true end
  if raw_lc:find("settimeout%s*%(", 1, false) then return true end
  if raw_lc:find("setinterval%s*%(", 1, false) then return true end
  if raw_lc:find("fromcharcode%s*%(", 1, false) then return true end
  if raw_lc:find("on%w+%s*=", 1, false) then return true end
  if raw_lc:find("webassembly%.instantiate", 1, false) then return true end
  if raw_lc:find("webassembly%.instantiatestreaming", 1, false) then return true end
  if raw_lc:find("new%s+webassembly%.module", 1, false) then return true end
  if raw_lc:find("new%s+webassembly%.instance", 1, false) then return true end
  if raw_lc:find("getcomputedstyle", 1, true) then return true end
  if raw_lc:find("notification%.requestpermission", 1, false) then return true end
  if raw_lc:find("ms%-appinstaller", 1, true) then return true end
  if raw_lc:find("%.appinstaller", 1, true) then return true end
  return false
end

function Policy.has_smuggling_context(ctx)
  return ctx:has_reason("createObjectURL") or ctx:has_reason("blob") or
         ctx:has_reason("fetch") or ctx:has_reason("obfus_api") or
         ctx:has_reason("array_index_atob") or ctx:has_reason("eval_call") or
         ctx:has_reason("atob") or ctx:has_reason("atob_obfuscated") or
         ctx:has_reason("split_payload") or ctx:has_reason("uint8array_payload") or
         ctx:has_reason("ms_appinstaller_uri") or ctx:has_reason("appinstaller_file") or
         ctx:has_reason("wasm_staged_payload") or ctx:has_reason("blockchain_staged_payload") or
         ctx:has_reason("clickfix_lure") or ctx:has_reason("att_pdf_javascript") or
         ctx:has_reason("att_svg_script") or ctx:has_reason("att_svg_event_handler")
end

function Policy.has_strong_decode_gate(ctx)
  return ctx:has_reason("atob") or ctx:has_reason("atob_obfuscated") or
         ctx:has_reason("obfus_api") or ctx:has_reason("split_payload") or
         ctx:has_reason("delayed_execution") or ctx:has_reason("ms_appinstaller_uri") or
         ctx:has_reason("appinstaller_file") or ctx:has_reason("uint8array_payload") or
         ctx:has_reason("wasm_inline_stage")
end

function Policy.should_scan_css(ctx)
  return Policy.has_smuggling_context(ctx) or ctx:has_reason("delayed_execution") or module_enabled("css_code_execution")
end

function Policy.should_score_external_scripts(ctx)
  if not REQUIRE_SCRIPT_CONTEXT_FOR_EXTERNAL then return true end
  return Policy.has_strong_decode_gate(ctx)
end

function Policy.should_deep_scan_scripts(ctx, html_view)
  local lc = html_view.scan_lc
  local has_b64_pattern = has_long_base64_sequence(lc, 100)
  local has_atob = (lc:find("atob%s*%(", 1, false) ~= nil)
  local has_blob = (lc:find("blob%s*%(", 1, false) ~= nil)
  local has_fetch = (lc:find("fetch%s*%(", 1, false) ~= nil)
  local has_uint8 = (lc:find("uint8array", 1, true) ~= nil)
  local has_script_tags  = (lc:find("<script", 1, true) ~= nil)
  local has_script_close = (lc:find("</script>", 1, true) ~= nil)
  local has_modern_stage =
    (lc:find("webassembly%.instantiate", 1, false) ~= nil) or
    (lc:find("webassembly%.instantiatestreaming", 1, false) ~= nil) or
    (lc:find("new%s+webassembly%.module", 1, false) ~= nil) or
    (lc:find("new%s+webassembly%.instance", 1, false) ~= nil) or
    (lc:find("ethers", 1, true) ~= nil) or
    (lc:find("web3", 1, true) ~= nil) or
    (lc:find("getcomputedstyle", 1, true) ~= nil) or
    (lc:find("navigator%.webdriver", 1, false) ~= nil) or
    (lc:find("notification%.requestpermission", 1, false) ~= nil)
  local has_existing_context = Policy.has_smuggling_context(ctx) or
    ctx:has_reason("webassembly") or ctx:has_reason("serviceworker_api") or
    ctx:has_reason("webcrypto_api") or ctx:has_reason("qr_canvas_api")
  if not (has_existing_context or has_modern_stage) then return false end
  if not (has_b64_pattern or has_atob or has_blob or has_fetch or has_uint8 or ctx:has_reason("obfus_api") or ctx:has_reason("split_payload") or has_modern_stage) then return false end
  if not (has_script_tags or has_script_close) then return false end
  return true
end

-- =========================
-- Base64 Candidates
-- =========================
local function extract_b64_candidates(text, max_candidates_override)
  local candidates, seen = {}, {}
  if not text or #text < (LB64.min_len or 200) then return candidates end
  local max_in = tonumber(LB64.max_scan_bytes) or (LSCAN.max_bytes * 2)
  if #text > max_in then text = text:sub(1, max_in) end
  local max_cand = tonumber(max_candidates_override) or (LB64.max_candidates or 6)
  local min_len  = tonumber(LB64.min_len) or 200
  local start_time = rspamd_util.get_ticks()
  local budget_ms  = tonumber(THRESHOLDS.b64_extract_loop_budget_ms) or 25.0
  local iter_count = 0
  for raw in text:gmatch("[A-Za-z0-9%+/_=-]+") do
    iter_count = iter_count + 1
    if (iter_count % 80 == 0) and (((rspamd_util.get_ticks() - start_time) / 1000.0) > budget_ms) then break end
    if #candidates >= max_cand then break end
    if #raw >= min_len and not looks_like_tracking_or_inline_b64(raw) then
      local nb = normalize_b64(raw)
      if #nb >= min_len and nb:match("^[A-Za-z0-9%+/_=-]+$") then
        local q = base64_quality_score(nb)
        if q >= 3 then
          local h = rspamd_util.str_hash(nb)
          if not seen[h] then seen[h] = true; candidates[#candidates + 1] = nb end
        end
      end
    end
  end
  return candidates
end

-- =========================
-- Deobfuskation
-- FIX v4.3.7b: Array-Join-Resolver eingebaut
-- =========================
local function advanced_deobfuscate(script, timeout_ms)
  if not script or #script < 30 then return script, {}, 0 end
  local max_len = tonumber(LSCRIPT.max_script_len) or 80000
  if #script > max_len then script = script:sub(1, max_len) end
  local t0 = rspamd_util.get_ticks()
  local budget = tonumber(timeout_ms) or tonumber(LSCRIPT.deobfus_timeout_ms) or 50.0
  local timeout_flag = 0
  local function timed_out(op_cnt)
    if (op_cnt % 10) ~= 0 then return false end
    return (rspamd_util.get_ticks() - t0) / 1000.0 > budget
  end
  local clean, var_map, var_cnt, virtuals = script, {}, 0, {}

  -- FIX v4.3.7b: Separater Zaehler fuer Join-Kandidaten damit
  -- virtual_max_payloads diese nicht verdraengt
  local join_virtuals_added = 0
  local MAX_JOIN_VIRTUALS = 3

  local function maybe_add_virtual(val)
    if not val then return end
    if #virtuals >= (LOBFUS.virtual_max_payloads or 3) then return end
    if #val >= (LOBFUS.virtual_trigger_len or 120) then virtuals[#virtuals + 1] = val end
  end

  -- FIX v4.3.7b: Join-Kandidat mit eigenem Limit und ohne virtual_trigger_len Check
  local function add_join_virtual(val)
    if not val or #val < (LB64.min_len or 200) then return end
    if join_virtuals_added >= MAX_JOIN_VIRTUALS then return end
    local hv = rspamd_util.str_hash(val)
    for _, v in ipairs(virtuals) do
      if rspamd_util.str_hash(v) == hv then return end
    end
    virtuals[#virtuals + 1] = val
    join_virtuals_added = join_virtuals_added + 1
  end

  local function remember_var(name, val)
    if not name or not val then return end
    if #name > 64 or var_map[name] or var_cnt >= (LSCRIPT.max_vars or 20) then return end
    val = val:gsub("%s+", "")
    if not is_frag_base64ish(val) then return end
    var_map[name] = val
    var_cnt = var_cnt + 1
  end

  -- Decl-Loop: var/let/const x = '...'
  local decl_ops = 0
  for _, kw in ipairs({"const", "let", "var"}) do
    for name, val in script:gmatch(kw .. "%s+([%w_]+)%s*=%s*'([^']*)'") do
      decl_ops = decl_ops + 1
      if timed_out(decl_ops) then return clean, virtuals, 1 end
      remember_var(name, val)
    end
    for name, val in script:gmatch(kw .. '%s+([%w_]+)%s*=%s*"([^"]*)"') do
      decl_ops = decl_ops + 1
      if timed_out(decl_ops) then return clean, virtuals, 1 end
      remember_var(name, val)
    end
  end

  -- += Accumulation-Loop (unveraendert aus 4.3.7a)
  local add_ops = 0
  for name, val in script:gmatch("([%w_]+)%s*%+=%s*'([^']*)'") do
    add_ops = add_ops + 1
    if timed_out(add_ops) then return clean, virtuals, 1 end
    if var_cnt >= (LSCRIPT.max_vars or 20) then break end
    name = trim(name)
    val = (val or ""):gsub("%s+", "")
    if is_frag_base64ish(val) then
      if not var_map[name] then
        if var_cnt >= (LSCRIPT.max_vars or 20) then break end
        var_cnt = var_cnt + 1
        var_map[name] = ""
      end
      var_map[name] = (var_map[name] or "") .. val
      maybe_add_virtual(var_map[name])
    end
  end

  -- ================================================================
  -- FIX v4.3.7b: Array-Join-Resolver
  -- Erkennt: var/let/const name = ["frag1","frag2",...]; name.join(...)
  -- Laeuft auf vollem script (nicht smart_text_scan Chunk) damit
  -- Array-Literale in der Mitte grosser Scripts nicht weggeschnitten werden.
  -- MAX_JOIN_ARRAY_PARTS=20 statt join_max_parts=5 fuer Array-Literale.
  -- Join-Kandidaten umgehen base64_quality_score via add_join_virtual
  -- (is_frag_base64ish reicht, Padding-Bloecke haben Entropy ~0 aber
  -- sind valide PE-Header-Bestandteile).
  -- ================================================================
  local MAX_JOIN_ARRAY_PARTS = 20
  local MAX_JOIN_TOTAL_LEN   = tonumber(LB64.join_max_len) or 180000

  local join_ops = 0
  for kw_decl, arr_name, arr_body in script:gmatch(
      "([%w]+)%s+([%w_]+)%s*=%s*%[([^%]]+)%]") do
    join_ops = join_ops + 1
    if timed_out(join_ops) then break end
    if join_virtuals_added >= MAX_JOIN_VIRTUALS then break end

    -- Nur weiterarbeiten wenn arr_name.join( im Script vorkommt
    if not script:find(arr_name .. "%s*%.%s*join%s*%(", 1, false) then
      goto continue_join
    end

    do
      local frags = {}
      local total_len = 0
      local ok_frags = true

      -- Doppelte Anfuehrungszeichen
      for frag in arr_body:gmatch('"([^"]*)"') do
        local f = frag:gsub("%s+", "")
        if #f > 0 then
          if not f:match("^[A-Za-z0-9%+/_=-]*$") then ok_frags = false; break end
          frags[#frags + 1] = f
          total_len = total_len + #f
          if #frags > MAX_JOIN_ARRAY_PARTS or total_len > MAX_JOIN_TOTAL_LEN then
            ok_frags = false; break
          end
        end
      end

      -- Falls keine doppelten gefunden: einfache Anfuehrungszeichen versuchen
      if ok_frags and #frags == 0 then
        for frag in arr_body:gmatch("'([^']*)'") do
          local f = frag:gsub("%s+", "")
          if #f > 0 then
            if not f:match("^[A-Za-z0-9%+/_=-]*$") then ok_frags = false; break end
            frags[#frags + 1] = f
            total_len = total_len + #f
            if #frags > MAX_JOIN_ARRAY_PARTS or total_len > MAX_JOIN_TOTAL_LEN then
              ok_frags = false; break
            end
          end
        end
      end

      if ok_frags and #frags >= 2 then
        local joined = table.concat(frags, "")
        -- URL-safe Base64 normalisieren
        joined = joined:gsub("%-", "+"):gsub("_", "/")
        local mod4 = #joined % 4
        if mod4 == 2 then joined = joined .. "=="
        elseif mod4 == 3 then joined = joined .. "=" end

        if #joined >= (LB64.min_len or 200) and joined:match("^[A-Za-z0-9%+/_=-]+$") then
          add_join_virtual(joined)
          -- Auch in var_map eintragen fuer nachfolgende Resolve-Passes
          if var_cnt < (LSCRIPT.max_vars or 20) and not var_map[arr_name] then
            var_map[arr_name] = joined
            var_cnt = var_cnt + 1
          end
        end
      end
    end

    ::continue_join::
  end
  -- ================================================================
  -- Ende Array-Join-Resolver
  -- ================================================================

  local function resolve_token(tok)
    tok = trim(tok or "")
    if tok == "" then return nil end
    local q = tok:match("^'([^']*)'$")
    if q then q = q:gsub("%s+", ""); if is_frag_base64ish(q) then return q end; return nil end
    local qq = tok:match('^"([^"]*)"$')
    if qq then qq = qq:gsub("%s+", ""); if is_frag_base64ish(qq) then return qq end; return nil end
    if tok:match("^[%w_]+$") then return var_map[tok] end
    return nil
  end

  local function try_resolve_concat(expr)
    local out, parts = {}, 0
    for tok in expr:gmatch("([^%+]+)") do
      tok = trim(tok)
      local v = resolve_token(tok)
      if not v then return nil end
      parts = parts + 1
      if parts > (LB64.join_max_parts or 5) then return nil end
      out[#out + 1] = v
    end
    local s = table.concat(out, "")
    if is_frag_base64ish(s) then return s end
    return nil
  end

  local function try_resolve_join(expr)
    local inside = expr:match("^%[(.-)%]%.join%s*%(%s*['\"][^'\"]*['\"]%s*%)$")
    if not inside then return nil end
    local out, parts = {}, 0
    for item in inside:gmatch("([^,]+)") do
      item = trim(item)
      local v = resolve_token(item)
      if not v then return nil end
      parts = parts + 1
      if parts > (LB64.join_max_parts or 5) then return nil end
      out[#out + 1] = v
    end
    local s = table.concat(out, "")
    if is_frag_base64ish(s) then return s end
    return nil
  end

  local resolve_region = script:sub(1, math.min(#script, 20000))
  local passes = tonumber(LOBFUS.resolve_passes) or 8
  if #script > 100000 then passes = math.min(passes, 2)
  elseif #script > (THRESHOLDS.deobfus_reduce_len_2 or 40000) then passes = math.min(passes, 2)
  elseif #script > (THRESHOLDS.deobfus_reduce_len_1 or 20000) then passes = math.min(passes, 4) end
  local resolve_ops = 0
  for _ = 1, passes do
    local changed = false
    for target, expr in resolve_region:gmatch("([%w_]+)%s*=%s*([^;\n]+)") do
      resolve_ops = resolve_ops + 1
      if timed_out(resolve_ops) then return clean, virtuals, 1 end
      target = trim(target); expr = trim(expr)
      if target ~= "" and #target <= 64 and expr ~= "" then
        if var_map[target] or var_cnt < (LSCRIPT.max_vars or 20) then
          local resolved = nil
          if expr:find("%+", 1, false) then resolved = try_resolve_concat(expr) end
          if (not resolved) and expr:find("%.join", 1, true) then resolved = try_resolve_join(expr) end
          if resolved and resolved ~= var_map[target] then
            if not var_map[target] then var_cnt = var_cnt + 1 end
            var_map[target] = resolved
            maybe_add_virtual(resolved)
            changed = true
          end
        end
      end
    end
    if not changed then break end
  end

  clean = clean:gsub('"%s*%+%s*"', ""):gsub("'%s*%+%s*'", "")
  return clean, virtuals, timeout_flag
end

-- =========================
-- PE Validierung und Payload Sniffing
-- =========================
local function le_u32(s, off)
  if not s or #s < off + 4 then return nil end
  local b1, b2, b3, b4 = s:byte(off + 1, off + 4)
  if not b1 then return nil end
  return b1 + (b2 * 256) + (b3 * 65536) + (b4 * 16777216)
end

local function le_u16(s, off)
  if not s or #s < off + 2 then return nil end
  local b1, b2 = s:byte(off + 1, off + 2)
  if not b1 then return nil end
  return b1 + (b2 * 256)
end

local function is_valid_pe(bin)
  local ok, res = pcall(function()
    if not bin or #bin < 256 then return false end
    if bin:sub(1, 2) ~= "MZ" then return false end
    local e_lfanew = le_u32(bin, 0x3C)
    if not e_lfanew then return false end
    if e_lfanew < 0x40 or e_lfanew > (#bin - 256) then return false end
    if bin:sub(e_lfanew + 1, e_lfanew + 4) ~= "PE\000\000" then return false end
    local machine = le_u16(bin, e_lfanew + 4)
    if not machine then return false end
    return (machine == 0x014c) or (machine == 0x8664) or (machine == 0x01c0) or (machine == 0xaa64)
  end)
  if not ok then return false end
  return res == true
end

local function sniff_decoded(bin)
  local ok, result = pcall(function()
    if not bin or #bin < 16 then return nil end
    if is_valid_pe(bin) then return "PE" end
    if bin:sub(1, 4) == "MSCF" then return "CAB" end
    if bin:sub(1, 6) == "7z\xBC\xAF\x27\x1C" then return "7ZIP" end
    if bin:sub(1, 6) == "Rar!\x1A\x07" then return "RAR" end
    if bin:sub(1, 4) == "PK\003\004" or bin:sub(1, 4) == "PK\005\006" then
      local head = bin:sub(1, 200000)
      if head:find("AppxManifest%.xml", 1, true) or head:find("AppxBlockMap%.xml", 1, true) or head:find("AppxSignature%.p7x", 1, true) or head:find("AppxMetadata/", 1, true) then
        if head:find("AppxManifest%.xml", 1, true) then return "APPX" end
        return "MSIX"
      end
      return "ZIP"
    end
    if bin:sub(1, 5) == "%PDF-" then return "PDF" end
    if bin:sub(1, 8) == "\208\207\017\224\161\177\026\225" then return "OLE" end
    if bin:sub(1, 8) == "vhdxfile" then return "VHDX" end
    if bin:sub(1, 4) == "ITSF" then return "CHM" end
    if #bin >= 0x8001 + 5 and bin:sub(0x8001 + 1, 0x8001 + 5) == "CD001" then return "ISO"
    elseif #bin >= 2048 and bin:sub(1, 2048):find("CD001", 1, true) then return "ISO" end
    if bin:sub(1, 4) == "\076\000\000\000" then
      local h = bin:sub(1, 64)
      if h:find("\001\020\002\000\000\000\000\000\192\000\000\000\000\000\000\070", 1, true) then return "LNK" end
    end
    if bin:sub(1, 4) == "\000asm" or bin:sub(1, 8) == "\000asm\001\000\000\000" then return "WASM" end
    local head = bin:sub(1, 4096)
    local l = head:lower()
    if l:find("<?xml", 1, true) or l:find("<appinstaller", 1, true) then return "XML" end
    if l:find("<html", 1, true) or l:find("<script", 1, true) then return "HTML" end
    if l:find("<svg", 1, true) then return "SVG" end
    if l:find("<hta:", 1, true) or l:find("application%s*=") or l:find("showintaskbar", 1, true) then return "HTA" end
    local vbs_ind = 0
    if l:find("wscript%.createobject", 1, true) then vbs_ind = vbs_ind + 1 end
    if l:find("on error resume next", 1, true) then vbs_ind = vbs_ind + 1 end
    if l:find("createobject%s*%(", 1, false) then vbs_ind = vbs_ind + 1 end
    if vbs_ind >= 2 then return "VBS" end
    local ps_ind = 0
    if l:find("powershell", 1, true) then ps_ind = ps_ind + 1 end
    if l:find("invoke%-expression", 1, true) then ps_ind = ps_ind + 1 end
    if l:find("%biex%b", 1, false) or l:find("%-enc%s+", 1, false) then ps_ind = ps_ind + 1 end
    if ps_ind >= 2 then return "PS1" end
    local bat_ind = 0
    if l:find("@echo off", 1, true) then bat_ind = bat_ind + 1 end
    if l:find("cmd%.exe", 1, true) or l:find("start%s+/", 1, false) then bat_ind = bat_ind + 1 end
    if l:find("%%[a-z]%%", 1, false) then bat_ind = bat_ind + 1 end
    if bat_ind >= 2 then return "BAT" end
    local js_ind = 0
    if l:find("function%s*[%w_]*%s*%(", 1, false) then js_ind = js_ind + 1 end
    if l:find("var%s+[%w_]+", 1, false) or l:find("let%s+[%w_]+", 1, false) or l:find("const%s+[%w_]+", 1, false) then js_ind = js_ind + 1 end
    if l:find("=>", 1, true) then js_ind = js_ind + 1 end
    if l:find("eval%s*%(", 1, false) then js_ind = js_ind + 1 end
    if l:find("atob%s*%(", 1, false) then js_ind = js_ind + 1 end
    if l:find("document%.createelement", 1, true) then js_ind = js_ind + 1 end
    if l:find("addeventlistener", 1, true) then js_ind = js_ind + 1 end
    if js_ind >= 2 then return "JS" end
    return "BINARY"
  end)
  if not ok then return "BINARY" end
  return result
end

local function part_is_htmlish(p)
  if not p then return false end
  if SAFE_PART_ACCESS then
    local ok_html, is_html = pcall(function() return p:is_html() end)
    if ok_html and is_html then return true end
  else
    if p:is_html() then return true end
  end
  local fname = part_get_filename_lc(p)
  if fname ~= "" and (fname:match("%.html?$") or fname:match("%.svg$")) then return true end
  local ctype = part_get_type_lc(p)
  if ctype ~= "" and (ctype:find("text/html", 1, true) or ctype:find("image/svg+xml", 1, true) or ctype:find("application/xhtml", 1, true)) then return true end
  local content = part_get_content_text(p, 4096)
  if content ~= "" then
    local lcc = content:lower()
    if lcc:find("<html", 1, true) or lcc:find("<script", 1, true) or lcc:find("<svg", 1, true) then return true end
  end
  return false
end

local function part_is_likely_attachment_vector(p)
  if not p then return false end
  local fname = part_get_filename_lc(p)
  local ctype = part_get_type_lc(p)
  if fname:match("%.pdf$") or fname:match("%.svg$") or fname:match("%.chm$") or fname:match("%.hta$") or fname:match("%.one$") or fname:match("%.lnk$") or fname:match("%.js$") or fname:match("%.vbs$") or fname:match("%.ps1$") or fname:match("%.wsf$") or fname:match("%.docm$") or fname:match("%.xlsm$") or fname:match("%.pptm$") or fname:match("%.cer$") or fname:match("%.crt$") or fname:match("%.p7b$") or fname:match("%.p7c$") or fname:match("%.pfx$") or fname:match("%.p12$") or fname:match("%.pem$") then
    return true
  end
  if ctype:find("application/pdf", 1, true) or ctype:find("image/svg+xml", 1, true) or ctype:find("application/x%-msdownload", 1, false) or ctype:find("application/octet%-stream", 1, false) then
    return true
  end
  return false
end

-- =========================
-- Fruehe Context Helpers
-- =========================
local function has_hard_reasons(ctx)
  return ctx.found_categories.CRITICAL or ctx.found_categories.CONTAINER or ctx.found_categories.SCRIPT_HARD
end

local function has_any_critical_kind(ctx)
  return ctx.critical_kind ~= nil and ctx.critical_kind ~= ""
end

-- =========================
-- HTML Module Scanner
-- =========================
local function scan_appinstaller_module(ctx, raw_html)
  if not module_enabled("appinstaller") then return end
  local raw_lc = raw_html:lower()
  if raw_lc:find("ms%-appinstaller", 1, true) then
    if raw_lc:find("ms%-appinstaller:%s*", 1, false) then ctx:add_module_reason("appinstaller", "ms_appinstaller_uri")
    else ctx:add_module_reason("appinstaller", "ms_appinstaller_word") end
  end
  if raw_lc:find("%.appinstaller", 1, true) then ctx:add_module_reason("appinstaller", "appinstaller_file") end
end

local function has_obfuscated_api_call(lc)
  if lc:find("%[%s*['\"]atob['\"]%s*%]", 1, false) then return true end
  if lc:find("%[%s*['\"]blob['\"]%s*%]", 1, false) then return true end
  if lc:find("%[%s*['\"]fetch['\"]%s*%]", 1, false) then return true end
  if lc:find("%[%s*['\"]eval['\"]%s*%]", 1, false) then return true end
  if lc:find("%[%s*['\"]constructor['\"]%s*%]", 1, false) then return true end
  if lc:find("%[%s*['\"]createobjecturl['\"]%s*%]", 1, false) then return true end
  local suspicious_concat = {
    "['\"]a['\"]%s*%+%s*['\"]tob['\"]",
    "['\"]at['\"]%s*%+%s*['\"]ob['\"]",
    "['\"]bl['\"]%s*%+%s*['\"]ob['\"]",
    "['\"]fe['\"]%s*%+%s*['\"]tch['\"]",
    "['\"]ev['\"]%s*%+%s*['\"]al['\"]",
    "['\"]constr['\"]%s*%+%s*['\"]uctor['\"]",
    "['\"]createobject['\"]%s*%+%s*['\"]url['\"]",
  }
  for _, p in ipairs(suspicious_concat) do if lc:find(p, 1, false) then return true end end
  local hex_count = 0
  for _ in lc:gmatch("x%x%x") do hex_count = hex_count + 1; if hex_count >= 3 then return true end end
  local unicode_count = 0
  for _ in lc:gmatch("u%x%x%x%x") do unicode_count = unicode_count + 1; if unicode_count >= 3 then return true end end
  if lc:find("fromcharcode%s*%(", 1, false) or lc:find("charcodeat%s*%(", 1, false) then return true end
  if lc:find("eval%s*%([^%)]+%+[^%)]+%)", 1, false) then return true end
  if lc:find("atob%.call", 1, true) or lc:find("atob%.apply", 1, true) then return true end
  if lc:find("%.constructor%s*%(", 1, false) then return true end
  return false
end

local function has_wasm_api_indicator(lc)
  if not lc or lc == "" then return false end
  if lc:find("webassembly%.instantiate", 1, false) then return true end
  if lc:find("webassembly%.instantiatestreaming", 1, false) then return true end
  if lc:find("webassembly%.compile", 1, false) then return true end
  if lc:find("webassembly%.validate", 1, false) then return true end
  if lc:find("new%s+webassembly%.module", 1, false) then return true end
  if lc:find("new%s+webassembly%.instance", 1, false) then return true end
  if lc:find("\000asm", 1, true) then return true end
  return false
end

local function has_canvas_qr_indicator(lc)
  if not lc or lc == "" then return false end
  local has_canvas_surface = lc:find("<canvas", 1, true) or lc:find("document%.createelement%s*%(%s*['\"]canvas['\"]%s*%)", 1, false) or lc:find("getcontext%s*%(%s*['\"]2d['\"]%s*%)", 1, false) or lc:find("getcontext%s*%(%s*['\"]webgl['\"]%s*%)", 1, false)
  if not has_canvas_surface then return false end
  local has_qr_terms = lc:find("qrcanvas", 1, true) or lc:find("qrcode", 1, true) or lc:find("qr%-code", 1, false) or lc:find("qr code", 1, true)
  local has_render_ops = lc:find("filltext%s*%(", 1, false) or lc:find("putimagedata%s*%(", 1, false) or lc:find("drawimage%s*%(", 1, false) or lc:find("todataurl%s*%(", 1, false)
  return (has_canvas_surface and has_render_ops) or (has_canvas_surface and has_qr_terms)
end

local function detect_inline_event_handler_exec(lc, add_fn)
  if not lc or lc == "" then return end
  for on_event in lc:gmatch("on%w+%s*=%s*'([^']*)'") do
    if on_event:find("atob", 1, true) or on_event:find("eval", 1, true) or on_event:find("blob", 1, true) or on_event:find("fetch", 1, true) then add_fn("event_handler_api"); return end
  end
  for on_event in lc:gmatch('on%w+%s*=%s*"([^"]*)"') do
    if on_event:find("atob", 1, true) or on_event:find("eval", 1, true) or on_event:find("blob", 1, true) or on_event:find("fetch", 1, true) then add_fn("event_handler_api"); return end
  end
end

local function detect_advanced_api_calls(lc, add_fn)
  if lc:find("%[%s*['\"]atob['\"]%s*%]", 1, false) then add_fn("array_index_atob") end
  if lc:find("%[%s*['\"]blob['\"]%s*%]", 1, false) then add_fn("array_index_blob") end
  if lc:find("%[%s*['\"]fetch['\"]%s*%]", 1, false) then add_fn("array_index_fetch") end
  if lc:find("new%s+function%s*%(", 1, false) then add_fn("function_constructor") end
  if lc:find("eval%s*%(", 1, false) then add_fn("eval_call") end
  if lc:find("settimeout%s*%(", 1, false) then add_fn("settimeout_call") end
  if lc:find("setinterval%s*%(", 1, false) then add_fn("setinterval_call") end
  if lc:find("new%s+worker%s*%(", 1, false) then add_fn("webworker") end
  if lc:find("serviceworker", 1, true) or lc:find("navigator%.serviceworker", 1, false) then add_fn("serviceworker_api") end
  if has_wasm_api_indicator(lc) then add_fn("webassembly") end
  if lc:find("crypto%.subtle", 1, false) or lc:find("subtle%.decrypt", 1, false) or lc:find("importkey", 1, true) then add_fn("webcrypto_api") end
  if has_canvas_qr_indicator(lc) then add_fn("qr_canvas_api") end
  detect_inline_event_handler_exec(lc, add_fn)
end

local function detect_string_obfuscation(lc)
  local hit, reasons = false, {}
  if lc:find("%[%s*['\"]%w+['\"]%s*,%s*['\"]%w+['\"]%s*%]%s*%.%s*join", 1, false) then hit = true; reasons[#reasons + 1] = "array_join_concat" end
  if lc:find("window%s*%[%s*['\"]atob['\"]%s*%]", 1, false) or lc:find("this%s*%[%s*['\"]atob['\"]%s*%]", 1, false) then hit = true; reasons[#reasons + 1] = "bracket_atob" end
  local fromcharcode_count = 0
  for codes in lc:gmatch("fromcharcode%s*%(%s*([%d%s,]+)%s*%)") do
    fromcharcode_count = fromcharcode_count + 1
    local suspicious_chars = 0
    for num_str in codes:gmatch("%d+") do
      local code = tonumber(num_str)
      if code == 97 or code == 98 or code == 102 or code == 111 or code == 116 then suspicious_chars = suspicious_chars + 1 end
    end
    if suspicious_chars >= 3 then hit = true; reasons[#reasons + 1] = "fromcharcode_api"; break end
  end
  if fromcharcode_count > 3 then hit = true; reasons[#reasons + 1] = "fromcharcode_heavy" end
  return { hit = hit, reasons = reasons }
end

local function detect_split_payload(html)
  if not html or #html < 120 then return false end

  local lc = html:lower()
  local has_sink =
    lc:find("atob%s*%(", 1, false) or
    lc:find("blob%s*%(", 1, false) or
    lc:find("createobjecturl", 1, true) or
    lc:find("fetch%s*%(", 1, false)

  if not has_sink then
    return false
  end

  local min_parts = tonumber(LSCRIPT.split_payload_min_vars) or 6

  local cnt, vars = 0, {}
  local function register_decl(varname, value)
    if not varname or not value then return end
    value = (value or ""):gsub("%s+", "")
    if not is_frag_base64ish(value) or #value < 8 or vars[varname] then return end
    vars[varname] = true
    cnt = cnt + 1
  end

  local function scan_keyword(keyword)
    for varname, value in html:gmatch(keyword .. "%s+([%w_]+)%s*=%s*'([^']*)'") do
      register_decl(varname, value)
    end
    for varname, value in html:gmatch(keyword .. '%s+([%w_]+)%s*=%s*"([^"]*)"') do
      register_decl(varname, value)
    end
  end

  scan_keyword("var")
  scan_keyword("let")
  scan_keyword("const")

  if cnt >= min_parts and (html:find("%+=", 1, false) or html:find("%.join%s*%(", 1, false)) then
    return true
  end

  -- FIX v4.3.7c-r3: Array-Join Konstrukte robust erkennen
  -- var/let/const name = ["frag1","frag2",...]; name.join('')
  local function check_array_join(pattern)
    for arr_name, arr_body in html:gmatch(pattern) do
      if html:find(arr_name .. "%s*%.%s*join%s*%(", 1, false) then
        local frag_count = 0
        for frag in arr_body:gmatch('"([^"]*)"') do
          local f = (frag or ""):gsub("%s+", "")
          if is_frag_base64ish(f) and #f >= 8 then frag_count = frag_count + 1 end
        end
        if frag_count == 0 then
          for frag in arr_body:gmatch("'([^']*)'") do
            local f = (frag or ""):gsub("%s+", "")
            if is_frag_base64ish(f) and #f >= 8 then frag_count = frag_count + 1 end
          end
        end
        if frag_count >= 2 then return true end
      end
    end
    return false
  end

  if check_array_join("[Vv][Aa][Rr]%s+([%w_]+)%s*=%s*%[([^%]]+)%]") then return true end
  if check_array_join("[Ll][Ee][Tt]%s+([%w_]+)%s*=%s*%[([^%]]+)%]") then return true end
  if check_array_join("[Cc][Oo][Nn][Ss][Tt]%s+([%w_]+)%s*=%s*%[([^%]]+)%]") then return true end

  return false
end

local function collect_timer_positions(lc)
  local out, pos = {}, 1
  while true do
    local p1 = lc:find("settimeout", pos, true)
    local p2 = lc:find("setinterval", pos, true)
    local next_pos
    if p1 and p2 then next_pos = math.min(p1, p2) else next_pos = p1 or p2 end
    if not next_pos then break end
    out[#out + 1] = next_pos
    pos = next_pos + 1
    if #out >= 5 then break end
  end
  return out
end

local function detect_delayed_execution(html)
  local lc = html:lower()
  local reasons = {}
  local has_timeout = lc:find("settimeout", 1, true) or lc:find("setinterval", 1, true)
  if not has_timeout then return { hit = false, reasons = {} } end
  local timer_positions = collect_timer_positions(lc)
  for _, timer_pos in ipairs(timer_positions) do
    local ctx_len = tonumber(LOBFUS.max_delayed_exec_context) or 500
    local snippet = lc:sub(math.max(1, timer_pos - ctx_len), math.min(#lc, timer_pos + ctx_len))
    local has_b64 = has_long_base64_sequence(snippet, 100)
    local has_blob = snippet:find("blob", 1, true)
    local has_url  = snippet:find("createobjecturl", 1, true)
    local has_atob = snippet:find("atob", 1, true)
    if has_b64 then
      if has_blob or has_url then reasons[#reasons + 1] = "timeout_b64_smuggling"
      elseif has_atob then reasons[#reasons + 1] = "timeout_b64_decode"
      else reasons[#reasons + 1] = "timeout_b64" end
    end
  end
  if lc:find("<form[^>]+name%s*=%s*['\"]%w+['\"]", 1, false) then
    if lc:find("<input[^>]+name%s*=%s*['\"]payload['\"]", 1, false) or lc:find("<input[^>]+name%s*=%s*['\"]data['\"]", 1, false) then reasons[#reasons + 1] = "dom_clobbering" end
  end
  return { hit = (#reasons > 0), reasons = reasons }
end

local function scan_js_smuggling_html_module(ctx, html_view)
  if not module_enabled("js_smuggling") then return end
  local lc, mod, obf_mod = html_view.scan_lc, "js_smuggling", "obfuscation"
  if lc:find("atob%s*%(", 1, false) then ctx:add_module_reason(mod, "atob") end
  if lc:find("blob%s*%(", 1, false) then ctx:add_module_reason(mod, "blob") end
  if lc:find("createobjecturl", 1, true) then ctx:add_module_reason(mod, "createObjectURL") end
  if lc:find("fetch%s*%(", 1, false) then ctx:add_module_reason(mod, "fetch") end
  if lc:find("filereader", 1, true) then ctx:add_module_reason(mod, "filereader") end
  if lc:find("uint8array", 1, true) then ctx:add_module_reason(mod, "uint8array") end
  if has_long_base64_sequence(lc, LSCAN.long_html_b64_threshold or 1200) then ctx:add_module_reason(mod, "b64_long_html") end
  local needs_obfus_scan = lc:find("fromcharcode", 1, true) or lc:find("window%[", 1, false) or lc:find("this%[", 1, false) or lc:find("%.join%s*%(", 1, false)
  if needs_obfus_scan then
    local obfus_res = detect_string_obfuscation(lc)
    if obfus_res.hit then ctx:add_module_reason(obf_mod, "atob_obfuscated"); ctx:add_module_reasons(obf_mod, obfus_res.reasons) end
  end
  detect_advanced_api_calls(lc, function(why)
    local target_mod = REASON_MODULE_MAP[why] or mod
    ctx:add_module_reason(target_mod, why)
  end)
  if lc:find("<iframe", 1, true) and lc:find("src%s*=", 1, false) then ctx:add_module_reason(mod, "iframe_src") end
  if lc:find("src%s*=", 1, false) and lc:find("data:", 1, true) then ctx:add_module_reason(mod, "data_uri") end
  if has_obfuscated_api_call(lc) then ctx:add_module_reason(obf_mod, "obfus_api") end
  if lc:find("function", 1, true) or lc:find("var ", 1, true) or lc:find("let ", 1, true) or lc:find("const ", 1, true) then
    if detect_split_payload(html_view.scan) then ctx:add_module_reason(mod, "split_payload") end
  end
  if lc:find("settimeout", 1, true) or lc:find("setinterval", 1, true) then
    local delay_res = detect_delayed_execution(html_view.scan)
    if delay_res.hit then ctx:add_module_reason(mod, "delayed_execution"); ctx:add_module_reasons(mod, delay_res.reasons) end
  end
end

local function scan_css_exfil_module(ctx, html_view)
  if not module_enabled("css_exfil") or not Policy.should_scan_css(ctx) then return end
  local lc, mod = html_view.scan_lc, "css_exfil"
  local max_style = tonumber(LOBFUS.css_max_style_size) or 10000
  if lc:find("@import%s+url%s*%(%s*['\"]https?://", 1, false) then ctx:add_module_reason(mod, "css_import_external") end
  if lc:find("background[^:]*:%s*url%s*%([^%)]*attr%s*%(", 1, false) then ctx:add_module_reason(mod, "css_attr_exfil"); ctx:add_module_reason(mod, "css_exfiltration") end
  for style_content in html_view.raw_lc:gmatch("<[Ss][Tt][Yy][Ll][Ee][^>]*>(.-)</[Ss][Tt][Yy][Ll][Ee]>") do
    if #style_content > max_style and has_long_base64_sequence(style_content, 200) then
      ctx:add_module_reason(mod, "css_large_b64")
      ctx:add_module_reason(mod, "css_exfiltration")
      break
    end
  end
end

local function scan_clickfix_module(ctx, html_view)
  if not module_enabled("clickfix") then return end
  local lc, mod = html_view.scan_lc, "clickfix"
  local has_captcha = lc:find("i am not a robot", 1, true) or lc:find("verify you are human", 1, true) or lc:find("human verification", 1, true) or lc:find("prove you are human", 1, true) or lc:find("click to verify", 1, true) or (lc:find("captcha", 1, true) and (lc:find("powershell", 1, true) or lc:find("cmd%.exe", 1, false) or lc:find("windows%+r", 1, false) or lc:find("clipboard", 1, true)))
  local has_clipboard_with_exec = (lc:find("clipboard", 1, true) or lc:find("navigator%.clipboard", 1, false)) and (lc:find("powershell", 1, true) or lc:find("cmd%.exe", 1, false) or lc:find("windows%+r", 1, false) or lc:find("mshta", 1, true) or lc:find("wscript", 1, true) or lc:find("cscript", 1, true))
  local has_run_flow = lc:find("windows%+r", 1, false) or lc:find("win%+r", 1, false) or lc:find("run dialog", 1, true) or lc:find("open run", 1, true) or lc:find("press%s+win%w*%s*%+%s*r", 1, false) or lc:find("press%s+windows%s*%+%s*r", 1, false)
  local has_terminal_flow = lc:find("powershell", 1, true) or lc:find("cmd%.exe", 1, false) or lc:find("mshta", 1, true) or lc:find("wscript", 1, true) or lc:find("cscript", 1, true) or (lc:find("terminal", 1, true) and lc:find("paste", 1, true))
  if has_captcha then ctx:add_module_reason(mod, "fake_captcha_lure") end
  if has_clipboard_with_exec then ctx:add_module_reason(mod, "clipboard_exec_lure") end
  if has_run_flow then ctx:add_module_reason(mod, "run_dialog_lure") end
  if has_terminal_flow then ctx:add_module_reason(mod, "powershell_lure") end
  local has_exec_flow = has_run_flow or has_terminal_flow or has_clipboard_with_exec
  if (has_captcha or has_clipboard_with_exec) and has_exec_flow then ctx:add_module_reason(mod, "clickfix_lure") end
end

local function scan_external_scripts_module(ctx, script_entries)
  if not module_enabled("external_scripts") or not Policy.has_smuggling_context(ctx) then return end
  local all, unsafe, seen_all, seen_unsafe = {}, {}, {}, {}
  for _, entry in ipairs(script_entries or {}) do
    if entry.is_external and entry.src then
      local u, ul = entry.src, entry.src:lower()
      if u ~= "" and not seen_all[u] then
        seen_all[u] = true
        if entry.is_dynamic then
          if #all < (LSCRIPT.max_external or 5) then all[#all + 1] = u end
          if ul == "dynamic_script_creation" then
            if not seen_unsafe[u] then seen_unsafe[u] = true; unsafe[#unsafe + 1] = u end
          elseif not is_safe_script_domain(u) and not seen_unsafe[u] then
            seen_unsafe[u] = true; unsafe[#unsafe + 1] = u
          end
        elseif ul:match("^https?://") or ul:match("^//") then
          if #all < (LSCRIPT.max_external or 5) then all[#all + 1] = u end
          if not is_safe_script_domain(u) and not seen_unsafe[u] then seen_unsafe[u] = true; unsafe[#unsafe + 1] = u end
        end
      end
    end
  end
  all = dedupe_list_limit(all, LSCRIPT.max_external or 5)
  unsafe = dedupe_list_limit(unsafe, LSCRIPT.max_external or 5)
  for _, u in ipairs(all) do if #ctx.external_scripts < (LSCRIPT.max_external or 5) then ctx.external_scripts[#ctx.external_scripts + 1] = u end end
  if Policy.should_score_external_scripts(ctx) and #unsafe > 0 then ctx:add_module_reason("external_scripts", "external_scripts") end
end

local function scan_push_abuse_html_module(ctx, html_view)
  if not module_enabled("push_abuse") then return end
  local lc, mod = html_view.scan_lc, "push_abuse"
  if lc:find("notification%.requestpermission", 1, false) then
    ctx:add_module_reason(mod, "push_permission_request")
    if lc:find("serviceworker", 1, true) or lc:find("pushmanager", 1, true) then
      ctx:add_module_reason(mod, "push_serviceworker_combo")
      ctx:add_module_reason(mod, "push_notification_flow")
    end
  end
end

local function scan_certificate_html_module(ctx, html_view)
  if not module_enabled("certificate_smuggling") then return end
  local lc = html_view.scan_lc

  local has_pem =
    lc:find("begin certificate", 1, true) or
    lc:find("begin x509 certificate", 1, true)

  local has_pkcs =
    lc:find("begin pkcs7", 1, true) or
    lc:find("begin pkcs12", 1, true)

  if not has_pem and not has_pkcs
     and not lc:find("data:application/x%-x509", 1, false)
     and not lc:find("data:application/pkcs", 1, false) then
    return
  end

  if lc:find("data:application/x%-x509", 1, false) or lc:find("data:application/pkcs", 1, false) then
    ctx:add_module_reason("certificate_smuggling", "cert_data_uri")
  end

  local suspicious_ctx =
    Policy.has_smuggling_context(ctx) or
    lc:find("atob%s*%(", 1, false) or
    lc:find("blob%s*%(", 1, false) or
    lc:find("fetch%s*%(", 1, false)

  if has_pem then
    if suspicious_ctx then
      ctx:add_module_reason("certificate_smuggling", "cert_inline_pem")
    else
      ctx:add_module_reason("certificate_smuggling", "cert_attachment_file")
    end
  end

  if has_pkcs then
    if suspicious_ctx then
      ctx:add_module_reason("certificate_smuggling", "cert_inline_pkcs")
    else
      ctx:add_module_reason("certificate_smuggling", "cert_attachment_file")
    end
  end

  if has_long_base64_sequence(lc, 600) and (lc:find("certificate", 1, true) or lc:find("pkcs", 1, true)) then
    ctx:add_module_reason("certificate_smuggling", "cert_base64_block")
  end
end

-- =========================
-- Script Module Scanner
-- =========================
local function scan_wasm_staging_module(ctx, script_raw)
  if not module_enabled("wasm_staging") then return end
  local lc, mod = (script_raw or ""):lower(), "wasm_staging"
  local has_wasm_api = lc:find("webassembly%.instantiate", 1, false) or lc:find("webassembly%.instantiatestreaming", 1, false) or lc:find("new%s+webassembly%.module", 1, false)
  if not has_wasm_api then return end
  local has_fetch  = (lc:find("fetch%s*%(", 1, false) ~= nil)
  local has_worker = lc:find("worker%s*%(", 1, false) or lc:find("new%s+worker", 1, false)
  local has_exec   = lc:find("eval%s*%(", 1, false) or lc:find("new%s+function%s*%(", 1, false) or lc:find("instance%.exports", 1, false)
  local has_inline = lc:find("\000asm", 1, true) or lc:find("agfzbq", 1, true) or lc:find("aaabiaa", 1, true)
  local reasons = {}
  if has_fetch then reasons[#reasons + 1] = "wasm_fetch_stage" end
  if has_inline then reasons[#reasons + 1] = "wasm_inline_stage" end
  if has_worker then reasons[#reasons + 1] = "wasm_worker_stage" end
  if has_exec then reasons[#reasons + 1] = "wasm_eval_bridge" end
  if lc:find("instance%.exports%.decode", 1, false) or lc:find("instance%.exports%.run", 1, false) or lc:find("instance%.exports%.execute", 1, false) then reasons[#reasons + 1] = "wasm_suspicious_exports" end
  if #reasons >= 2 then reasons[#reasons + 1] = "wasm_staged_payload" end
  ctx:add_module_reasons(mod, reasons)
end

local function scan_blockchain_staging_module(ctx, script_raw)
  if not module_enabled("blockchain_staging") then return end
  local lc, mod = (script_raw or ""):lower(), "blockchain_staging"
  local has_web3 = lc:find("ethers", 1, true) or lc:find("web3", 1, true) or lc:find("ethereum", 1, true) or lc:find("binance smart chain", 1, true)
  if not has_web3 then return end
  local has_contract = lc:find("new%s+ethers%.contract", 1, false) or lc:find("eth_call", 1, true) or lc:find("jsonrpc", 1, true) or lc:find("contract", 1, true)
  local has_payload = lc:find("getpayload", 1, true) or lc:find("callstatic", 1, true) or lc:find("provider%.call", 1, false) or lc:find("rpc", 1, true)
  local has_exec = lc:find("eval%s*%(", 1, false) or lc:find("new%s+function%s*%(", 1, false) or lc:find("atob%s*%(", 1, false) or lc:find("blob%s*%(", 1, false)
  local reasons = { "web3_api_usage" }
  if has_contract then reasons[#reasons + 1] = "ethers_contract_payload" end
  if has_payload then reasons[#reasons + 1] = "web3_eth_call"; reasons[#reasons + 1] = "blockchain_remote_stage" end
  if has_exec then reasons[#reasons + 1] = "blockchain_eval_bridge" end
  if has_web3 and has_contract and (has_payload or has_exec) then reasons[#reasons + 1] = "blockchain_staged_payload" end
  ctx:add_module_reasons(mod, reasons)
end

local function extract_css_content_values(html_view)
  local values, html_scan = {}, (html_view and html_view.scan) or ""
  if html_scan == "" then return values end
  for style_content in html_scan:gmatch("<[Ss][Tt][Yy][Ll][Ee][^>]*>(.-)</[Ss][Tt][Yy][Ll][Ee]>") do
    for val in style_content:gmatch("content%s*:%s*'([^']*)'") do values[#values + 1] = val end
    for val in style_content:gmatch('content%s*:%s*"([^"]*)"') do values[#values + 1] = val end
  end
  return values
end

local function css_content_looks_code_like(val)
  if not val or val == "" then return false end
  local compact = tostring(val):gsub("%s+", "")
  if #compact < 40 then return false end
  if has_long_base64_sequence(compact:lower(), 40) then return true end
  if compact:find("function", 1, true) or compact:find("eval(", 1, true) or compact:find("atob(", 1, true) or compact:find("blob(", 1, true) or compact:find("fetch(", 1, true) or compact:find("createobjecturl", 1, true) then return true end
  return false
end

local function scan_css_code_exec_module(ctx, html_view, script_view, meta)
  if not module_enabled("css_code_execution") then return end
  if meta and not meta.maybe_css then return end
  local h, s, mod = html_view.scan_lc or "", (script_view and script_view.lc) or "", "css_code_execution"
  local has_css_content = h:find("::before", 1, true) or h:find("::after", 1, true)
  if not has_css_content and not s:find("getcomputedstyle", 1, true) then return end
  local has_content_prop  = h:find("content%s*:%s*['\"]", 1, false) ~= nil
  local has_computedstyle = s:find("getcomputedstyle%s*%(", 1, false) ~= nil
  local has_content_read  = s:find("%.content", 1, true) or s:find("%[content%]", 1, false) or s:find("%[.content.%]", 1, false) or s:find("getpropertyvalue%s*%(", 1, false)
  local has_exec = s:find("new%s+function%s*%(", 1, false) or s:find("eval%s*%(", 1, false)
  local reasons = {}
  if has_css_content and has_content_prop then
    reasons[#reasons + 1] = "css_before_after_content"
    local content_values = extract_css_content_values(html_view)
    for _, val in ipairs(content_values) do if css_content_looks_code_like(val) then reasons[#reasons + 1] = "css_hidden_code_string"; break end end
  end
  if has_computedstyle and has_content_read then reasons[#reasons + 1] = "css_computedstyle_exec" end
  if has_exec then reasons[#reasons + 1] = "css_function_bridge" end
  if has_css_content and has_computedstyle and has_exec then reasons[#reasons + 1] = "css_code_execution" end
  ctx:add_module_reasons(mod, reasons)
end

local function detect_hex_array(script)
  if not script then return false end
  local hex_count = 0
  for _ in script:gmatch("0x%x%x") do
    hex_count = hex_count + 1
    if hex_count >= 32 then return script:find("%[%s*0x%x%x", 1, false) ~= nil end
  end
  if hex_count < 8 then return false end
  return script:find("%[%s*0x%x%x", 1, false) ~= nil
end

local function detect_polymorphic_obfuscation(script)
  local reasons = {}
  local hex_var_high, hex_var_low = THRESHOLDS.hex_var_high or 5, THRESHOLDS.hex_var_low or 2
  local hex_var_count = 0
  for _ in script:gmatch("_0x%x+") do hex_var_count = hex_var_count + 1; if hex_var_count >= hex_var_high then reasons[#reasons + 1] = "hex_var_names"; break end end
  if hex_var_count < hex_var_high and hex_var_count >= hex_var_low then reasons[#reasons + 1] = "hex_vars" end
  if #reasons == 0 then
    local entropy = calculate_entropy(script)
    if entropy > (THRESHOLDS.entropy_very_high or 5.0) then reasons[#reasons + 1] = "very_high_entropy"
    elseif entropy > (THRESHOLDS.entropy_high or 4.5) then reasons[#reasons + 1] = "high_entropy" end
  end
  if #reasons < 2 then
    local array_storage_count = 0
    local array_high, array_low = THRESHOLDS.array_storage_high or 3, THRESHOLDS.array_storage_low or 1
    for _ in script:gmatch("const%s+_%w+%s*=%s*%[%s*['\"]") do array_storage_count = array_storage_count + 1; if array_storage_count >= array_high then reasons[#reasons + 1] = "array_string_storage"; break end end
    if array_storage_count < array_high then for _ in script:gmatch("var%s+_%w+%s*=%s*%[%s*['\"]") do array_storage_count = array_storage_count + 1; if array_storage_count >= array_high then reasons[#reasons + 1] = "array_string_storage"; break end end end
    if array_storage_count >= array_low and array_storage_count < array_high then reasons[#reasons + 1] = "array_storage" end
  end
  if script:find("function%s*%(%s*_0x%x+%s*,%s*_0x%x+", 1, false) then reasons[#reasons + 1] = "func_obfuscation" end
  return { hit = (#reasons > 0), reasons = reasons }
end

local function scan_obfuscation_script_module(ctx, script_raw, meta)
  if not module_enabled("obfuscation") then return end
  local mod = "obfuscation"
  if meta.maybe_hex and detect_hex_array(script_raw) then ctx:add_module_reason(mod, "hex_array") end
  if meta.maybe_obfus then
    local res = detect_polymorphic_obfuscation(script_raw)
    if res.hit then ctx:add_module_reason(mod, "polymorphic_obfuscation"); ctx:add_module_reasons(mod, res.reasons) end
  end
end

local function scan_geo_targeting_module(ctx, script_raw)
  if not module_enabled("geo_targeting") then return end
  local lc, mod = (script_raw or ""):lower(), "geo_targeting"
  if not (lc:find("ipapi%.co", 1, false) or lc:find("ipinfo%.io", 1, false) or lc:find("geolocation", 1, true) or lc:find("timezone", 1, true) or lc:find("country_code", 1, true) or lc:find("cf%-ipcountry", 1, true)) then return end
  local geo_patterns = { "ipapi%.co", "ipinfo%.io", "geoplugin%.net", "cloudflare%.com/cdn%-cgi/trace", "country_code", "x%-country%-code", "cf%-ipcountry" }
  for _, p in ipairs(geo_patterns) do if lc:find(p, 1, false) then ctx:add_module_reason(mod, "geo_targeting_api"); break end end
  if lc:find("navigator%.geolocation", 1, false) or lc:find("getcurrentposition", 1, true) or lc:find("geolocation", 1, true) then ctx:add_module_reason(mod, "geo_location_api") end
  if lc:find("intl%.datetimeformat%(%)%.resolvedoptions%(%)%.timezone", 1, false) or lc:find("gettimezoneoffset%s*%(", 1, false) or lc:find("timezone", 1, true) then ctx:add_module_reason(mod, "timezone_targeting") end
end

local function scan_evasion_module(ctx, script_raw)
  if not module_enabled("evasion") then return end
  local lc, mod = (script_raw or ""):lower(), "evasion"
  local needs_scan = lc:find("webdriver", 1, true) or lc:find("hardwareconcurrency", 1, true) or lc:find("devicememory", 1, true) or lc:find("screen%.width", 1, false) or lc:find("mousemove", 1, true) or lc:find("addeventlistener", 1, true)
  if not needs_scan then return end
  if lc:find("navigator%.webdriver", 1, false) or lc:find("['\"]webdriver['\"]%s+in%s+navigator", 1, false) or lc:find("webdriver%s*===?%s*true", 1, false) or lc:find("navigator%[['\"]webdriver['\"]%]", 1, false) then ctx:add_module_reason(mod, "antisandbox_webdriver") end
  local has_hw_conc = lc:find("hardwareconcurrency", 1, true) ~= nil
  local has_dev_mem = lc:find("devicememory", 1, true) ~= nil
  local has_screen  = lc:find("screen%.width", 1, false) or lc:find("screen%.height", 1, false) or lc:find("innerwidth", 1, true) or lc:find("innerheight", 1, true)
  local low_hw_check = lc:find("hardwareconcurrency%s*[<=>]+%s*[12]", 1, false) or lc:find("devicememory%s*[<=>]+%s*[124]", 1, false) or lc:find("screen%.width%s*[<=>]+%s*8?0?0", 1, false) or lc:find("innerwidth%s*[<=>]+%s*8?0?0", 1, false) or lc:find("cpuclass", 1, true)
  if (has_hw_conc or has_dev_mem or has_screen) and low_hw_check then ctx:add_module_reason(mod, "hardware_check_evasion") end
  local has_user_event = lc:find("mousemove", 1, true) or lc:find("keydown", 1, true) or lc:find("click", 1, true) or lc:find("pointermove", 1, true)
  local has_event_hook = lc:find("addeventlistener", 1, true) or lc:find("onmousemove", 1, true) or lc:find("onkeydown", 1, true) or lc:find("onclick", 1, true)
  local has_payload_logic = lc:find("atob", 1, true) or lc:find("uint8array", 1, true) or lc:find("blob", 1, true) or lc:find("createobjecturl", 1, true) or lc:find("fetch", 1, true)
  if has_user_event and has_event_hook and has_payload_logic then ctx:add_module_reason(mod, "human_interaction_required") end
end

local function scan_persistence_module(ctx, script_raw)
  if not module_enabled("persistence") then return end
  local lc = (script_raw or ""):lower()
  if not (lc:find("localstorage", 1, true) or lc:find("sessionstorage", 1, true)) then return end
  local mod = "persistence"
  if lc:find("localstorage%.getitem", 1, false) and lc:find("localstorage%.setitem", 1, false) then ctx:add_module_reason(mod, "localstorage_persistence") end
  if lc:find("sessionstorage", 1, true) then ctx:add_module_reason(mod, "sessionstorage_persistence") end
end

local function scan_domain_rotation_module(ctx, script_raw)
  if not module_enabled("domain_rotation") then return end
  local lc, mod = (script_raw or ""):lower(), "domain_rotation"
  if not (lc:find("http://", 1, true) or lc:find("https://", 1, true) or lc:find("window%.location", 1, false) or lc:find("location%.href", 1, false)) then return end
  local has_redirect_sink = lc:find("window%.location%s*=", 1, false) or lc:find("location%.href%s*=", 1, false) or lc:find("location%.assign%s*%(", 1, false) or lc:find("location%.replace%s*%(", 1, false) or lc:find("window%.open%s*%(", 1, false)
  if not has_redirect_sink then return end
  local domains, unique_count = {}, 0
  for domain in lc:gmatch("https?://([a-z0-9][a-z0-9%-]*%.[a-z][a-z0-9%.%-]+)") do
    if not domains[domain] then domains[domain] = true; unique_count = unique_count + 1; if unique_count >= 3 then ctx:add_module_reason(mod, "domain_rotation"); break end end
  end
  if lc:find("window%.location%s*=%s*[%w_]+%s*%+", 1, false) or lc:find("location%.href%s*=%s*[%w_]+%s*%+", 1, false) or lc:find("document%.location%s*=%s*[%w_]+%s*%+", 1, false) then ctx:add_module_reason("js_smuggling", "computed_redirect") end
end

local function has_quoted_hex_key_material(script_lc, min_len)
  if not script_lc or script_lc == "" then return false end
  min_len = tonumber(min_len) or 8
  for q in script_lc:gmatch("'([a-f0-9]+)'") do if #q >= min_len then return true end end
  for q in script_lc:gmatch('"([a-f0-9]+)"') do if #q >= min_len then return true end end
  return false
end

local function scan_rc4_module(ctx, script_raw)
  if not module_enabled("rc4_detection") then return end
  local lc, mod = (script_raw or ""):lower(), "rc4_detection"
  local has_ksa = (lc:find("s%[i%]%s*=%s*s%[j%]", 1, false) ~= nil and lc:find("s%[j%]%s*=%s*s%[i%]", 1, false) ~= nil) or (lc:find("ksa", 1, true) ~= nil)
  local has_prga = (lc:find("prga", 1, true) ~= nil) or (lc:find("s%[i%]", 1, false) ~= nil and lc:find("s%[j%]", 1, false) ~= nil and lc:find("charcodeat", 1, true) ~= nil)
  local has_xor = (lc:find("charcodeat%s*%(%)%s*%^", 1, false) ~= nil) or (lc:find("%^%s*s%[", 1, false) ~= nil)
  local has_decrypt = (lc:find("decrypt%s*%(", 1, false) ~= nil) or (lc:find("rc4%s*%(", 1, false) ~= nil)
  local has_key = has_quoted_hex_key_material(lc, 8) or (lc:find("key%s*=%s*['\"]", 1, false) ~= nil)
  if has_ksa then ctx:add_module_reason(mod, "rc4_ksa_pattern") end
  if has_prga then ctx:add_module_reason(mod, "rc4_prga_pattern") end
  if has_xor then ctx:add_module_reason(mod, "rc4_xor_loop") end
  if has_decrypt then ctx:add_module_reason(mod, "rc4_decrypt_call") end
  if has_key and (has_ksa or has_prga or has_decrypt) then ctx:add_module_reason(mod, "rc4_key_material") end
end

local function scan_wasm_binary_module(ctx, decoded_bin)
  if not module_enabled("wasm_binary_analysis") then return end
  if not decoded_bin or #decoded_bin < 8 then return end
  if decoded_bin:sub(1, 4) ~= "\000asm" then return end
end

local function byte_clamp(n)
  n = tonumber(n) or 0
  if n < 0 then return 0 end
  if n > 255 then return 255 end
  return n
end

local function scan_uint8array_module(ctx, script_raw, meta)
  if not module_enabled("uint8array") or not meta.maybe_uint8 then return end
  local ok = pcall(function()
    local lc, mod = (script_raw or ""):lower(), "uint8array"
    local patterns = {
      "uint8array%s*%(%s*%[%s*([%d%s,]+)",
      "uint8array%.from%s*%(%s*%[%s*([%d%s,]+)",
    }
    local found = false
    for _, array_pattern in ipairs(patterns) do
      if found then break end
      for array_content in lc:gmatch(array_pattern) do
        local byte_values, byte_count = {}, 0
        local maxb = tonumber(LOBFUS.max_uint8array_bytes) or 2048
        for num_str in array_content:gmatch("%d+") do
          byte_count = byte_count + 1
          if byte_count <= maxb then byte_values[#byte_values + 1] = tonumber(num_str) or 0 end
          if byte_count > maxb then break end
        end
        if byte_count > (THRESHOLDS.uint8array_large_min or 1024) then
          ctx:add_module_reason(mod, "uint8array_payload")
          local header_bytes = {}
          for i = 1, math.min(16, #byte_values) do header_bytes[#header_bytes + 1] = string.char(byte_clamp(byte_values[i])) end
          local header = table.concat(header_bytes)
          if #header >= 4 then
            if header:sub(1, 4) == "\000asm" then ctx:set_critical("WASM"); ctx:add_module_reason(mod, "wasm_uint8array")
            elseif header:sub(1, 2) == "MZ" then ctx:set_critical("PE"); ctx:add_module_reason(mod, "pe_uint8array")
            elseif header:sub(1, 4) == "PK\003\004" then ctx:add_module_reason(mod, "zip_uint8array")
            elseif header:sub(1, 5) == "%PDF-" then ctx:add_module_reason(mod, "pdf_uint8array")
            else ctx:add_module_reason(mod, "large_uint8array") end
          else ctx:add_module_reason(mod, "large_uint8array") end
          found = true
          break
        end
      end
    end
  end)
  if not ok then ctx:add_error("scan_uint8array_module failed") end
end

local function scan_certificate_script_module(ctx, script_raw)
  if not module_enabled("certificate_smuggling") then return end
  local lc = (script_raw or ""):lower()

  if lc:find("begin certificate", 1, true) or lc:find("begin x509 certificate", 1, true) then
    ctx:add_module_reason("certificate_smuggling", "cert_inline_pem")
  end

  if lc:find("begin pkcs7", 1, true) or lc:find("begin pkcs12", 1, true) then
    ctx:add_module_reason("certificate_smuggling", "cert_inline_pkcs")
  end

  if has_long_base64_sequence(lc, 600) and (lc:find("certificate", 1, true) or lc:find("pkcs", 1, true)) then
    ctx:add_module_reason("certificate_smuggling", "cert_base64_block")
  end
end

local function analyze_decoded_blob(ctx, decoded)
  local kind = sniff_decoded(decoded)
  if not kind then ctx:add_module_reason("js_smuggling", "dec_bin"); return end
  local function add_decoded(mod, reason, critical)
    ctx:add_module_reason(mod, reason)
    if critical then ctx:set_critical(critical) end
  end
  if kind == "PE" then add_decoded("decoded_payload", "dec_pe", "PE"); ctx:add_info("single_sniff_pe"); return end
  if kind == "WASM" then add_decoded("decoded_payload", "dec_wasm", "WASM"); scan_wasm_binary_module(ctx, decoded); return end
  if kind == "XML" then
    if ctx:has_reason("ms_appinstaller_uri") or ctx:has_reason("appinstaller_file") then add_decoded("appinstaller", "dec_xml_appinstaller", "XML_APPINSTALLER")
    else ctx:add_module_reason("js_smuggling", "dec_xml") end
    return
  end
  if kind == "VHDX" then add_decoded("decoded_payload", "dec_vhdx", "VHDX"); return end
  if kind == "ISO"  then add_decoded("decoded_payload", "dec_iso",  "ISO"); return end
  if kind == "LNK"  then add_decoded("decoded_payload", "dec_lnk",  "LNK"); return end
  if kind == "OLE"  then add_decoded("decoded_payload", "dec_ole",  "OLE"); return end
  if kind == "MSIX" then add_decoded("decoded_payload", "dec_msix", "MSIX"); return end
  if kind == "APPX" then add_decoded("decoded_payload", "dec_appx", "APPX"); return end
  if kind == "CAB"  then add_decoded("decoded_payload", "dec_cab",  "CAB"); return end
  if kind == "7ZIP" then add_decoded("decoded_payload", "dec_7zip", "7ZIP"); return end
  if kind == "RAR"  then add_decoded("decoded_payload", "dec_rar",  "RAR"); return end
  if kind == "ZIP"  then add_decoded("decoded_payload", "dec_zip",  "ZIP"); return end
  if kind == "CHM"  then add_decoded("attachment_vectors", "att_chm_attachment", "CHM"); return end
  if kind == "HTA"  then add_decoded("attachment_vectors", "att_hta_attachment", "SCRIPT"); return end
  if kind == "PDF"  then ctx:add_module_reason("js_smuggling", "dec_pdf"); return end
  if kind == "SVG"  then ctx:add_module_reason("attachment_vectors", "att_svg_smuggling_context"); return end
  if kind == "VBS" or kind == "PS1" or kind == "BAT" then add_decoded("decoded_payload", "dec_script", "SCRIPT"); return end
  if kind == "JS"  then ctx:add_module_reason("js_smuggling", "dec_js"); return end
  if kind == "HTML" then ctx:add_module_reason("js_smuggling", "dec_html"); return end
  ctx:add_module_reason("js_smuggling", "dec_bin")
end

local function collect_script_meta(script_view)
  local sl = script_view.lc
  local maybe_b64    = sl:find("atob", 1, true) ~= nil or sl:find("base64", 1, true) ~= nil
  local maybe_concat = sl:find("%+=", 1, false) ~= nil or sl:find(".join", 1, true) ~= nil
  local maybe_obfus  = sl:find("\\x", 1, true) ~= nil or sl:find("\\u", 1, true) ~= nil or sl:find("fromcharcode", 1, true) ~= nil or sl:find("_0x", 1, true) ~= nil
  local maybe_uint8  = sl:find("uint8array", 1, true) ~= nil
  local maybe_hex    = sl:find("0x%x%x", 1, false) ~= nil
  local maybe_wasm   = has_wasm_api_indicator(sl)
  local maybe_web3   = sl:find("ethers", 1, true) ~= nil or sl:find("web3", 1, true) ~= nil or sl:find("ethereum", 1, true) ~= nil
  local maybe_css    = sl:find("getcomputedstyle", 1, true) ~= nil
  local maybe_rc4    = sl:find("rc4", 1, true) ~= nil or sl:find("ksa", 1, true) ~= nil or sl:find("prga", 1, true) ~= nil or (sl:find("decrypt", 1, true) ~= nil and sl:find("key", 1, true) ~= nil)
  -- FIX v4.3.7c-r3: maybe_array_join robuster - .join( muss mit Array-Deklaration kombiniert sein
  local maybe_array_join =
    (sl:find("%.join%s*%(", 1, false) ~= nil) and
    (
      sl:find("%[%s*['\"]", 1, false) ~= nil or
      sl:find("var%s+[%w_]+%s*=%s*%[", 1, false) ~= nil or
      sl:find("let%s+[%w_]+%s*=%s*%[", 1, false) ~= nil or
      sl:find("const%s+[%w_]+%s*=%s*%[", 1, false) ~= nil
    )
  return {
    maybe_b64 = maybe_b64, maybe_concat = maybe_concat, maybe_obfus = maybe_obfus,
    maybe_uint8 = maybe_uint8, maybe_hex = maybe_hex, maybe_wasm = maybe_wasm,
    maybe_web3 = maybe_web3, maybe_css = maybe_css, maybe_rc4 = maybe_rc4,
    maybe_array_join = maybe_array_join,
    is_interesting = (maybe_b64 or maybe_concat or maybe_obfus or maybe_uint8 or maybe_hex or maybe_wasm or maybe_web3 or maybe_css or maybe_rc4 or maybe_array_join),
    allow_decode_path = (maybe_b64 or maybe_concat or maybe_obfus or maybe_array_join),
  }
end

local function scan_decoded_payload_module(ctx, script_raw, meta)
  if not module_enabled("decoded_payload") or not meta.allow_decode_path then return end
  local sscan = smart_text_scan(script_raw, LSCRIPT.smart_chunk)
  local norm  = sscan:gsub('"%s*%+%s*"', ""):gsub("'%s*%+%s*'", "")
  local virtuals = {}
  if meta.maybe_concat or meta.maybe_obfus or meta.maybe_array_join then
    -- FIX v4.3.7b: advanced_deobfuscate bekommt script_raw (nicht sscan) damit
    -- der Array-Join-Resolver den vollen Script-Text sieht
    local deob, vlist, tflag = advanced_deobfuscate(script_raw, LSCRIPT.deobfus_timeout_ms)
    norm = deob; virtuals = vlist or {}
    if tflag == 1 then ctx:add_info("deobfus_timeout") end
  end
  if not norm or #norm < (THRESHOLDS.normalized_script_min_len or 40) then return end
  local max_cand = (LB64.max_candidates or 6)
  if ctx.newsletter then max_cand = math.min(max_cand, 4) end
  local cands = extract_b64_candidates(norm, max_cand)
  if virtuals and #virtuals > 0 then
    local seen_v = {}
    for _, v in ipairs(virtuals) do
      local vv = (v or ""):gsub("%s+", "")
      if is_frag_base64ish(vv) then
        local hv = rspamd_util.str_hash(vv)
        if not seen_v[hv] then seen_v[hv] = true; cands[#cands + 1] = vv end
      end
    end
    ctx:add_module_reason("js_smuggling", "virtual_b64_candidates")
  end
  if not cands or #cands == 0 then return end
  ctx.phase.decode_candidates = ctx.phase.decode_candidates + #cands
  local total_b64_len = 0
  for _, cand in ipairs(cands) do total_b64_len = total_b64_len + #(tostring(cand):gsub("%s+", "")) end
  if total_b64_len >= (LB64.big_threshold or 5000) then ctx:add_module_reason("js_smuggling", "b64_total_len_big") end
  if total_b64_len >= (LB64.huge_threshold or 20000) then ctx:add_module_reason("js_smuggling", "b64_total_len_huge") end
  if #cands > 1 then ctx:add_module_reason("js_smuggling", "b64_joined_parts") end
  local min_decode_total = tonumber(LB64.min_decode_total) or 400
  if total_b64_len < min_decode_total then return end
  if REQUIRE_STRONG_GATE_FOR_DECODE and not Policy.has_strong_decode_gate(ctx) then ctx:add_info("decode_gate_not_strong_enough"); return end
  for _, cand in ipairs(cands) do
    local nb = normalize_b64(cand)
    if nb and #nb >= 40 then
      local decoded = safe_decode_base64(ctx.task, nb, LDEC.max_bytes)
      if decoded and #decoded > 0 then
        ctx.phase.decode_success = ctx.phase.decode_success + 1
        analyze_decoded_blob(ctx, decoded)
        if has_any_critical_kind(ctx) then break end
      else
        ctx.phase.decode_fail = ctx.phase.decode_fail + 1
      end
    end
  end
end

-- =========================
-- Script Entry Sammeln und Deep Scan
-- =========================
local function collect_script_entries(html)
  local entries = {}
  if not html or #html < 10 then return entries end
  local script_min = THRESHOLDS.script_min_len or 20
  for attrs, body in html:gmatch("<[Ss][Cc][Rr][Ii][Pp][Tt]([^>]*)>(.-)</[Ss][Cc][Rr][Ii][Pp][Tt]>") do
    local src = attrs:match('[Ss][Rr][Cc]%s*=%s*"([^"]*)"') or attrs:match("[Ss][Rr][Cc]%s*=%s*'([^']*)'") or attrs:match("[Ss][Rr][Cc]%s*=%s*([^%s>]+)")
    if src then src = trim(src) end
    local is_external = (src ~= nil and src ~= "")
    local is_inline = not is_external and (body ~= nil and #body > 0)
    local lc_body = ""
    if is_inline and body and #body >= script_min then lc_body = body:lower() end
    entries[#entries + 1] = { attrs = attrs, body = body or "", src = src, is_inline = is_inline, is_external = is_external, lc_body = lc_body, lc_attrs = (attrs or ""):lower(), interest_score = 0 }
  end
  if html:find("createElement%(%s*['\"]script['\"]%)", 1, false) then
    local extracted = html:match('[%w_]+%.src%s*=%s*"(https?://[^"]+)"') or html:match("[%w_]+%.src%s*=%s*'(https?://[^']+)'") or html:match('[%w_]+%.src%s*=%s*"(//[^"]+)"') or html:match("[%w_]+%.src%s*=%s*'(//[^']+)'")
    if not extracted then
      extracted = html:match('[Ss]et[Aa]ttribute%s*%(%s*["\']src["\']%s*,%s*"(https?://[^"]+)"') or html:match("[Ss]et[Aa]ttribute%s*%(%s*[\"']src[\"']%s*,%s*'(https?://[^']+)'") or html:match('[Ss]et[Aa]ttribute%s*%(%s*["\']src["\']%s*,%s*"(//[^"]+)"') or html:match("[Ss]et[Aa]ttribute%s*%(%s*[\"']src[\"']%s*,%s*'(//[^']+)'")
    end
    if not extracted then
      extracted = html:match('[%w_]+%[%s*["\']src["\']%s*%]%s*=%s*"(https?://[^"]+)"') or html:match("[%w_]+%[%s*[\"']src[\"']%s*%]%s*=%s*'(https?://[^']+)'") or html:match('[%w_]+%[%s*["\']src["\']%s*%]%s*=%s*"(//[^"]+)"') or html:match("[%w_]+%[%s*[\"']src[\"']%s*%]%s*=%s*'(//[^']+)'")
    end
    entries[#entries + 1] = { attrs = "", body = "", src = extracted or "dynamic_script_creation", is_inline = false, is_external = true, lc_body = "", lc_attrs = "", interest_score = 0, is_dynamic = true }
  end
  return entries
end

local function score_script_interest(entry)
  if not entry.is_inline or #entry.body < (THRESHOLDS.script_min_len or 20) then return 0 end
  local lc, score = entry.lc_body, 0
  if lc:find("atob%s*%(", 1, false) then score = score + 4 end
  if lc:find("createobjecturl", 1, true) then score = score + 4 end
  if lc:find("uint8array", 1, true) then score = score + 3 end
  if lc:find("blob%s*%(", 1, false) then score = score + 3 end
  if lc:find("fetch%s*%(", 1, false) then score = score + 2 end
  if lc:find("eval%s*%(", 1, false) then score = score + 2 end
  if lc:find("fromcharcode", 1, true) then score = score + 2 end
  if lc:find("webassembly%.instantiate", 1, false) then score = score + 3 end
  if lc:find("_0x", 1, true) then score = score + 2 end
  if lc:find("%+=", 1, false) then score = score + 1 end
  if has_long_base64_sequence(lc, 100) then score = score + 3 end
  -- FIX v4.3.7b: Array-Join Pattern als Interest-Signal
  if lc:find("%.join%s*%(", 1, false) and lc:find("%[", 1, false) then score = score + 2 end
  return score
end

local function select_top_script_entries(entries, max_check)
  max_check = tonumber(max_check) or 3
  local inline = {}
  for _, entry in ipairs(entries or {}) do
    if entry.is_inline and #entry.body >= (THRESHOLDS.script_min_len or 20) then
      entry.interest_score = score_script_interest(entry)
      inline[#inline + 1] = entry
    end
  end
  table.sort(inline, function(a, b) return a.interest_score > b.interest_score end)
  local selected = {}
  for i = 1, math.min(max_check, #inline) do selected[i] = inline[i] end
  return selected
end

local function is_script_budget_exceeded(ctx, script_loop_start)
  local dt_ms = (rspamd_util.get_ticks() - script_loop_start) / 1000.0
  if dt_ms > (LSCRIPT.max_script_time_ms or 80.0) then ctx:add_info("script_time_budget"); return true end
  if ctx.total_script_scanned >= (LSCRIPT.max_total_script_scan or 120000) then ctx:add_info("script_total_budget"); return true end
  return false
end

local function analyze_script_block(ctx, html_view, entry)
  local script = entry.body or ""
  if #script < (THRESHOLDS.script_min_len or 20) then return end
  local script_view = build_script_views(script)
  local meta = collect_script_meta(script_view)
  if not meta.is_interesting then return end
  ctx.total_script_scanned = ctx.total_script_scanned + math.min(#script_view.raw, (tonumber(LSCRIPT.smart_chunk) or 20000) * 2)
  scan_uint8array_module(ctx, script_view.raw, meta)
  if has_any_critical_kind(ctx) then return end
  scan_obfuscation_script_module(ctx, script_view.raw, meta)
  scan_geo_targeting_module(ctx, script_view.raw)
  scan_evasion_module(ctx, script_view.raw)
  scan_persistence_module(ctx, script_view.raw)
  scan_domain_rotation_module(ctx, script_view.raw)
  scan_wasm_staging_module(ctx, script_view.raw)
  scan_blockchain_staging_module(ctx, script_view.raw)
  scan_css_code_exec_module(ctx, html_view, script_view, meta)
  scan_certificate_script_module(ctx, script_view.raw)
  if meta.maybe_rc4 then scan_rc4_module(ctx, script_view.raw) end
  if has_any_critical_kind(ctx) then return end
  scan_decoded_payload_module(ctx, script_view.raw, meta)
end

local function scan_script_blocks(ctx, html_view, script_entries)
  if not ctx.deep_scan or not Policy.should_deep_scan_scripts(ctx, html_view) then return end
  local selected = select_top_script_entries(script_entries, LSCRIPT.max_check or 3)
  local script_loop_start = rspamd_util.get_ticks()
  for _, entry in ipairs(selected) do
    ctx.phase.script_blocks_seen = ctx.phase.script_blocks_seen + 1
    if is_script_budget_exceeded(ctx, script_loop_start) then break end
    local ok_script, err = pcall(function() analyze_script_block(ctx, html_view, entry); ctx.phase.script_blocks_scanned = ctx.phase.script_blocks_scanned + 1 end)
    if not ok_script then ctx:add_error("analyze_script_block failed: " .. tostring(err)) end
    if has_any_critical_kind(ctx) then break end
  end
end

-- =========================
-- Attachment Vectors
-- =========================
local function scan_attachment_vectors_module(ctx, part)
  if not module_enabled("attachment_vectors") then return end
  local fname = part_get_filename_lc(part)
  local ctype = part_get_type_lc(part)
  local text  = lower_limit_text(part_get_content_text(part, LSCAN.max_attachment_text), LSCAN.max_attachment_text)
  if fname == "" and ctype == "" and text == "" then return end
  ctx.phase.attach_parts_seen = ctx.phase.attach_parts_seen + 1

  local mod = "attachment_vectors"
  local hit = false

  if fname:match("%.pdf$") or ctype:find("application/pdf", 1, true) then
    if text ~= "" then
      if text:find("/javascript", 1, true) then ctx:add_module_reason(mod, "att_pdf_javascript"); hit = true end
      if text:find("/openaction", 1, true) then ctx:add_module_reason(mod, "att_pdf_openaction"); hit = true end
      if text:find("/launch", 1, true) then ctx:add_module_reason(mod, "att_pdf_launch"); hit = true end
      if text:find("/embeddedfile", 1, true) then ctx:add_module_reason(mod, "att_pdf_embeddedfile"); hit = true end
      if text:find("/richmedia", 1, true) then ctx:add_module_reason(mod, "att_pdf_richmedia"); hit = true end
    end
  end

  if fname:match("%.svg$") or ctype:find("image/svg+xml", 1, true) then
    if text ~= "" then
      if text:find("<script", 1, true) then ctx:add_module_reason(mod, "att_svg_script"); hit = true end
      if text:find("onload=", 1, true) or text:find("onbegin=", 1, true) or text:find("onclick=", 1, true) then ctx:add_module_reason(mod, "att_svg_event_handler"); hit = true end
      if text:find("foreignobject", 1, true) then ctx:add_module_reason(mod, "att_svg_foreignobject"); hit = true end
      if text:find("xlink:href", 1, true) or text:find("href=\"javascript:", 1, true) or text:find("href='javascript:", 1, true) then ctx:add_module_reason(mod, "att_svg_xlink_href"); hit = true end
      if text:find("data:", 1, true) and (text:find("base64", 1, true) or text:find("javascript", 1, true)) then ctx:add_module_reason(mod, "att_svg_data_uri"); hit = true end
      if hit and (text:find("atob", 1, true) or text:find("blob", 1, true) or text:find("fetch", 1, true) or text:find("createobjecturl", 1, true)) then ctx:add_module_reason(mod, "att_svg_smuggling_context") end
    end
  end

  if fname:match("%.chm$") then ctx:add_module_reason(mod, "att_chm_attachment"); ctx:set_critical("CHM"); hit = true end
  if fname:match("%.hta$") then ctx:add_module_reason(mod, "att_hta_attachment"); ctx:set_critical("SCRIPT"); hit = true end
  if fname:match("%.one$") then ctx:add_module_reason(mod, "att_onenote_attachment"); ctx:set_critical("ONENOTE"); hit = true end
  if fname:match("%.lnk$") then ctx:add_module_reason(mod, "att_lnk_attachment"); ctx:set_critical("LNK"); hit = true end
  if fname:match("%.docm$") or fname:match("%.xlsm$") or fname:match("%.pptm$") then ctx:add_module_reason(mod, "att_office_macro_container"); hit = true end
  if fname:match("%.js$") or fname:match("%.jse$") or fname:match("%.vbs$") or fname:match("%.vbe$") or fname:match("%.ps1$") or fname:match("%.wsf$") or fname:match("%.bat$") or fname:match("%.cmd$") then ctx:add_module_reason(mod, "att_script_attachment"); ctx:set_critical("SCRIPT"); hit = true end
  if fname:match("%.html?$") and text ~= "" and Policy.has_basic_js_gate(text) then ctx:add_module_reason(mod, "att_html_attachment"); hit = true end

  if hit then ctx.phase.attach_parts_scanned = ctx.phase.attach_parts_scanned + 1 end
end

local function scan_certificate_smuggling_part_module(ctx, part)
  if not module_enabled("certificate_smuggling") then return end
  local mod = "certificate_smuggling"
  local fname = part_get_filename_lc(part)
  local text  = lower_limit_text(part_get_content_text(part, LSCAN.max_attachment_text), LSCAN.max_attachment_text)
  local is_cert_file = fname:match("%.cer$") or fname:match("%.crt$") or fname:match("%.pem$") or fname:match("%.der$") or fname:match("%.p7b$") or fname:match("%.p7c$") or fname:match("%.pfx$") or fname:match("%.p12$")
  if is_cert_file then ctx:add_module_reason(mod, "cert_attachment_file") end
  if text ~= "" then
    if text:find("begin certificate", 1, true) or text:find("begin pkcs7", 1, true) or text:find("begin x509 certificate", 1, true) then ctx:add_module_reason(mod, "cert_attachment_file") end
    if has_long_base64_sequence(text, 600) and (text:find("certificate", 1, true) or text:find("pkcs", 1, true)) then ctx:add_module_reason(mod, "cert_base64_block") end
  end
end

local function scan_image_smuggling_info_part_module(ctx, part)
  if not module_enabled("image_smuggling_info") then return end
  local mod = "image_smuggling_info"
  local fname = part_get_filename_lc(part)
  if fname == "" then return end
  if (fname:match("%.png%.html$") or fname:match("%.jpg%.html$") or fname:match("%.gif%.html$") or fname:match("%.svg%.html$")) then ctx:add_module_reason(mod, "image_double_ext") end
  if fname:match("%.png$") or fname:match("%.jpg$") or fname:match("%.jpeg$") or fname:match("%.gif$") or fname:match("%.webp$") then
    if fname:find("invoice", 1, true) and fname:find("payload", 1, true) then ctx:add_module_reason(mod, "image_polyglot_name") end
    local text = lower_limit_text(part_get_content_text(part, 16384), 16384)
    if text ~= "" and (text:find("mz", 1, true) or text:find("pk\003\004", 1, true) or text:find("powershell", 1, true) or text:find("atob", 1, true)) then ctx:add_module_reason(mod, "image_embedded_payload_hint") end
  end
end

-- =========================
-- HTML Orchestration
-- =========================
local function scan_html_part(ctx, part)
  ctx.phase.html_parts_seen = ctx.phase.html_parts_seen + 1
  local ok_content, content = pcall(function() return part:get_content() end)
  if not ok_content or not content then ctx:add_error("part:get_content failed"); return end
  local ok_scan, err = pcall(function()
    local raw_html = normalize_text(content)
    raw_html = clamp_html_size(raw_html)
    scan_appinstaller_module(ctx, raw_html)
    local html_view = build_html_views(raw_html)
    if not Policy.has_basic_js_gate(html_view.raw_lc) then
      if html_view.raw_lc:find("begin certificate", 1, true) or html_view.raw_lc:find("data:application/x%-x509", 1, false) then scan_certificate_html_module(ctx, html_view) end
      return
    end
    ctx.phase.html_parts_scanned = ctx.phase.html_parts_scanned + 1
    if (not ctx.newsletter) and html_view.scan_lc:find("view in browser", 1, true) then
      ctx.newsletter = true
      ctx.newsletter_reason = "view_in_browser_link"
      ctx.heur_mul = compute_heur_mul(ctx.task, ctx.newsletter, ctx.newsletter_reason)
    end
    local script_entries = collect_script_entries(raw_html)
    scan_js_smuggling_html_module(ctx, html_view)
    scan_css_exfil_module(ctx, html_view)
    scan_clickfix_module(ctx, html_view)
    scan_push_abuse_html_module(ctx, html_view)
    scan_certificate_html_module(ctx, html_view)
    scan_script_blocks(ctx, html_view, script_entries)
    scan_external_scripts_module(ctx, script_entries)
  end)
  if not ok_scan then ctx:add_error("scan_html_part failed: " .. tostring(err)) end
end

local function scan_non_html_part(ctx, part)
  if not part_is_likely_attachment_vector(part) then
    scan_image_smuggling_info_part_module(ctx, part)
    return
  end
  local ok_scan, err = pcall(function()
    scan_attachment_vectors_module(ctx, part)
    scan_certificate_smuggling_part_module(ctx, part)
    scan_image_smuggling_info_part_module(ctx, part)
  end)
  if not ok_scan then ctx:add_error("scan_non_html_part failed: " .. tostring(err)) end
end

-- =========================
-- Scoring
-- =========================
local function finalize_score(ctx)
  local soft_part, hard_part = 0.0, 0.0
  if ctx.found_categories.JS_SMUGGLING   then soft_part = soft_part + get_effective_weight("js_smuggling") end
  if ctx.found_categories.OBFUSCATION    then soft_part = soft_part + get_effective_weight("obfuscation") end
  if ctx.found_categories.SUSPICIOUS_API then soft_part = soft_part + get_effective_weight("suspicious_api") end
  if ctx.found_categories.EVASION        then soft_part = soft_part + get_effective_weight("evasion") end
  if ctx.found_categories.CONTAINER      then hard_part = hard_part + get_effective_weight("container") end
  if ctx.found_categories.SCRIPT_HARD    then hard_part = hard_part + get_effective_weight("script_hard") end
  if ctx.found_categories.CRITICAL       then hard_part = hard_part + get_effective_weight("critical") end
  ctx.raw_score = soft_part + hard_part
  if ctx.found_categories.JS_SMUGGLING and ctx.found_categories.OBFUSCATION then ctx.combo_soft = ctx.combo_soft + (tonumber(W.COMBO_JS_OBFUS) or 0) end
  if ctx.found_categories.JS_SMUGGLING and ctx.found_categories.SUSPICIOUS_API then ctx.combo_soft = ctx.combo_soft + (tonumber(W.COMBO_JS_API) or 0) end
  if ctx.found_categories.JS_SMUGGLING and ctx.found_categories.EVASION then ctx.combo_soft = ctx.combo_soft + (tonumber(W.COMBO_JS_EVASION) or 0) end
  if (ctx.found_categories.CONTAINER or ctx.found_categories.SCRIPT_HARD or ctx.found_categories.CRITICAL) and ctx.found_categories.OBFUSCATION then ctx.combo_hard = ctx.combo_hard + (tonumber(W.COMBO_HARD_OBFUS) or 0) end
  soft_part = soft_part + ctx.combo_soft + ctx.soft_bonus_score
  hard_part = hard_part + ctx.combo_hard + ctx.hard_bonus_score
  local final_soft = soft_part * ctx.heur_mul
  local score = final_soft + hard_part
  ctx.after_combos = score
  if ctx.critical_kind and RUNTIME_CRITICAL_BOOST > 0 then score = score + RUNTIME_CRITICAL_BOOST; ctx:add_info("critical_boost") end
  ctx.after_boost = score
  if score > 0 and RUNTIME_MIN_SCORE > 0 and score < RUNTIME_MIN_SCORE then score = RUNTIME_MIN_SCORE; ctx:add_info("min_score") end
  ctx.after_floor = score
  if not has_hard_reasons(ctx) and score > RUNTIME_SOFT_ONLY_CAP then score = RUNTIME_SOFT_ONLY_CAP; ctx:add_info("soft_only_cap") end
  if score > RUNTIME_MAX_FINAL_SCORE then score = RUNTIME_MAX_FINAL_SCORE; ctx:add_info("max_final_score") end
  ctx.final_score = score
end

-- =========================
-- Summary
-- =========================
local function build_reason_summary(reasons)
  local tags = {}
  local function add_tag(tag) for _, v in ipairs(tags) do if v == tag then return end end; tags[#tags + 1] = tag end
  if reasons["dec_pe"] or reasons["pe_uint8array"] then add_tag("[KRITISCH:EXE]") end
  if reasons["dec_wasm"] or reasons["wasm_uint8array"] then add_tag("[KRITISCH:WASM]") end
  if reasons["dec_msix"] or reasons["dec_appx"] or reasons["ms_appinstaller_uri"] or reasons["dec_xml_appinstaller"] then add_tag("[APPINSTALLER]") end
  if reasons["dec_zip"] or reasons["dec_iso"] or reasons["dec_lnk"] or reasons["dec_vhdx"] or reasons["dec_ole"] or reasons["dec_cab"] or reasons["dec_7zip"] or reasons["dec_rar"] or reasons["att_chm_attachment"] or reasons["att_onenote_attachment"] or reasons["att_office_macro_container"] then add_tag("[CONTAINER]") end
  if reasons["dec_script"] or reasons["dec_js"] or reasons["dec_html"] or reasons["att_hta_attachment"] or reasons["att_script_attachment"] then add_tag("[SCRIPT_PAYLOAD]") end
  if reasons["atob_obfuscated"] or reasons["obfus_api"] or reasons["polymorphic_obfuscation"] or reasons["hex_array"] or reasons["fromcharcode_api"] then add_tag("[VERSCHLEIERT]") end
  if reasons["atob"] or reasons["blob"] or reasons["createObjectURL"] or reasons["fetch"] or reasons["split_payload"] or reasons["delayed_execution"] or reasons["uint8array_payload"] or reasons["att_svg_smuggling_context"] then add_tag("[JS_SMUGGLING]") end
  if reasons["geo_targeting_api"] or reasons["geo_location_api"] then add_tag("[GEO_TARGETING]") end
  if reasons["antisandbox_webdriver"] or reasons["hardware_check_evasion"] then add_tag("[EVASION]") end
  if reasons["localstorage_persistence"] or reasons["sessionstorage_persistence"] then add_tag("[PERSISTENCE]") end
  if reasons["domain_rotation"] or reasons["computed_redirect"] then add_tag("[ROTATION]") end
  if reasons["external_scripts"] then add_tag("[EXTERNAL_SCRIPT]") end
  if reasons["css_exfiltration"] then add_tag("[CSS_ABUSE]") end
  if reasons["clickfix_lure"] or reasons["fake_captcha_lure"] then add_tag("[CLICKFIX]") end
  if reasons["wasm_staged_payload"] or reasons["wasm_fetch_stage"] then add_tag("[WASM_STAGING]") end
  if reasons["blockchain_staged_payload"] or reasons["web3_api_usage"] then add_tag("[BLOCKCHAIN_STAGE]") end
  if reasons["css_code_execution"] or reasons["css_computedstyle_exec"] then add_tag("[CSS_CODE_EXEC]") end
  if reasons["att_pdf_javascript"] or reasons["att_pdf_openaction"] or reasons["att_pdf_launch"] then add_tag("[PDF_ACTIVE]") end
  if reasons["att_svg_script"] or reasons["att_svg_event_handler"] then add_tag("[SVG_ACTIVE]") end
  if reasons["cert_inline_pem"] or reasons["cert_inline_pkcs"] or reasons["cert_data_uri"] then add_tag("[CERT_SMUGGLING]") end
  if #tags == 0 then add_tag("[HTML_SMUGGLING]") end
  return table.concat(tags, " ")
end

-- =========================
-- Logging
-- =========================
local function log_detection_extended(task, score, critical_kind, NL, NL_reason, reasons, info_reasons, external_scripts, dur_ms)
  local why, info = table_keys_sorted(reasons), table_keys_sorted(info_reasons)
  local from = task:get_from_addr()
  local from_s = from and from:to_string() or "unknown"
  local ext_s = "none"
  if external_scripts and #external_scripts > 0 then ext_s = table.concat(dedupe_list_limit(external_scripts, MAX_EXTERNAL_REPORTED), "|") end
  local to, to_s = task:get_recipients("smtp"), "unknown"
  if to and to[1] then
    local a = to[1].addr
    if type(a) == "string" then to_s = a
    elseif a and a.to_string then local ok, s = pcall(function() return a:to_string() end); to_s = (ok and s) or tostring(a) or "unknown"
    else to_s = tostring(a) or "unknown" end
  end
  local ip_s = tostring(task:get_from_ip() or "unknown")
  local msgid = task:get_message_id() or "none"
  local subj  = task:get_subject() or "none"
  if #subj > 160 then subj = subj:sub(1, 160) end
  if #msgid > 160 then msgid = msgid:sub(1, 160) end
  rspamd_logger.infox(task, string.format(
    "HTML_SMUGGLING_DETECTION || version=%s || score=%.2f || critical=%s || newsletter=%s || nl_reason=%s || reasons=%s || info=%s || external_scripts=%s || from=%s || to=%s || ip=%s || msgid=%s || subject=%s || dur_ms=%.2f || ts=%d",
    VERSION, tonumber(score) or 0, safe_str(critical_kind, "none"), safe_str(NL, "false"), safe_str(NL_reason, "none"), table.concat(why, ","), table.concat(info, ","), redact_value(ext_s, 12), redact_value(from_s, 5), redact_value(to_s, 5), redact_value(ip_s, 4), redact_value(msgid, 8), redact_value(subj, 16), tonumber(dur_ms) or 0, os.time()
  ))
end

local function log_result(ctx, summary, det_s, info_s)
  local ok_log, err = pcall(function()
    if DEBUG or SCORE_DEBUG then
      rspamd_logger.infox(ctx.task, string.format(
        "HTML_SMUGGLING_SCORE_DEBUG || v=%s || raw=%.2f || after_combos=%.2f || after_boost=%.2f || after_floor=%.2f || final=%.2f || heur_mul=%.2f || newsletter=%s || nl_reason=%s || reasons=%s || info=%s || combo_soft=%.2f || combo_hard=%.2f || hard_present=%s || class_js=%s || class_obfus=%s || class_api=%s || class_evasion=%s || class_container=%s || class_script_hard=%s || class_critical=%s || soft_bonus=%.2f || hard_bonus=%.2f",
        VERSION, tonumber(ctx.raw_score) or 0, tonumber(ctx.after_combos) or 0, tonumber(ctx.after_boost) or 0, tonumber(ctx.after_floor) or 0, tonumber(ctx.final_score) or 0, tonumber(ctx.heur_mul) or 1.0, safe_str(ctx.newsletter, "false"), safe_str(ctx.newsletter_reason, "none"), det_s, info_s, tonumber(ctx.combo_soft) or 0, tonumber(ctx.combo_hard) or 0, tostring(has_hard_reasons(ctx)), tostring(ctx.found_categories.JS_SMUGGLING), tostring(ctx.found_categories.OBFUSCATION), tostring(ctx.found_categories.SUSPICIOUS_API), tostring(ctx.found_categories.EVASION), tostring(ctx.found_categories.CONTAINER), tostring(ctx.found_categories.SCRIPT_HARD), tostring(ctx.found_categories.CRITICAL), tonumber(ctx.soft_bonus_score) or 0, tonumber(ctx.hard_bonus_score) or 0
      ))
    end
    local dur_ms = (rspamd_util.get_ticks() - ctx.started_at) / 1000.0
    if ENABLE_PHASE_DEBUG then
      rspamd_logger.infox(ctx.task, string.format(
        "HTML_SMUGGLING_PHASE_DEBUG || v=%s || html_seen=%d || html_scanned=%d || attach_seen=%d || attach_scanned=%d || script_seen=%d || script_scanned=%d || decode_candidates=%d || decode_success=%d || decode_fail=%d || errors=%d",
        VERSION, tonumber(ctx.phase.html_parts_seen) or 0, tonumber(ctx.phase.html_parts_scanned) or 0, tonumber(ctx.phase.attach_parts_seen) or 0, tonumber(ctx.phase.attach_parts_scanned) or 0, tonumber(ctx.phase.script_blocks_seen) or 0, tonumber(ctx.phase.script_blocks_scanned) or 0, tonumber(ctx.phase.decode_candidates) or 0, tonumber(ctx.phase.decode_success) or 0, tonumber(ctx.phase.decode_fail) or 0, #(ctx.errors or {})
      ))
    end
    if (FORCE_EXTENDED_LOG and ctx.final_score >= FORCE_EXTENDED_LOG_MIN_SCORE) or (ctx.final_score >= LOG_SCORE_THRESHOLD) or DEBUG then
      log_detection_extended(ctx.task, ctx.final_score, ctx.critical_kind, ctx.newsletter, ctx.newsletter_reason, ctx.reasons, ctx.info_reasons, ctx.external_scripts, dur_ms)
    end
    if (ctx.final_score >= LOG_SCORE_THRESHOLD or DEBUG) and LOG_SIMPLE_LINE then
      local from = ctx.task:get_from_addr()
      local from_s = from and from:to_string() or "unknown"
      rspamd_logger.infox(ctx.task, string.format(
        "HTML_SMUGGLING %s || score=%.2f || critical=%s || NL=%s(%s) || heur_mul=%.2f || deep_scan=%s || summary=%s || reasons=%s || info=%s || external=%s || from=%s || subject=%s || dur_ms=%.2f",
        VERSION, tonumber(ctx.final_score) or 0, safe_str(ctx.critical_kind, "none"), safe_str(ctx.newsletter, "false"), safe_str(ctx.newsletter_reason, "none"), tonumber(ctx.heur_mul) or 1.0, safe_str(ctx.deep_scan, "true"), summary, det_s, info_s, safe_str(table.concat(dedupe_list_limit(ctx.external_scripts, MAX_EXTERNAL_REPORTED), ","), ""), redact_value(from_s, 5), redact_value(ctx.task:get_subject() or "", 16), tonumber(dur_ms) or 0
      ))
    end
    if dur_ms >= SLOW_LOG_MS then rspamd_logger.infox(ctx.task, string.format("HTML_SMUGGLING_SLOW || v=%s || dur_ms=%.2f || reasons=%s || info=%s", VERSION, tonumber(dur_ms) or 0, det_s, info_s)) end
  end)
  if not ok_log then rspamd_logger.errx(ctx.task, "HTML_SMUGGLING logging failed: " .. tostring(err)) end
end

-- =========================
-- Marker
-- =========================
local function apply_markers(ctx)
  local task, reasons, info = ctx.task, ctx.reasons, ctx.info_reasons
  if reasons["serviceworker_api"] then task:insert_result("HTML_SMUGGLING_MARKER_SERVICEWORKER", 1.0) end
  if reasons["webcrypto_api"] then task:insert_result("HTML_SMUGGLING_MARKER_WEBCRYPTO", 1.0) end
  if reasons["qr_canvas_api"] then task:insert_result("HTML_SMUGGLING_MARKER_QR_CANVAS", 1.0) end
  if reasons["split_payload"] then task:insert_result("HTML_SMUGGLING_MARKER_SPLIT_PAYLOAD", 1.0) end
  if reasons["hex_array"] then task:insert_result("HTML_SMUGGLING_MARKER_HEX_ARRAY", 1.0) end
  if reasons["geo_targeting_api"] or reasons["geo_location_api"] or reasons["timezone_targeting"] then task:insert_result("HTML_SMUGGLING_MARKER_GEO_TARGETING", 1.0) end
  if reasons["antisandbox_webdriver"] or reasons["hardware_check_evasion"] or reasons["human_interaction_required"] then task:insert_result("HTML_SMUGGLING_MARKER_EVASION", 1.0) end
  if reasons["localstorage_persistence"] or reasons["sessionstorage_persistence"] then task:insert_result("HTML_SMUGGLING_MARKER_PERSISTENCE", 1.0) end
  if reasons["domain_rotation"] or reasons["computed_redirect"] then task:insert_result("HTML_SMUGGLING_MARKER_DOMAIN_ROTATION", 1.0) end
  if reasons["clickfix_lure"] or reasons["fake_captcha_lure"] or reasons["clipboard_exec_lure"] then task:insert_result("HTML_SMUGGLING_MARKER_CLICKFIX", 1.0) end
  if reasons["wasm_staged_payload"] or reasons["wasm_fetch_stage"] or reasons["wasm_inline_stage"] then task:insert_result("HTML_SMUGGLING_MARKER_WASM_STAGING", 1.0) end
  if reasons["blockchain_staged_payload"] or reasons["web3_api_usage"] or reasons["ethers_contract_payload"] then task:insert_result("HTML_SMUGGLING_MARKER_BLOCKCHAIN_STAGING", 1.0) end
  if reasons["css_code_execution"] or reasons["css_computedstyle_exec"] then task:insert_result("HTML_SMUGGLING_MARKER_CSS_CODE_EXEC", 1.0) end
  if reasons["rc4_ksa_pattern"] or reasons["rc4_prga_pattern"] or reasons["rc4_xor_loop"] then task:insert_result("HTML_SMUGGLING_MARKER_RC4_DECRYPT", 1.0) end
  if reasons["att_pdf_javascript"] or reasons["att_pdf_openaction"] or reasons["att_pdf_launch"] then task:insert_result("HTML_SMUGGLING_MARKER_PDF_ACTIVE", 1.0) end
  if reasons["att_svg_script"] or reasons["att_svg_event_handler"] or reasons["att_svg_foreignobject"] then task:insert_result("HTML_SMUGGLING_MARKER_SVG_ACTIVE", 1.0) end
  if reasons["cert_inline_pem"] or reasons["cert_inline_pkcs"] or reasons["cert_data_uri"] then task:insert_result("HTML_SMUGGLING_MARKER_CERT_SMUGGLING", 1.0) end
  if info["push_notification_flow"] or info["push_permission_request"] or info["push_serviceworker_combo"] then task:insert_result("HTML_SMUGGLING_MARKER_PUSH_ABUSE", 1.0) end
  if ctx.found_categories.JS_SMUGGLING then task:insert_result("HTML_SMUGGLING_CLASS_JS", 1.0) end
  if ctx.found_categories.OBFUSCATION then task:insert_result("HTML_SMUGGLING_CLASS_OBFUS", 1.0) end
  if ctx.found_categories.SUSPICIOUS_API then task:insert_result("HTML_SMUGGLING_MARKER_SUSPICIOUS_API", 1.0) end
  if ctx.found_categories.CONTAINER then task:insert_result("HTML_SMUGGLING_CLASS_CONTAINER", 1.0) end
  if ctx.found_categories.SCRIPT_HARD then task:insert_result("HTML_SMUGGLING_CLASS_SCRIPT_HARD", 1.0) end
  if ctx.found_categories.CRITICAL then task:insert_result("HTML_SMUGGLING_CLASS_CRITICAL", 1.0) end
  local critical_map = {
    PE = "HTML_SMUGGLING_CRITICAL_PE",
    WASM = "HTML_SMUGGLING_CRITICAL_WASM",
    XML_APPINSTALLER = "HTML_SMUGGLING_CRITICAL_APPINSTALLER",
    VHDX = "HTML_SMUGGLING_CRITICAL_VHDX",
    ISO = "HTML_SMUGGLING_CRITICAL_ISO",
    LNK = "HTML_SMUGGLING_CRITICAL_LNK",
    OLE = "HTML_SMUGGLING_CRITICAL_OLE",
    ZIP = "HTML_SMUGGLING_CRITICAL_ZIP",
    SCRIPT = "HTML_SMUGGLING_CRITICAL_SCRIPT",
    MSIX = "HTML_SMUGGLING_CRITICAL_MSIX",
    APPX = "HTML_SMUGGLING_CRITICAL_APPX",
    CAB = "HTML_SMUGGLING_CRITICAL_CAB",
    ["7ZIP"] = "HTML_SMUGGLING_CRITICAL_7ZIP",
    RAR = "HTML_SMUGGLING_CRITICAL_RAR",
    CHM = "HTML_SMUGGLING_CRITICAL_CHM",
    ONENOTE = "HTML_SMUGGLING_CRITICAL_ONENOTE",
  }
  if ctx.critical_kind and critical_map[ctx.critical_kind] then task:insert_result(critical_map[ctx.critical_kind], 1.0) end
end

-- =========================
-- Result schreiben
-- =========================
local function write_result(ctx)
  if ctx.final_score <= 0 then return end
  local det, info = table_keys_sorted(ctx.reasons), table_keys_sorted(ctx.info_reasons)
  local det_s, info_s = table.concat(det, ","), table.concat(info, ",")
  local summary = build_reason_summary(ctx.reasons)
  local result_text = summary .. " Details: " .. det_s
  if info_s ~= "" then result_text = result_text .. " Info: " .. info_s end
  if TEST_MODE then ctx.task:insert_result("HTML_SMUGGLING_TEST", ctx.final_score, "Test: " .. result_text)
  else ctx.task:insert_result("HTML_SMUGGLING_PAYLOAD", ctx.final_score, result_text) end
  log_result(ctx, summary, det_s, info_s)
end

-- =========================
-- Main
-- =========================
local function detect_html_smuggling_payload(task)
  if not ENABLED then return end
  local parts = SAFE_TASK_ACCESS and safe_call(nil, function() return task:get_parts() end) or task:get_parts()
  if not parts then return end
  local ctx = Detector.new(task)
  local NL, NL_reason = is_newsletter(task)
  ctx.newsletter = NL
  ctx.newsletter_reason = NL_reason
  ctx.heur_mul = compute_heur_mul(task, NL, NL_reason)
  local trusted_news = is_trusted_newsletter_sender(task)
  ctx.deep_scan = true
  if NL and NL_reason == "header" and (not DEEP_SCAN_NEWSLETTER_HEADER) then ctx.deep_scan = false end
  if trusted_news then ctx.deep_scan = true end
  for _, p in ipairs(parts) do
    if part_is_htmlish(p) then
      scan_html_part(ctx, p)
    else
      scan_non_html_part(ctx, p)
    end
    if has_any_critical_kind(ctx) then break end
  end
  finalize_score(ctx)
  apply_markers(ctx)
  write_result(ctx)
end

-- =========================
-- Init
-- =========================
clamp_runtime_values()
local CONFIG_OK, CONFIG_MSG = validate_config_or_raise()
if LOG_CONFIG_VALIDATION and (not CONFIG_OK) then rspamd_logger.errx("html_smuggling config validation failed: " .. tostring(CONFIG_MSG)) end

-- =========================
-- Symbole registrieren
-- =========================
if ENABLED then
  local smuggling_id = rspamd_config:register_symbol{
    name = "HTML_SMUGGLING_PAYLOAD",
    callback = detect_html_smuggling_payload,
    score = 1.0,
    flags = "dynamic",
    group = "phishing",
    type = "callback",
    description = "Detect HTML smuggling and decoded payload indicators (" .. VERSION .. ")"
  }
  local function reg_marker(name, desc)
    rspamd_config:register_symbol{ name = name, parent = smuggling_id, type = "virtual", score = 0.0, group = "phishing", description = desc }
  end
  reg_marker("HTML_SMUGGLING_TEST",                      "HTML smuggling test mode marker")
  reg_marker("HTML_SMUGGLING_MARKER_SERVICEWORKER",      "HTML smuggling marker: ServiceWorker API")
  reg_marker("HTML_SMUGGLING_MARKER_WEBCRYPTO",          "HTML smuggling marker: WebCrypto API")
  reg_marker("HTML_SMUGGLING_MARKER_QR_CANVAS",          "HTML smuggling marker: QR/Canvas lure")
  reg_marker("HTML_SMUGGLING_MARKER_SPLIT_PAYLOAD",      "HTML smuggling marker: split payload construction")
  reg_marker("HTML_SMUGGLING_MARKER_HEX_ARRAY",          "HTML smuggling marker: hex byte array detected")
  reg_marker("HTML_SMUGGLING_MARKER_SUSPICIOUS_API",     "HTML smuggling marker: suspicious browser API usage")
  reg_marker("HTML_SMUGGLING_MARKER_GEO_TARGETING",      "HTML smuggling marker: geo targeting or geo fencing")
  reg_marker("HTML_SMUGGLING_MARKER_EVASION",            "HTML smuggling marker: antisandbox or interaction evasion")
  reg_marker("HTML_SMUGGLING_MARKER_PERSISTENCE",        "HTML smuggling marker: localStorage or sessionStorage persistence")
  reg_marker("HTML_SMUGGLING_MARKER_DOMAIN_ROTATION",    "HTML smuggling marker: domain rotation or computed redirect")
  reg_marker("HTML_SMUGGLING_MARKER_CLICKFIX",           "HTML smuggling marker: ClickFix or fake CAPTCHA lure")
  reg_marker("HTML_SMUGGLING_MARKER_WASM_STAGING",       "HTML smuggling marker: WASM staging or WASM smuggling context")
  reg_marker("HTML_SMUGGLING_MARKER_BLOCKCHAIN_STAGING", "HTML smuggling marker: blockchain or web3 staged payload")
  reg_marker("HTML_SMUGGLING_MARKER_CSS_CODE_EXEC",      "HTML smuggling marker: CSS to JS execution pattern")
  reg_marker("HTML_SMUGGLING_MARKER_PUSH_ABUSE",         "HTML smuggling marker: push notification abuse flow")
  reg_marker("HTML_SMUGGLING_MARKER_RC4_DECRYPT",        "HTML smuggling marker: RC4 or symmetric decryption pattern")
  reg_marker("HTML_SMUGGLING_MARKER_PDF_ACTIVE",         "HTML smuggling marker: active PDF content")
  reg_marker("HTML_SMUGGLING_MARKER_SVG_ACTIVE",         "HTML smuggling marker: active SVG content")
  reg_marker("HTML_SMUGGLING_MARKER_CERT_SMUGGLING",     "HTML smuggling marker: certificate or PKCS smuggling context")
  reg_marker("HTML_SMUGGLING_CLASS_JS",                  "HTML smuggling class: JavaScript smuggling behaviour")
  reg_marker("HTML_SMUGGLING_CLASS_OBFUS",               "HTML smuggling class: obfuscation detected")
  reg_marker("HTML_SMUGGLING_CLASS_CONTAINER",           "HTML smuggling class: container style payload detected")
  reg_marker("HTML_SMUGGLING_CLASS_SCRIPT_HARD",         "HTML smuggling class: decoded hard script payload")
  reg_marker("HTML_SMUGGLING_CLASS_CRITICAL",            "HTML smuggling class: critical payload detected")
  reg_marker("HTML_SMUGGLING_CRITICAL_PE",               "HTML smuggling decoded PE payload")
  reg_marker("HTML_SMUGGLING_CRITICAL_WASM",             "HTML smuggling decoded WebAssembly")
  reg_marker("HTML_SMUGGLING_CRITICAL_APPINSTALLER",     "HTML smuggling decoded AppInstaller XML")
  reg_marker("HTML_SMUGGLING_CRITICAL_VHDX",             "HTML smuggling decoded VHDX")
  reg_marker("HTML_SMUGGLING_CRITICAL_ISO",              "HTML smuggling decoded ISO")
  reg_marker("HTML_SMUGGLING_CRITICAL_LNK",              "HTML smuggling decoded LNK")
  reg_marker("HTML_SMUGGLING_CRITICAL_OLE",              "HTML smuggling decoded OLE")
  reg_marker("HTML_SMUGGLING_CRITICAL_ZIP",              "HTML smuggling decoded ZIP")
  reg_marker("HTML_SMUGGLING_CRITICAL_SCRIPT",           "HTML smuggling decoded script payload")
  reg_marker("HTML_SMUGGLING_CRITICAL_MSIX",             "HTML smuggling decoded MSIX")
  reg_marker("HTML_SMUGGLING_CRITICAL_APPX",             "HTML smuggling decoded APPX")
  reg_marker("HTML_SMUGGLING_CRITICAL_CAB",              "HTML smuggling decoded CAB")
  reg_marker("HTML_SMUGGLING_CRITICAL_7ZIP",             "HTML smuggling decoded 7ZIP")
  reg_marker("HTML_SMUGGLING_CRITICAL_RAR",              "HTML smuggling decoded RAR")
  reg_marker("HTML_SMUGGLING_CRITICAL_CHM",              "HTML smuggling attachment CHM")
  reg_marker("HTML_SMUGGLING_CRITICAL_ONENOTE",          "HTML smuggling attachment OneNote")
end

-- =========================
-- Debug Export
-- =========================
if DEBUG then
  return {
    Detector = Detector,
    Policy = Policy,
    scan_appinstaller_module = scan_appinstaller_module,
    scan_js_smuggling_html_module = scan_js_smuggling_html_module,
    scan_obfuscation_script_module = scan_obfuscation_script_module,
    scan_css_exfil_module = scan_css_exfil_module,
    scan_clickfix_module = scan_clickfix_module,
    scan_external_scripts_module = scan_external_scripts_module,
    scan_push_abuse_html_module = scan_push_abuse_html_module,
    scan_uint8array_module = scan_uint8array_module,
    scan_geo_targeting_module = scan_geo_targeting_module,
    scan_evasion_module = scan_evasion_module,
    scan_persistence_module = scan_persistence_module,
    scan_domain_rotation_module = scan_domain_rotation_module,
    scan_wasm_staging_module = scan_wasm_staging_module,
    scan_blockchain_staging_module = scan_blockchain_staging_module,
    scan_css_code_exec_module = scan_css_code_exec_module,
    scan_rc4_module = scan_rc4_module,
    scan_decoded_payload_module = scan_decoded_payload_module,
    scan_attachment_vectors_module = scan_attachment_vectors_module,
    scan_certificate_smuggling_part_module = scan_certificate_smuggling_part_module,
    scan_image_smuggling_info_part_module = scan_image_smuggling_info_part_module,
    extract_b64_candidates = extract_b64_candidates,
    sniff_decoded = sniff_decoded,
    calculate_entropy = calculate_entropy,
    finalize_score = finalize_score,
    MODULES = MODULES,
    REASON_MODULE_MAP = REASON_MODULE_MAP,
  }
end
