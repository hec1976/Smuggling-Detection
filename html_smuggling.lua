-- /etc/rspamd/lua.local.d/html_smuggling.lua
-- HTML Smuggling Detection v2.9-r1
-- Fokus: saubere Scoring Stages, kein goto, korrektes after_combos und after_auth
-- Optimiert fuer High Volume

local rspamd_logger = require "rspamd_logger"
local rspamd_util   = require "rspamd_util"

local VERSION = "2.9-r1"

-- =========================
-- Config lesen
-- =========================
local CFG = rspamd_config:get_all_opt("html_smuggling") or {}

local ENABLED   = (CFG.enabled ~= false)
local DEBUG     = (CFG.debug == true)
local TEST_MODE = (CFG.test_mode == true)

-- Logging Steuerung
local LOG_SCORE_THRESHOLD = tonumber(CFG.log_score_threshold) or 5.0
local LOG_SIMPLE_LINE     = (CFG.log_simple_line == true)
local SCORE_DEBUG         = (CFG.score_debug == true)  -- separates Score Debug Logging (unabhaengig von DEBUG)

-- v2.7+ Extended Logging forcieren (kontrolliert)
local FORCE_EXTENDED_LOG           = (CFG.force_extended_log == true)
local FORCE_EXTENDED_LOG_MIN_SCORE = tonumber(CFG.force_extended_log_min_score) or 0.1

-- Newsletter Handling
local DEEP_SCAN_NEWSLETTER_HEADER = (CFG.deep_scan_newsletter_header ~= false)

-- Scoring Steuerung (neu/sauber)
local MIN_SCORE           = tonumber(CFG.min_score) or 0.0
local CRITICAL_BOOST      = tonumber(CFG.critical_boost) or 0.0
local AUTH_MUL_ENABLED    = (CFG.auth_mul_enabled == true)

-- Multiplikatoren
local HEUR_MUL_DEFAULT            = tonumber(CFG.heur_mul_default) or 1.0
local HEUR_MUL_NEWSLETTER_HEADER  = tonumber(CFG.heur_mul_newsletter_header) or 0.3
local HEUR_MUL_NEWSLETTER_HEUR    = tonumber(CFG.heur_mul_newsletter_heuristic) or 0.4
local HEUR_MUL_TRUSTED_NEWSLETTER = tonumber(CFG.heur_mul_trusted_newsletter) or 0.1

-- =========================
-- LIMITS (Defaults)
-- =========================
local LIMITS = {
  scan = {
    max_bytes = 200 * 1024,
    smart_chunk = 50 * 1024,
  },
  b64 = {
    min_len = 200,
    max_candidates = 6,
    max_scan_bytes = 500 * 1024,
    min_decode_total = 1500,
    big_threshold = 5000,
    huge_threshold = 20000,
    join_max_parts = 5,
    join_max_len = 180000,
  },
  decode = {
    max_bytes = 160 * 1024,
    joined_len_mul = 2,
  },
  script = {
    max_check = 3,
    max_external = 5,
    max_vars = 20,
  },
  obfus = {
    min_frag_len = 16,
    virtual_trigger_len = 120,
    virtual_max_payloads = 3,
    resolve_passes = 8,

    max_uint8array_bytes = 2048,
    max_entropy_check_bytes = 8192,
    css_max_style_size = 10000,
    max_delayed_exec_context = 500,
  }
}

-- =========================
-- Weights (Defaults)
-- =========================
local W = {
  atob = 0.2,
  blob = 0.2,
  createobjecturl = 0.3,
  data_uri = 0.1,
  iframe_src = 0.2,
  fetch = 0.1,
  filereader = 0.1,
  uint8array = 0.1,

  array_index_api = 0.3,
  function_constructor = 0.4,
  eval_api = 0.3,
  settimeout_api = 0.3,
  webworker_api = 0.5,
  serviceworker_api = 0.5,
  webassembly_api = 0.6,

  event_handler = 0.3,
  split_payload = 1.0,
  external_script = 0.5,

  obfus = 0.8,

  ms_appinstaller_uri = 3.5,
  appinstaller_file = 0.8,

  hex_array = 0.8,

  b64_total_len_big = 0.6,
  b64_total_len_huge = 1.2,
  b64_joined_parts = 0.4,
  b64_long_html = 0.4,

  dec_pe = 8.0,
  dec_zip = 5.0,
  dec_msix = 6.0,
  dec_appx = 6.0,
  dec_cab  = 4.0,
  dec_7zip = 4.0,
  dec_rar  = 4.0,

  dec_pdf = 1.5,
  dec_js = 2.5,
  dec_html = 2.0,
  dec_xml = 0.6,
  dec_xml_appinstaller = 3.0,
  dec_ole = 3.0,
  dec_vhdx = 5.0,
  dec_iso = 6.0,
  dec_lnk = 5.0,
  dec_script = 4.0,
  dec_bin = 0.2,
  dec_wasm = 8.0,

  combo_smuggling_api = 2.0,
  combo_atob_plus_b64 = 2.0,
  combo_msapp_plus_xml = 3.0,
  combo_zip_plus_smuggling = 2.0,
  combo_pe = 4.0,
  combo_hex_plus_smuggling = 1.5,
  combo_container_plus_smuggling = 2.0,
  combo_wasm_plus_smuggling = 3.0,
  combo_external_script = 1.5,
  combo_split_payload = 2.0,

  atob_obfuscated = 1.2,
  delayed_execution = 2.0,
  wasm_uint8array = 8.0,
  pe_uint8array = 10.0,
  large_uint8array = 3.0,
  css_exfiltration = 2.5,
  polymorphic_obfuscation = 2.0,
}

local function merge_numbers(dst, src)
  if type(dst) ~= "table" or type(src) ~= "table" then return end
  for k, v in pairs(src) do
    local n = tonumber(v)
    if n ~= nil and dst[k] ~= nil then
      dst[k] = n
    end
  end
end

local function merge_numbers_deep(dst, src)
  if type(dst) ~= "table" or type(src) ~= "table" then return end
  for k, v in pairs(src) do
    if type(v) == "table" and type(dst[k]) == "table" then
      merge_numbers_deep(dst[k], v)
    else
      local n = tonumber(v)
      if n ~= nil and dst[k] ~= nil then
        dst[k] = n
      end
    end
  end
end

local function apply_legacy_limits(src)
  if type(src) ~= "table" then return end

  local function set_if_num(path, v)
    local n = tonumber(v)
    if n == nil then return end
    local t = LIMITS
    for i = 1, #path - 1 do
      t = t[path[i]]
      if type(t) ~= "table" then return end
    end
    local k = path[#path]
    if t[k] ~= nil then t[k] = n end
  end

  set_if_num({"scan","max_bytes"}, src.max_scan_bytes)
  set_if_num({"scan","smart_chunk"}, src.smart_chunk)

  set_if_num({"b64","min_len"}, src.min_b64_len)
  set_if_num({"b64","max_candidates"}, src.max_b64_candidates)
  set_if_num({"b64","max_scan_bytes"}, src.max_b64_scan_bytes)
  set_if_num({"b64","min_decode_total"}, src.min_decode_total_b64)
  set_if_num({"b64","join_max_parts"}, src.join_max_parts)
  set_if_num({"b64","join_max_len"}, src.join_max_len)
  set_if_num({"b64","big_threshold"}, src.b64_total_len_big)
  set_if_num({"b64","huge_threshold"}, src.b64_total_len_huge)

  set_if_num({"decode","max_bytes"}, src.max_decode_bytes)
  set_if_num({"decode","joined_len_mul"}, src.decode_joined_len_mul)

  set_if_num({"script","max_check"}, src.scripts_max_check)
  set_if_num({"script","max_external"}, src.max_external_scripts)
  set_if_num({"script","max_vars"}, src.max_vars_to_track)

  set_if_num({"obfus","min_frag_len"}, src.min_frag_len)
  set_if_num({"obfus","virtual_trigger_len"}, src.virtual_trigger_len)
  set_if_num({"obfus","virtual_max_payloads"}, src.virtual_max_payloads)
  set_if_num({"obfus","resolve_passes"}, src.resolve_passes)
  set_if_num({"obfus","max_uint8array_bytes"}, src.max_uint8array_bytes)
  set_if_num({"obfus","max_entropy_check_bytes"}, src.max_entropy_check_bytes)
  set_if_num({"obfus","css_max_style_size"}, src.css_max_style_size)
  set_if_num({"obfus","max_delayed_exec_context"}, src.max_delayed_exec_context)
end

if type(CFG.limits) == "table" then
  if CFG.limits.scan or CFG.limits.b64 or CFG.limits.decode or CFG.limits.script or CFG.limits.obfus then
    merge_numbers_deep(LIMITS, CFG.limits)
  else
    apply_legacy_limits(CFG.limits)
  end
end

if type(CFG.weights) == "table" then
  merge_numbers(W, CFG.weights)
end

local LSCAN   = LIMITS.scan
local LB64    = LIMITS.b64
local LDEC    = LIMITS.decode
local LSCRIPT = LIMITS.script
local LOBFUS  = LIMITS.obfus

-- =========================
-- Maps aus Conf
-- =========================
local SAFE_SCRIPT_DOMAINS_MAP = nil
if CFG.safe_script_domains_map and type(CFG.safe_script_domains_map) == "string" then
  SAFE_SCRIPT_DOMAINS_MAP = rspamd_config:add_map{
    url = CFG.safe_script_domains_map,
    type = "set",
    description = "html_smuggling safe script domains map"
  }
end

local TRUSTED_NEWSLETTER_DOMAINS_MAP = nil
if CFG.trusted_newsletter_domains_map and type(CFG.trusted_newsletter_domains_map) == "string" then
  TRUSTED_NEWSLETTER_DOMAINS_MAP = rspamd_config:add_map{
    url = CFG.trusted_newsletter_domains_map,
    type = "set",
    description = "html_smuggling trusted newsletter domains map"
  }
end

local UNSAFE_SCRIPT_DOMAINS_MAP = nil
if CFG.unsafe_script_domains_map and type(CFG.unsafe_script_domains_map) == "string" then
  UNSAFE_SCRIPT_DOMAINS_MAP = rspamd_config:add_map{
    url = CFG.unsafe_script_domains_map,
    type = "set",
    description = "html_smuggling unsafe script domains map"
  }
end

-- =========================
-- Helper
-- =========================
local function normalize_text(s)
  if not s then return "" end
  if type(s) == "string" then return s end
  if s.to_string then
    local ok, out = pcall(function() return s:to_string() end)
    if ok and out then return out end
  end
  return tostring(s) or ""
end

local function trim(s)
  if not s then return "" end
  return (tostring(s):gsub("^%s+", ""):gsub("%s+$", ""))
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
  local t = s:gsub("%s+", "")
  t = t:gsub("%-", "+"):gsub("_", "/")
  local mod = #t % 4
  if mod == 2 then t = t .. "=="
  elseif mod == 3 then t = t .. "="
  end
  return t
end

local function is_frag_base64ish(s)
  if not s then return false end
  if #s < (LOBFUS.min_frag_len or 16) then return false end
  return s:match("^[A-Za-z0-9%+/_%%-]+=*$") ~= nil
end

local function is_base64ish(s)
  if not s or #s < (LB64.min_len or 200) then return false end
  local t = s:gsub("%s+", "")
  if not t:match("^[A-Za-z0-9%+/_%%-]+=*$") then return false end
  return true
end

local function safe_decode_base64(task, b64, limit)
  local ok, res = pcall(function()
    return rspamd_util.decode_base64(b64, limit)
  end)
  if not ok then
    if task then rspamd_logger.warnx(task, "Base64 decode failed") end
    return nil
  end
  return res
end

-- =========================
-- Entropy
-- =========================
local function calculate_entropy(s)
  if not s or #s == 0 then return 0 end
  if #s > (LOBFUS.max_entropy_check_bytes or 8192) then
    s = s:sub(1, LOBFUS.max_entropy_check_bytes)
  end

  local freq = {}
  for i = 1, #s do
    local c = s:sub(i,i)
    freq[c] = (freq[c] or 0) + 1
  end

  local entropy = 0
  local len = #s
  for _, count in pairs(freq) do
    local p = count / len
    if p > 0 then
      entropy = entropy - (p * math.log(p) / math.log(2))
    end
  end
  return entropy
end

-- =========================
-- Extended Logging (1 String)
-- =========================
local function log_detection_extended(task, score, critical_kind, NL, NL_reason, reasons, external_scripts)
  local why = table_keys_sorted(reasons)
  local from = task:get_from_addr()
  local from_s = from and from:to_string() or "unknown"

  local ext_s = "none"
  if external_scripts and #external_scripts > 0 then
    ext_s = table.concat(external_scripts, "|")
  end

  local to = task:get_recipients('smtp')
  local to_s = "unknown"
  if to and to[1] then
    local a = to[1].addr
    if type(a) == "string" then
      to_s = a
    elseif a and a.to_string then
      local ok, s = pcall(function() return a:to_string() end)
      to_s = (ok and s) or tostring(a) or "unknown"
    else
      to_s = tostring(a) or "unknown"
    end
  end

  local ip = task:get_from_ip()
  local ip_s = ip and tostring(ip) or "unknown"

  local msgid = task:get_message_id() or "none"
  local subj = task:get_subject() or "none"

  local auth_status = {}
  if task:get_symbol("R_DKIM_ALLOW") then auth_status[#auth_status + 1] = "DKIM_OK" end
  if task:get_symbol("R_DKIM_REJECT") then auth_status[#auth_status + 1] = "DKIM_FAIL" end
  if task:get_symbol("R_SPF_ALLOW") then auth_status[#auth_status + 1] = "SPF_OK" end
  if task:get_symbol("R_SPF_FAIL") then auth_status[#auth_status + 1] = "SPF_FAIL" end
  local auth_s = #auth_status > 0 and table.concat(auth_status, ",") or "none"

  local line = string.format(
    "HTML_SMUGGLING_DETECTION || version=%s || score=%.2f || critical=%s || newsletter=%s || nl_reason=%s || reasons=%s || external_scripts=%s || from=%s || to=%s || ip=%s || msgid=%s || subject=%s || auth=%s || ts=%d",
    VERSION,
    tonumber(score) or 0,
    safe_str(critical_kind, "none"),
    safe_str(NL, "false"),
    safe_str(NL_reason, "none"),
    table.concat(why, ","),
    safe_str(ext_s, "none"),
    safe_str(from_s, "unknown"),
    safe_str(to_s, "unknown"),
    safe_str(ip_s, "unknown"),
    safe_str(msgid, "none"),
    safe_str(subj, "none"),
    safe_str(auth_s, "none"),
    os.time()
  )
  rspamd_logger.infox(task, line)
end

-- =========================
-- URL Host und Maps
-- =========================
local function host_from_url(u)
  if not u or u == "" then return nil end
  local s = tostring(u):lower()
  if s:match("^/") then return nil end
  s = s:gsub("^https?://", "")
  s = s:gsub("^//", "")
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
  if not u or u == "" then return false end
  local s = tostring(u):lower()
  if s:match("^javascript:") or s:match("^data:") or s:match("^file:") then return false end

  local host = host_from_url(u)
  if not host then return false end

  if UNSAFE_SCRIPT_DOMAINS_MAP and map_has_domain(UNSAFE_SCRIPT_DOMAINS_MAP, host) then
    return false
  end
  if SAFE_SCRIPT_DOMAINS_MAP and map_has_domain(SAFE_SCRIPT_DOMAINS_MAP, host) then
    return true
  end
  return false
end

-- =========================
-- Newsletter Detection
-- =========================
local function is_newsletter(task)
  local h = task:get_header("X-HEC-MailClass") or task:get_header("X-HEC-Category")
  if h then
    local hl = tostring(h):lower()
    if hl:find("newsletter", 1, true) or hl:find("marketing", 1, true) or hl:find("bulk", 1, true) then
      return true, "header"
    end
  end
  if task:get_header("List-Id") then return true, "list-id" end
  if task:get_header("List-Unsubscribe") then return true, "list-unsub" end

  local prec = task:get_header("Precedence") or task:get_header("X-Precedence")
  if prec and tostring(prec):lower():find("bulk", 1, true) then
    return true, "precedence"
  end

  local xm = task:get_header("X-Mailer")
  if xm then
    local xml = tostring(xm):lower()
    if xml:find("mailchimp", 1, true) then return true, "mailer_mailchimp" end
    if xml:find("sendgrid", 1, true) then return true, "mailer_sendgrid" end
    if xml:find("salesforce", 1, true) or xml:find("marketing cloud", 1, true) then
      return true, "mailer_sfmc"
    end
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
-- Smart Scan
-- =========================
local function smart_html_scan(html)
  local chunk = tonumber(LSCAN.smart_chunk) or (50 * 1024)
  if not html or #html <= chunk then return html end

  local parts = {}
  parts[#parts + 1] = html:sub(1, chunk)
  parts[#parts + 1] = html:sub(-chunk)

  if #html > (chunk * 4) then
    local mid = math.floor(#html / 2)
    local s = math.max(1, mid - math.floor(chunk / 2))
    parts[#parts + 1] = html:sub(s, s + chunk)
  end

  return table.concat(parts, "\n")
end

-- =========================
-- Base64 Candidates
-- =========================
local function extract_b64_candidates(text, max_candidates_override)
  local candidates = {}
  local seen = {}

  if not text or #text < (LB64.min_len or 200) then return candidates end

  local max_in = tonumber(LB64.max_scan_bytes) or (tonumber(LSCAN.max_bytes) * 2)
  if #text > max_in then text = text:sub(1, max_in) end

  local max_cand = max_candidates_override or (LB64.max_candidates or 6)
  local pat = "[A-Za-z0-9%+/_%%-]{" .. tostring(LB64.min_len or 200) .. ",}={0,2}"

  local start_time = os.clock()
  local iter_count = 0

  for m in text:gmatch(pat) do
    iter_count = iter_count + 1
    if (iter_count % 100 == 0) and (os.clock() - start_time > 0.1) then break end
    if #candidates >= max_cand then break end

    local nb = normalize_b64(m)
    if is_base64ish(nb) then
      local h = rspamd_util.str_hash(nb)
      if not seen[h] then
        seen[h] = true
        candidates[#candidates + 1] = nb
      end
    end
  end

  return candidates
end

-- =========================
-- Deobfuscation (kein goto)
-- =========================
local function advanced_deobfuscate(script)
  if not script or #script < 50 then return script, 0, 0 end

  local clean = script
  local var_map = {}
  local var_cnt = 0
  local virtuals = {}

  local function maybe_emit_virtual(val)
    if not val then return end
    if #virtuals >= (LOBFUS.virtual_max_payloads or 3) then return end
    if #val >= (LOBFUS.virtual_trigger_len or 120) then
      virtuals[#virtuals + 1] = val
    end
  end

  local function remember_var(name, val)
    if not name or not val then return end
    if #name > 64 then return end
    if var_map[name] then return end
    if var_cnt >= (LSCRIPT.max_vars or 20) then return end

    val = val:gsub("%s+", "")
    if not is_frag_base64ish(val) then return end

    var_map[name] = val
    var_cnt = var_cnt + 1
  end

  for _kw, name, val in script:gmatch("(const|let|var)%s+([%w_]+)%s*=%s*['\"]([^'\"]+)['\"]") do
    remember_var(name, val)
  end

  for name, val in script:gmatch("([%w_]+)%s*%+=%s*['\"]([^'\"]+)['\"]") do
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
      maybe_emit_virtual(var_map[name])
    end
  end

  local function resolve_token(tok)
    tok = trim(tok or "")
    if tok == "" then return nil end

    local q = tok:match("^['\"]([^'\"]+)['\"]$")
    if q then
      q = q:gsub("%s+", "")
      if is_frag_base64ish(q) then return q end
      return nil
    end

    if tok:match("^[%w_]+$") then return var_map[tok] end
    return nil
  end

  local function try_resolve_concat(expr)
    local out = {}
    local parts = 0
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
    local inside = expr:match("^%[(.*)%]%.join%s*%(%s*['\"][^'\"]*['\"]%s*%)$")
    if not inside then return nil end

    local out = {}
    local parts = 0
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

  for _ = 1, (LOBFUS.resolve_passes or 8) do
    local changed = false

    for target, expr in script:gmatch("([%w_]+)%s*=%s*([^;\n]+)") do
      repeat
        target = trim(target)
        expr = trim(expr)

        if target == "" or #target > 64 or expr == "" then break end
        if (not var_map[target]) and (var_cnt >= (LSCRIPT.max_vars or 20)) then break end

        local resolved = nil
        if expr:find("%+", 1, false) then resolved = try_resolve_concat(expr) end
        if (not resolved) and expr:find("%.join", 1, true) then resolved = try_resolve_join(expr) end

        if resolved and resolved ~= var_map[target] then
          if not var_map[target] then var_cnt = var_cnt + 1 end
          var_map[target] = resolved
          maybe_emit_virtual(resolved)
          changed = true
        end
      until true
    end

    if not changed then break end
  end

  if #virtuals > 0 then
    for i, v in ipairs(virtuals) do
      clean = clean .. "\n/*__RSPAMD_VIRTUAL_PAYLOAD_B64_" .. tostring(i) .. "__:" .. v .. "*/"
    end
  end

  clean = clean:gsub('["\']%s*%+%s*["\']', "")
  return clean, #virtuals, 0
end

-- =========================
-- Detection Helpers
-- =========================
local function detect_string_obfuscation(lc)
  local hit = false
  local reasons = {}

  if lc:find("%[%s*['\"]%w+['\"]%s*,%s*['\"]%w+['\"]%s*%]%s*%.%s*join", 1, false) then
    hit = true
    reasons[#reasons + 1] = "array_join_concat"
  end

  if lc:find("window%s*%[%s*['\"]atob['\"]%s*%]", 1, false) or lc:find("this%s*%[%s*['\"]atob['\"]%s*%]", 1, false) then
    hit = true
    reasons[#reasons + 1] = "bracket_atob"
  end

  local fromcharcode_count = 0
  for codes in lc:gmatch("fromcharcode%s*%(%s*([%d%s,]+)%s*%)") do
    fromcharcode_count = fromcharcode_count + 1
    local suspicious_chars = 0
    for num_str in codes:gmatch("%d+") do
      local code = tonumber(num_str)
      if code == 97 or code == 98 or code == 102 or code == 111 or code == 116 then
        suspicious_chars = suspicious_chars + 1
      end
    end
    if suspicious_chars >= 3 then
      hit = true
      reasons[#reasons + 1] = "fromcharcode_api"
      break
    end
  end

  if fromcharcode_count > 3 then
    hit = true
    reasons[#reasons + 1] = "fromcharcode_heavy"
  end

  return hit, reasons
end

local function detect_delayed_execution(html)
  local lc = html:lower()
  local score = 0
  local reasons = {}

  local has_timeout = lc:find("settimeout", 1, true) or lc:find("setinterval", 1, true)
  if not has_timeout then return 0, reasons end

  local timeout_positions = {}
  local pos = 1
  while true do
    local start_pos = lc:find("settimeout", pos, true)
    if not start_pos then break end
    timeout_positions[#timeout_positions + 1] = start_pos
    pos = start_pos + 10
    if #timeout_positions >= 5 then break end
  end

  for _, timeout_pos in ipairs(timeout_positions) do
    local ctx = tonumber(LOBFUS.max_delayed_exec_context) or 500
    local context_start = math.max(1, timeout_pos - ctx)
    local context_end = math.min(#lc, timeout_pos + ctx)
    local snippet = lc:sub(context_start, context_end)

    local has_b64 = snippet:find("[a-z0-9+/]{100,}", 1, false) ~= nil
    local has_blob = snippet:find("blob", 1, true)
    local has_url = snippet:find("createobjecturl", 1, true) or snippet:find("url%.createobjecturl", 1, true)
    local has_atob = snippet:find("atob", 1, true)

    if has_b64 then
      if has_blob or has_url then
        score = score + 2.0
        reasons[#reasons + 1] = "timeout_b64_smuggling"
      elseif has_atob then
        score = score + 1.5
        reasons[#reasons + 1] = "timeout_b64_decode"
      else
        score = score + 0.5
        reasons[#reasons + 1] = "timeout_b64"
      end
    end
  end

  if lc:find("<form[^>]+name%s*=%s*['\"]%w+['\"]", 1, false) then
    if lc:find("<input[^>]+name%s*=%s*['\"]payload['\"]", 1, false) or lc:find("<input[^>]+name%s*=%s*['\"]data['\"]", 1, false) then
      score = score + 1.5
      reasons[#reasons + 1] = "dom_clobbering"
    end
  end

  return score, reasons
end

local function detect_css_exfiltration(html)
  local lc = html:lower()
  local score = 0
  local reasons = {}
  local max_style = tonumber(LOBFUS.css_max_style_size) or 10000

  if lc:find("@import%s+url%s*%(%s*['\"]https?://", 1, false) then
    score = score + 1.0
    reasons[#reasons + 1] = "css_import_external"
  end

  if lc:find("background[^:]*:%s*url%s*%([^%)]*attr%s*%(", 1, false) then
    score = score + 2.5
    reasons[#reasons + 1] = "css_attr_exfil"
  end

  for style_content in lc:gmatch("<style[^>]*>(.-)</style>") do
    if #style_content > max_style then
      if style_content:find("[a-z0-9+/]{200,}", 1, false) then
        score = score + 1.5
        reasons[#reasons + 1] = "css_large_b64"
        break
      end
    end
  end

  return score, reasons
end

local function detect_polymorphic_obfuscation(script, task)
  local score = 0
  local reasons = {}

  local hex_vars = {}
  for varname in script:gmatch("_0x%x+") do hex_vars[varname] = true end
  local hex_var_count = 0
  for _ in pairs(hex_vars) do hex_var_count = hex_var_count + 1 end

  if hex_var_count >= 5 then
    score = score + 2.0
    reasons[#reasons + 1] = "hex_var_names"
  elseif hex_var_count >= 2 then
    score = score + 0.5
    reasons[#reasons + 1] = "hex_vars"
  end

  local entropy = calculate_entropy(script)
  if entropy > 5.0 then
    score = score + 1.5
    reasons[#reasons + 1] = "very_high_entropy"
  elseif entropy > 4.5 then
    score = score + 1.0
    reasons[#reasons + 1] = "high_entropy"
  end

  local array_storage_count = 0
  for _ in script:gmatch("const%s+_%w+%s*=%s*%[%s*['\"]") do array_storage_count = array_storage_count + 1 end
  for _ in script:gmatch("var%s+_%w+%s*=%s*%[%s*['\"]") do array_storage_count = array_storage_count + 1 end

  if array_storage_count >= 3 then
    score = score + 1.5
    reasons[#reasons + 1] = "array_string_storage"
  elseif array_storage_count >= 1 then
    score = score + 0.5
    reasons[#reasons + 1] = "array_storage"
  end

  if script:find("function%s*%(%s*_0x%x+%s*,%s*_0x%x+", 1, false) then
    score = score + 1.0
    reasons[#reasons + 1] = "func_obfuscation"
  end

  return score, reasons
end

local function byte_clamp(n)
  n = tonumber(n) or 0
  if n < 0 then return 0 end
  if n > 255 then return 255 end
  return n
end

local function detect_uint8array_payload(script)
  local lc = script:lower()
  local score = 0
  local critical = nil
  local reasons = {}

  local array_pattern = "uint8array%s*%(%s*%[%s*([%d%s,]+)"
  for array_content in lc:gmatch(array_pattern) do
    local byte_values = {}
    local byte_count = 0
    local maxb = tonumber(LOBFUS.max_uint8array_bytes) or 2048

    for num_str in array_content:gmatch("%d+") do
      byte_count = byte_count + 1
      if byte_count <= maxb then byte_values[#byte_values + 1] = tonumber(num_str) or 0 end
      if byte_count > maxb then break end
    end

    if byte_count > 1024 then
      local header = ""
      local ok_header = pcall(function()
        local header_bytes = {}
        for i = 1, math.min(16, #byte_values) do
          header_bytes[#header_bytes + 1] = string.char(byte_clamp(byte_values[i]))
        end
        header = table.concat(header_bytes)
      end)

      if ok_header and #header >= 4 then
        if header:sub(1,4) == "\000asm" then
          score = W.wasm_uint8array
          critical = "WASM"
          reasons[#reasons + 1] = "wasm_uint8array"
        elseif header:sub(1,2) == "MZ" then
          score = W.pe_uint8array
          critical = "PE"
          reasons[#reasons + 1] = "pe_uint8array"
        elseif header:sub(1,4) == "PK\003\004" then
          score = W.dec_zip
          critical = "ZIP"
          reasons[#reasons + 1] = "zip_uint8array"
        elseif header:sub(1,5) == "%PDF-" then
          score = W.dec_pdf
          reasons[#reasons + 1] = "pdf_uint8array"
        else
          score = W.large_uint8array
          reasons[#reasons + 1] = "large_uint8array"
        end
      else
        score = W.large_uint8array
        reasons[#reasons + 1] = "large_uint8array"
      end
      break
    end
  end

  return score, critical, reasons
end

local function detect_split_payload(html)
  if not html or #html < 200 then return false end
  local minf = tonumber(LOBFUS.min_frag_len) or 16
  local cnt = 0
  local maxv = tonumber(LSCRIPT.max_vars) or 20
  local vars = {}

  local function scan_decl(keyword)
    for varname, value in html:gmatch("[\n;%s]" .. keyword .. "%s+(%w+)%s*=%s*['\"]([A-Za-z0-9%+/_%%-=%s]{"..minf..",})['\"]") do
      value = (value or ""):gsub("%s+", "")
      if is_frag_base64ish(value) and not vars[varname] then
        vars[varname] = true
        cnt = cnt + 1
        if cnt >= maxv then return end
      end
    end
  end

  scan_decl("var")
  scan_decl("let")
  scan_decl("const")

  if cnt < 2 then return false end
  if html:find("%+=%s*['\"]", 1, false) then return true end
  if html:find("%.join%s*%(", 1, false) then return true end
  if html:find("%w+%s*=%s*%w+%s*%+%s*%w+", 1, false) then return true end
  return false
end

local function detect_external_scripts(html)
  local all = {}
  local unsafe = {}
  if not html then return all, unsafe end

  for script_url in html:gmatch('<script[^>]*src=["\'](.-)["\'][^>]*>') do
    if #all >= (LSCRIPT.max_external or 5) then break end
    all[#all + 1] = script_url
    if not is_safe_script_domain(script_url) then
      unsafe[#unsafe + 1] = script_url
    end
  end

  if html:find("createElement%(%s*['\"]script['\"]%)", 1, false) then
    if #all < (LSCRIPT.max_external or 5) then
      all[#all + 1] = "dynamic_script_creation"
      unsafe[#unsafe + 1] = "dynamic_script_creation"
    end
  end

  return all, unsafe
end

local function has_obfuscated_api_call(lc)
  if lc:find("%[%s*['\"]%w+['\"]%s*%]", 1, false) then return true end
  if lc:find("['\"]%w+['\"]%s*%+%s*['\"]%w+['\"]", 1, false) then return true end
  if lc:find("(\\x%x%x)+", 1, false) then return true end
  if lc:find("(\\u%x%x%x%x)+", 1, false) then return true end
  if lc:find("fromcharcode%s*%(", 1, false) then return true end
  if lc:find("charcodeat%s*%(", 1, false) then return true end
  if lc:find("eval%s*%([^%)]*%+[^%)]*%)", 1, false) then return true end
  if lc:find("atob%.call", 1, true) or lc:find("atob%.apply", 1, true) then return true end
  if lc:find("%.constructor%s*%(", 1, false) then return true end
  return false
end

local function detect_advanced_api_calls(lc, add)
  if lc:find("%[%s*['\"]atob['\"]%s*%]", 1, false) then add(W.array_index_api, "array_index_atob", false) end
  if lc:find("%[%s*['\"]blob['\"]%s*%]", 1, false) then add(W.array_index_api, "array_index_blob", false) end
  if lc:find("%[%s*['\"]fetch['\"]%s*%]", 1, false) then add(W.array_index_api, "array_index_fetch", false) end

  if lc:find("new%s+function%s*%(", 1, false) then add(W.function_constructor, "function_constructor", false) end
  if lc:find("eval%s*%(", 1, false) then add(W.eval_api, "eval_call", false) end
  if lc:find("settimeout%s*%(", 1, false) then add(W.settimeout_api, "settimeout_call", false) end
  if lc:find("setinterval%s*%(", 1, false) then add(W.settimeout_api, "setinterval_call", false) end

  if lc:find("new%s+worker%s*%(", 1, false) then add(W.webworker_api, "webworker", false) end
  if lc:find("serviceworker", 1, true) then add(W.serviceworker_api, "serviceworker", false) end

  if lc:find("webassembly", 1, true) then add(W.webassembly_api, "webassembly", false) end
  if lc:find("wasm", 1, true) then add(W.webassembly_api, "wasm_reference", false) end

  for on_event in lc:gmatch("on%w+%s*=%s*['\"]([^'\"]+)['\"]") do
    if on_event:find("atob", 1, true) or on_event:find("eval", 1, true) then
      add(W.event_handler, "event_handler_api", false)
      break
    end
  end
end

-- =========================
-- PE Validation
-- =========================
local function le_u32(s, off)
  if not s or #s < off + 3 then return nil end
  local b1, b2, b3, b4 = s:byte(off, off+3)
  if not b1 then return nil end
  return b1 + (b2 * 256) + (b3 * 65536) + (b4 * 16777216)
end

local function le_u16(s, off)
  if not s or #s < off + 1 then return nil end
  local b1, b2 = s:byte(off, off+1)
  if not b1 then return nil end
  return b1 + (b2 * 256)
end

local function is_valid_pe(bin)
  if not bin or #bin < 256 then return false end
  if bin:sub(1,2) ~= "MZ" then return false end

  local e_lfanew = le_u32(bin, 0x3C + 1)
  if not e_lfanew then return false end
  if e_lfanew < 0x40 or e_lfanew > (#bin - 256) then return false end

  local pe_off = e_lfanew + 1
  if bin:sub(pe_off, pe_off+3) ~= "PE\000\000" then return false end

  local machine = le_u16(bin, pe_off + 4)
  if not machine then return false end

  local ok_machine = (machine == 0x014c) or (machine == 0x8664) or (machine == 0x01c0) or (machine == 0xaa64)
  if not ok_machine then return false end
  return true
end

-- =========================
-- Payload Sniffing
-- =========================
local function sniff_decoded(bin)
  if not bin or #bin < 16 then return nil end

  if is_valid_pe(bin) then return "PE" end
  if bin:sub(1,4) == "MSCF" then return "CAB" end
  if bin:sub(1,6) == "7z\xBC\xAF\x27\x1C" then return "7ZIP" end
  if bin:sub(1,6) == "Rar!\x1A\x07" then return "RAR" end

  if bin:sub(1,4) == "PK\003\004" or bin:sub(1,4) == "PK\005\006" then
    local head = bin:sub(1, 200000)
    if head:find("AppxManifest%.xml", 1, true) or head:find("AppxBlockMap%.xml", 1, true) or head:find("AppxSignature%.p7x", 1, true) or head:find("AppxMetadata/", 1, true) then
      if head:find("AppxManifest%.xml", 1, true) then return "APPX" end
      return "MSIX"
    end
    return "ZIP"
  end

  if bin:sub(1,5) == "%PDF-" then return "PDF" end
  if bin:sub(1,8) == "\208\207\017\224\161\177\026\225" then return "OLE" end
  if bin:sub(1,8) == "vhdxfile" then return "VHDX" end

  if #bin >= 0x8001 + 5 and bin:sub(0x8001 + 1, 0x8001 + 5) == "CD001" then
    return "ISO"
  elseif #bin >= 2048 and bin:sub(1, 2048):find("CD001", 1, true) then
    return "ISO"
  end

  if bin:sub(1,4) == "\076\000\000\000" then
    local h = bin:sub(1,64)
    if h:find("\001\020\002\000\000\000\000\000\192\000\000\000\000\000\000\070", 1, true) then
      return "LNK"
    end
  end

  if bin:sub(1,4) == "\000asm" then return "WASM" end
  if bin:sub(1,8) == "\000asm\001\000\000\000" then return "WASM" end

  local head = bin:sub(1,4096)
  local l = head:lower()

  if l:find("<?xml", 1, true) or l:find("<appinstaller", 1, true) then return "XML" end
  if l:find("<html", 1, true) or l:find("<script", 1, true) then return "HTML" end

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
  if l:find("var%s+[%w_]+", 1, false) or l:find("let%s+[%w_]+", 1, false) or l:find("const%s+[%w_]+", 1, false) then
    js_ind = js_ind + 1
  end
  if l:find("=>", 1, true) then js_ind = js_ind + 1 end
  if l:find("eval%s*%(", 1, false) then js_ind = js_ind + 1 end
  if l:find("atob%s*%(", 1, false) then js_ind = js_ind + 1 end
  if l:find("document%.createelement", 1, true) then js_ind = js_ind + 1 end
  if l:find("addeventlistener", 1, true) then js_ind = js_ind + 1 end
  if js_ind >= 2 then return "JS" end

  return "BINARY"
end

local function part_is_htmlish(p)
  if not p then return false end

  local ok_html, is_html = pcall(function() return p:is_html() end)
  if ok_html and is_html then return true end

  local fname = ""
  if p.get_filename then
    local ok_fn, v = pcall(function() return p:get_filename() end)
    if ok_fn and v then fname = v end
  end
  if fname and #fname > 0 and fname:lower():match("%.html?$") then return true end

  local ctype = ""
  if p.get_type then
    local ok_ct, v = pcall(function() return p:get_type() end)
    if ok_ct and v then ctype = tostring(v) end
  end
  if ctype and #ctype > 0 then
    local cl = ctype:lower()
    if cl:find("text/html", 1, true) then return true end
  end

  local ok_text, is_text = pcall(function() return p:is_text() end)
  if ok_text and is_text then
    local ct2 = (ctype or ""):lower()
    if ct2:find("html", 1, true) then return true end
  end

  local ok_c, c = pcall(function() return p:get_content() end)
  if ok_c and c then
    local content = normalize_text(c)
    local lcc = content:lower()
    if lcc:find("<html", 1, true) or lcc:find("<script", 1, true) then return true end
  end

  return false
end

-- =========================
-- Main Detection v2.9-r1
-- =========================
local function detect_html_smuggling_payload(task)
  if not ENABLED then return end

  local t0 = nil
  if DEBUG then t0 = os.clock() end

  local parts = task:get_parts()
  if not parts then return end

  local score = 0.0
  local reasons = {}
  local critical_kind = nil
  local external_scripts = {}

  local NL, NL_reason = is_newsletter(task)
  local heur_mul = compute_heur_mul(task, NL, NL_reason)

  local deep_scan = true
  if NL and NL_reason == "header" and (not DEEP_SCAN_NEWSLETTER_HEADER) then
    deep_scan = false
  end

  local function add(points, why, is_decode_or_hard)
    local p = tonumber(points) or 0
    if not is_decode_or_hard then p = p * heur_mul end
    score = score + p
    reasons[why] = true
  end

  local function has(why) return reasons[why] == true end

  local b64_big_thr = tonumber(LB64.big_threshold) or 5000
  local b64_huge_thr = tonumber(LB64.huge_threshold) or 20000
  local decode_mul = tonumber(LDEC.joined_len_mul) or 2
  local max_joined_decode = (tonumber(LDEC.max_bytes) or (160 * 1024)) * decode_mul
  local min_decode_total = tonumber(LB64.min_decode_total) or 1500

  for _, p in ipairs(parts) do
    if part_is_htmlish(p) then
      local c = p:get_content()
      if c then
        local html = normalize_text(c)
        html = smart_html_scan(html)

        if #html > (LSCAN.max_bytes or (200 * 1024)) then
          html = html:sub(1, LSCAN.max_bytes)
        end

        local lc = html:lower()

        if (not NL) and lc:find("view in browser", 1, true) then
          NL = true
          NL_reason = "view_in_browser_link"
          heur_mul = compute_heur_mul(task, NL, NL_reason)
        end

        local flags = {
          has_atob = (lc:find("atob", 1, true) ~= nil),
          has_blob = (lc:find("blob(", 1, true) ~= nil),
          has_createobjecturl = (lc:find("createobjecturl", 1, true) ~= nil),
          has_fetch = (lc:find("fetch(", 1, true) ~= nil),
          has_filereader = (lc:find("filereader", 1, true) ~= nil),
          has_uint8 = (lc:find("uint8array", 1, true) ~= nil),
          has_iframe = (lc:find("<iframe", 1, true) ~= nil),
          has_data_uri = (lc:find("data:", 1, true) ~= nil),
          has_msapp = (lc:find("ms-appinstaller", 1, true) ~= nil),
          has_appinstaller = (lc:find(".appinstaller", 1, true) ~= nil),
          has_script_close = (lc:find("</script>", 1, true) ~= nil),
          has_script_tags = (lc:find("<script", 1, true) ~= nil),
          has_js_keywords = (lc:find("function", 1, true) ~= nil) or (lc:find("var ", 1, true) ~= nil) or (lc:find("let ", 1, true) ~= nil) or (lc:find("const ", 1, true) ~= nil),
          has_b64_pattern = (lc:find("[a-z0-9+/]{100,}", 1, false) ~= nil),
        }

        if flags.has_atob and lc:find("atob%s*%(", 1, false) then
          add(W.atob, "atob", false)
        end

        local obfus_hit, obfus_reasons = detect_string_obfuscation(lc)
        if obfus_hit then
          add(W.atob_obfuscated, "atob_obfuscated", false)
          for _, r in ipairs(obfus_reasons) do reasons[r] = true end
        end

        if flags.has_blob then add(W.blob, "blob", false) end
        if flags.has_createobjecturl then add(W.createobjecturl, "createObjectURL", false) end
        if flags.has_fetch then add(W.fetch, "fetch", false) end
        if flags.has_filereader then add(W.filereader, "filereader", false) end
        if flags.has_uint8 then add(W.uint8array, "uint8array", false) end

        detect_advanced_api_calls(lc, add)

        if flags.has_iframe and lc:find("src%s*=", 1, false) then add(W.iframe_src, "iframe_src", false) end
        if lc:find("src%s*=", 1, false) and flags.has_data_uri then add(W.data_uri, "data_uri", false) end

        if flags.has_msapp then
          if lc:find("ms%-appinstaller:%s*", 1, false) then
            add(W.ms_appinstaller_uri, "ms_appinstaller_uri", false)
          else
            add(1.0, "ms_appinstaller_word", false)
          end
        end
        if flags.has_appinstaller then add(W.appinstaller_file, "appinstaller_file", false) end

        if has_obfuscated_api_call(lc) then
          add(W.obfus, "obfus_api", false)
        end

        if flags.has_js_keywords and detect_split_payload(html) then
          add(W.split_payload, "split_payload", false)
        end

        if lc:find("settimeout", 1, true) or lc:find("setinterval", 1, true) then
          local delay_score, delay_reasons = detect_delayed_execution(html)
          if delay_score > 0 then
            add(W.delayed_execution, "delayed_execution", false)
            for _, r in ipairs(delay_reasons) do reasons[r] = true end
          end
        end

        local has_smuggling_api = (
          has("createObjectURL") or has("blob") or has("fetch") or
          has("obfus_api") or has("array_index_atob") or has("eval_call") or
          has("atob") or has("atob_obfuscated")
        )

        local smuggling_context_for_css = has_smuggling_api or has("delayed_execution") or has("split_payload") or has("ms_appinstaller_uri") or has("appinstaller_file")
        if smuggling_context_for_css then
          local css_score, css_reasons = detect_css_exfiltration(html)
          if css_score > 0 then
            add((css_score / 2.0), "css_exfiltration", false)
            for _, r in ipairs(css_reasons) do reasons[r] = true end
          end
        end

        if has_smuggling_api then
          local all_ext, unsafe_ext = detect_external_scripts(html)
          if all_ext and #all_ext > 0 then
            for _,u in ipairs(all_ext) do
              if #external_scripts < (LSCRIPT.max_external or 5) then
                external_scripts[#external_scripts + 1] = u
              end
            end
            if unsafe_ext and #unsafe_ext > 0 then
              add(W.external_script * #unsafe_ext, "external_scripts", false)
            end
          end
        end

        local smugglingish = has_smuggling_api or has("ms_appinstaller_uri") or has("appinstaller_file")
        local allow_b64_scan = flags.has_b64_pattern or flags.has_atob or has("obfus_api") or has("split_payload")

        if deep_scan and smugglingish and allow_b64_scan and (flags.has_script_tags or flags.has_script_close) then
          local scripts_checked = 0

          for script in html:gmatch("<script[^>]*>(.-)</script>") do
            scripts_checked = scripts_checked + 1

            repeat
              local sl = script:lower()
              local maybe_b64 = allow_b64_scan and ((sl:find("atob", 1, true) ~= nil) or (sl:find("base64", 1, true) ~= nil))
              local maybe_concat = (sl:find("%+=", 1, false) ~= nil) or (sl:find(".join", 1, true) ~= nil)
              local maybe_obfus = (sl:find("\\x", 1, true) ~= nil) or (sl:find("\\u", 1, true) ~= nil) or (sl:find("fromcharcode", 1, true) ~= nil)
              local maybe_uint8 = (sl:find("uint8array", 1, true) ~= nil)

              if not (maybe_b64 or maybe_concat or maybe_obfus or maybe_uint8) then break end

              if maybe_uint8 then
                local ua_score, ua_critical, ua_reasons = detect_uint8array_payload(script)
                if ua_score > 0 then
                  add(ua_score, "uint8array_payload", true)
                  if ua_critical then critical_kind = ua_critical end
                  for _, r in ipairs(ua_reasons) do reasons[r] = true end
                end
              end

              do
                local poly_score, poly_reasons = detect_polymorphic_obfuscation(script, task)
                if poly_score > 0 then
                  add(W.polymorphic_obfuscation, "polymorphic_obfuscation", false)
                  for _, r in ipairs(poly_reasons) do reasons[r] = true end
                end
              end

              if not allow_b64_scan then break end

              local normalized_script = script:gsub('"%s*%+%s*"', "")
              normalized_script = normalized_script:gsub("'%s*%+%s*'", "")
              normalized_script = select(1, advanced_deobfuscate(normalized_script))

              if not normalized_script or #normalized_script < (LB64.min_len or 200) then break end
              if (normalized_script:find("=", 1, true) == nil) and (#normalized_script < ((LB64.min_len or 200) * 2)) then break end

              local max_cand_script = (LB64.max_candidates or 6)
              if NL then max_cand_script = math.min(max_cand_script, 4) end

              local cands = extract_b64_candidates(normalized_script, max_cand_script)
              if #cands == 0 then break end

              local total_b64_len = 0
              local joined = {}
              local joined_len = 0

              for _, cand in ipairs(cands) do
                local cleaned = cand:gsub("%s+", "")
                total_b64_len = total_b64_len + #cleaned

                if #joined < (LB64.join_max_parts or 5) and joined_len < (LB64.join_max_len or 180000) then
                  local nb = normalize_b64(cand)
                  joined_len = joined_len + #nb
                  joined[#joined + 1] = nb
                end
              end

              if total_b64_len >= b64_big_thr then add(W.b64_total_len_big, "b64_total_len_big", false) end
              if total_b64_len >= b64_huge_thr then add(W.b64_total_len_huge, "b64_total_len_huge", false) end
              if #joined > 1 then add(W.b64_joined_parts, "b64_joined_parts", false) end

              if total_b64_len < min_decode_total then break end
              if joined_len <= 0 or joined_len > max_joined_decode then break end

              local joined_b64 = table.concat(joined, "")
              local decoded = safe_decode_base64(task, joined_b64, LDEC.max_bytes)
              if decoded and #decoded > 0 then
                local kind = sniff_decoded(decoded)

                if kind == "PE" then
                  add(W.dec_pe, "dec_pe", true); critical_kind = "PE"
                elseif kind == "WASM" then
                  add(W.dec_wasm, "dec_wasm", true); if not critical_kind then critical_kind = "WASM" end
                elseif kind == "XML" then
                  if has("ms_appinstaller_uri") or has("appinstaller_file") then
                    add(W.dec_xml_appinstaller, "dec_xml_appinstaller", true); critical_kind = "XML_APPINSTALLER"
                  else
                    add(W.dec_xml, "dec_xml", true)
                  end
                elseif kind == "VHDX" then
                  add(W.dec_vhdx, "dec_vhdx", true); critical_kind = "VHDX"
                elseif kind == "ISO" then
                  add(W.dec_iso, "dec_iso", true); critical_kind = "ISO"
                elseif kind == "LNK" then
                  add(W.dec_lnk, "dec_lnk", true); critical_kind = "LNK"
                elseif kind == "OLE" then
                  add(W.dec_ole, "dec_ole", true); critical_kind = "OLE"
                elseif kind == "MSIX" then
                  add(W.dec_msix, "dec_msix", true); critical_kind = "MSIX"
                elseif kind == "APPX" then
                  add(W.dec_appx, "dec_appx", true); critical_kind = "APPX"
                elseif kind == "CAB" then
                  add(W.dec_cab, "dec_cab", true); critical_kind = "CAB"
                elseif kind == "7ZIP" then
                  add(W.dec_7zip, "dec_7zip", true); critical_kind = "7ZIP"
                elseif kind == "RAR" then
                  add(W.dec_rar, "dec_rar", true); critical_kind = "RAR"
                elseif kind == "ZIP" then
                  add(W.dec_zip, "dec_zip", true); if not critical_kind then critical_kind = "ZIP" end
                elseif kind == "PDF" then
                  add(W.dec_pdf, "dec_pdf", true)
                elseif kind == "VBS" or kind == "PS1" or kind == "BAT" then
                  add(W.dec_script, "dec_script", true); critical_kind = "SCRIPT"
                elseif kind == "JS" then
                  add(W.dec_js, "dec_js", true)
                elseif kind == "HTML" then
                  add(W.dec_html, "dec_html", true)
                else
                  add(W.dec_bin, "dec_bin", true)
                end
              end
            until true

            if scripts_checked >= (LSCRIPT.max_check or 3) then break end
          end
        end
      end
    end
  end

  -- =========================
  -- Combos und Scoring Stages (Fix v2.9-r1)
  -- =========================
  local combo_soft = 0.0
  local combo_hard = 0.0

  local has_smuggling_api2 = (
    reasons["createObjectURL"] or reasons["blob"] or reasons["fetch"] or
    reasons["obfus_api"] or reasons["array_index_atob"] or reasons["eval_call"] or
    reasons["atob"] or reasons["atob_obfuscated"]
  )
  local has_api_pair = ((reasons["createObjectURL"] and reasons["blob"]) or (reasons["createObjectURL"] and reasons["fetch"]) or (reasons["blob"] and reasons["fetch"]))
  if has_api_pair then combo_soft = combo_soft + W.combo_smuggling_api end

  if (reasons["atob"] or reasons["obfus_api"] or reasons["array_index_atob"] or reasons["atob_obfuscated"]) and
     (reasons["b64_total_len_big"] or reasons["b64_long_html"]) then
    combo_soft = combo_soft + W.combo_atob_plus_b64
  end

  if reasons["ms_appinstaller_uri"] and (reasons["dec_xml_appinstaller"] or reasons["appinstaller_file"]) then
    combo_hard = combo_hard + W.combo_msapp_plus_xml
  end

  if reasons["dec_zip"] and (reasons["createObjectURL"] or reasons["atob"] or reasons["ms_appinstaller_uri"] or reasons["obfus_api"] or reasons["fetch"]) then
    combo_soft = combo_soft + W.combo_zip_plus_smuggling
  end

  if reasons["dec_pe"] then combo_hard = combo_hard + W.combo_pe end

  if (reasons["dec_lnk"] or reasons["dec_vhdx"] or reasons["dec_iso"] or reasons["dec_ole"] or reasons["dec_script"] or
      reasons["dec_msix"] or reasons["dec_appx"] or reasons["dec_cab"] or reasons["dec_7zip"] or reasons["dec_rar"]) and
     has_smuggling_api2 then
    combo_hard = combo_hard + W.combo_container_plus_smuggling
  end

  if reasons["split_payload"] and (reasons["dec_pe"] or reasons["dec_zip"] or reasons["dec_msix"] or reasons["dec_appx"]) then
    combo_hard = combo_hard + W.combo_split_payload
  end

  if reasons["external_scripts"] and has_smuggling_api2 then
    combo_soft = combo_soft + W.combo_external_script
  end

  if reasons["wasm_uint8array"] and has_smuggling_api2 then
    combo_hard = combo_hard + W.combo_wasm_plus_smuggling
  end

  if reasons["polymorphic_obfuscation"] and (reasons["dec_pe"] or reasons["dec_wasm"]) then
    combo_hard = combo_hard + 2.0
  end

  -- Stage 1: raw (ohne combos)
  local raw_score = score

  -- Stage 2: combos drauf
  if combo_soft > 0 then
    score = score + (combo_soft * heur_mul)
    reasons["combo_soft"] = true
  end
  if combo_hard > 0 then
    score = score + combo_hard
    reasons["combo_hard"] = true
  end
  local after_combos = score

  -- Stage 3: critical boost
  if critical_kind and CRITICAL_BOOST > 0 then
    score = score + CRITICAL_BOOST
    reasons["critical_boost"] = true
  end
  local after_boost = score

  -- Stage 4: min score floor
  if score > 0 and MIN_SCORE > 0 and score < MIN_SCORE then
    score = MIN_SCORE
    reasons["min_score"] = true
  end
  local after_floor = score

  -- Stage 5: auth mul optional
  local auth_mul = 1.0
  if AUTH_MUL_ENABLED then
    if task:get_symbol("R_DKIM_ALLOW") then auth_mul = auth_mul * 0.7 end
    if task:get_symbol("R_SPF_ALLOW") then auth_mul = auth_mul * 0.8 end
    if task:get_symbol("R_DKIM_REJECT") or task:get_symbol("R_SPF_FAIL") then auth_mul = auth_mul * 1.5 end
    score = score * auth_mul
  end
  local after_auth = score

  local final_score = score

  -- =========================
  -- Marker
  -- =========================
  if critical_kind == "PE" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_PE", 1.0)
  elseif critical_kind == "WASM" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_WASM", 1.0)
  elseif critical_kind == "XML_APPINSTALLER" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_APPINSTALLER", 1.0)
  elseif critical_kind == "VHDX" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_VHDX", 1.0)
  elseif critical_kind == "ISO" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_ISO", 1.0)
  elseif critical_kind == "LNK" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_LNK", 1.0)
  elseif critical_kind == "OLE" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_OLE", 1.0)
  elseif critical_kind == "ZIP" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_ZIP", 1.0)
  elseif critical_kind == "SCRIPT" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_SCRIPT", 1.0)
  elseif critical_kind == "MSIX" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_MSIX", 1.0)
  elseif critical_kind == "APPX" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_APPX", 1.0)
  elseif critical_kind == "CAB" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_CAB", 1.0)
  elseif critical_kind == "7ZIP" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_7ZIP", 1.0)
  elseif critical_kind == "RAR" then
    task:insert_result("HTML_SMUGGLING_CRITICAL_RAR", 1.0)
  end

  -- =========================
  -- Result + Logging
  -- =========================
  if final_score > 0 then
    local why = table_keys_sorted(reasons)
    local why_s = table.concat(why, ",")

    if TEST_MODE then
      task:insert_result("HTML_SMUGGLING_TEST", final_score, "Test:" .. why_s)
    else
      task:insert_result("HTML_SMUGGLING_PAYLOAD", final_score, why_s)
    end

    if (DEBUG or SCORE_DEBUG) then
      rspamd_logger.infox(task, string.format(
        "HTML_SMUGGLING_SCORE_DEBUG || v=%s || raw=%.2f || after_combos=%.2f || after_boost=%.2f || after_floor=%.2f || after_auth=%.2f || final=%.2f || auth_mul=%.2f || heur_mul=%.2f || newsletter=%s || nl_reason=%s || reasons=%s || combo_soft=%.2f || combo_hard=%.2f",
        VERSION,
        tonumber(raw_score) or 0,
        tonumber(after_combos) or 0,
        tonumber(after_boost) or 0,
        tonumber(after_floor) or 0,
        tonumber(after_auth) or 0,
        tonumber(final_score) or 0,
        tonumber(auth_mul) or 1.0,
        tonumber(heur_mul) or 1.0,
        safe_str(NL, "false"),
        safe_str(NL_reason, "none"),
        why_s,
        tonumber(combo_soft) or 0,
        tonumber(combo_hard) or 0
      ))
    end

    -- Extended Logging
    if (FORCE_EXTENDED_LOG and final_score >= FORCE_EXTENDED_LOG_MIN_SCORE) or (final_score >= LOG_SCORE_THRESHOLD) or DEBUG then
      log_detection_extended(task, final_score, critical_kind, NL, NL_reason, reasons, external_scripts)
    end

    -- Simple Line optional
    if (final_score >= LOG_SCORE_THRESHOLD or DEBUG) and LOG_SIMPLE_LINE then
      local from = task:get_from_addr()
      local from_s = from and from:to_string() or "unknown"
      local line = string.format(
        "HTML_SMUGGLING %s || score=%.2f || critical=%s || NL=%s(%s) || heur_mul=%.2f || deep_scan=%s || reasons=%s || external=%s || from=%s || subject=%s",
        VERSION,
        tonumber(final_score) or 0,
        safe_str(critical_kind, "none"),
        safe_str(NL, "false"),
        safe_str(NL_reason, "none"),
        tonumber(heur_mul) or 1.0,
        safe_str(deep_scan, "true"),
        why_s,
        safe_str(table.concat(external_scripts, ","), ""),
        safe_str(from_s, "unknown"),
        safe_str(task:get_subject() or "", "")
      )
      rspamd_logger.infox(task, line)
    end
  end

  if DEBUG and t0 then
    local elapsed = os.clock() - t0
    if elapsed > 0.01 then
      rspamd_logger.infox(task, string.format("SLOW_HTML_SCAN version=%s time_ms=%.3f", VERSION, elapsed * 1000))
    end
  end
end

-- =========================
-- Register symbols
-- =========================
if ENABLED then
  local smuggling_id = rspamd_config:register_symbol{
    name = "HTML_SMUGGLING_PAYLOAD",
    callback = detect_html_smuggling_payload,
    score = 0.0,
    group = "phishing",
    type = "callback",
    description = "Detect HTML smuggling and decoded payload indicators (" .. VERSION .. ")"
  }

  local function reg_marker(name, desc)
    rspamd_config:register_symbol{
      name = name,
      parent = smuggling_id,
      type = "virtual",
      score = 0.0,
      group = "phishing",
      description = desc
    }
  end

  reg_marker("HTML_SMUGGLING_TEST",                  "HTML smuggling test mode marker")
  reg_marker("HTML_SMUGGLING_CRITICAL_PE",           "HTML smuggling decoded PE payload")
  reg_marker("HTML_SMUGGLING_CRITICAL_WASM",         "HTML smuggling decoded WebAssembly module")
  reg_marker("HTML_SMUGGLING_CRITICAL_APPINSTALLER", "HTML smuggling decoded AppInstaller XML")
  reg_marker("HTML_SMUGGLING_CRITICAL_VHDX",         "HTML smuggling decoded VHDX container")
  reg_marker("HTML_SMUGGLING_CRITICAL_ISO",          "HTML smuggling decoded ISO container")
  reg_marker("HTML_SMUGGLING_CRITICAL_LNK",          "HTML smuggling decoded LNK payload")
  reg_marker("HTML_SMUGGLING_CRITICAL_OLE",          "HTML smuggling decoded OLE container")
  reg_marker("HTML_SMUGGLING_CRITICAL_ZIP",          "HTML smuggling decoded ZIP container")
  reg_marker("HTML_SMUGGLING_CRITICAL_SCRIPT",       "HTML smuggling decoded script payload")
  reg_marker("HTML_SMUGGLING_CRITICAL_MSIX",         "HTML smuggling decoded MSIX package")
  reg_marker("HTML_SMUGGLING_CRITICAL_APPX",         "HTML smuggling decoded APPX package")
  reg_marker("HTML_SMUGGLING_CRITICAL_CAB",          "HTML smuggling decoded CAB archive")
  reg_marker("HTML_SMUGGLING_CRITICAL_7ZIP",         "HTML smuggling decoded 7ZIP archive")
  reg_marker("HTML_SMUGGLING_CRITICAL_RAR",          "HTML smuggling decoded RAR archive")
end
