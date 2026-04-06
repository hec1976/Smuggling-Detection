# HTML Smuggling Detection v4.4.0

![Version](https://img.shields.io/badge/Version-4.4.0-green)
![Rspamd](https://img.shields.io/badge/Rspamd-Lua%20Local-blue)
![Security](https://img.shields.io/badge/Focus-Hardened%20Gate%20%26%20Entropy-red)

## Zweck

Dieses Modul erweitert Rspamd um eine praxisnahe Erkennung von HTML Smuggling, verschleierten JavaScript Payloads und ergänzenden Non HTML Vektoren. Die Version v4.4.0 baut auf den früheren 4.3.x Linien auf und führt die Architektur mit Modulmatrix, Reason Policy, Limits, Thresholds, Marker Symbolen und erweiterten Attachment Pfaden konsistent weiter.

Das Ziel ist nicht eine forensische Vollanalyse jeder Datei, sondern eine robuste und performante Erkennung typischer Smuggling, Staging und Delivery Muster im produktiven Mail Gateway Betrieb.

## Architekturüberblick

Die Erkennung ist in mehrere Schichten aufgeteilt:

1. **Frühe HTML und Part Erkennung**
   HTML Teile und smuggling relevante Attachments werden identifiziert.

2. **HTML Signalerkennung**
   Typische JavaScript, CSS, AppInstaller, ClickFix und andere frühe Indikatoren werden gesammelt.

3. **Script Deep Scan**
   Interessante Script Blöcke werden priorisiert, deobfuskiert und auf weitere Module untersucht.

4. **Decode Pfad**
   Base64 Kandidaten werden extrahiert, normalisiert, dekodiert und klassifiziert.

5. **Payload Klassifikation**
   Dekodierte Inhalte werden als PE, ZIP, ISO, Script, PDF, HTML, XML, WASM und weitere Typen eingeordnet.

6. **Scoring und Marker**
   Kategorien, Bonus Module, Caps und Marker Symbole werden konsistent berechnet und geschrieben.

## Abgedeckte Bereiche

Die Version v4.4.0 deckt insbesondere folgende Bereiche ab:

- HTML Smuggling mit JavaScript
- Base64 Decode Pfade
- Obfuskation und API Tarnung
- Uint8Array Payload Konstruktion
- externe Script Nachladungen
- CSS Exfiltration und CSS Code Execution Muster
- Geo Targeting und Evasion
- Persistence mit localStorage und sessionStorage
- ClickFix ähnliche Lures
- WASM Staging
- Blockchain oder Web3 Staging
- PDF Active Content
- SVG mit aktivem Inhalt
- CHM, HTA, OneNote, LNK und Script Attachments
- Zertifikats und PKCS basierte Smuggling Kontexte
- optionale Bild Indikatoren als Info Only
- Push Abuse als Info Signale
- vorbereitete, aber standardmässig deaktivierte Pfade für RC4 Detection und WASM Binary Analysis

## Nicht oder nur eingeschränkt abgedeckt

Die Version v4.4.0 ist stark für Mail Gateway Erkennung optimiert. Folgende Bereiche sind nicht als vollständige Tiefenanalyse umgesetzt:

- echte Steganographie Analyse in Bildern
- vollständige PDF Objekt Rekonstruktion
- tiefes Office Parsing mit Makro Extraktion
- vollständige Zertifikats oder PKCS Validierung
- Headless Nachverfolgung externer URLs
- Browser Laufzeitverhalten nach Mail Zustellung
- Sandbox Verhalten oder System Calls eines Payloads

Das ist bewusst so gehalten, damit das Modul produktiv auf Rspamd lauffähig und wartbar bleibt.

## Hauptmodule

### appinstaller
Erkennt `ms-appinstaller` Kontexte und `.appinstaller` Hinweise. Dazu gehören URI Hinweise, Dateiendungen und dekodierte XML AppInstaller Inhalte.

### js_smuggling
Erkennt die typischen JavaScript Bausteine wie `atob`, `Blob`, `fetch`, `createObjectURL`, Split Payloads, Timer Verzögerung, DOM Clobbering, Data URI Hinweise und Decode Kontexte.

### obfuscation
Erkennt Tarnungsmuster wie `fromCharCode`, `_0x...` Variablen, hohe Entropie, Hex Arrays, Function Konstruktoren, Eval Brücken und ähnliche Konstrukte.

### decoded_payload
Versucht dekodierte Base64 Inhalte zu klassifizieren, zum Beispiel PE, ZIP, ISO, CAB, RAR, 7ZIP, OLE, Script, HTML, XML, PDF oder WASM.

### uint8array
Erkennt grosse `Uint8Array` Konstruktionen und prüft Header Hinweise auf PE, WASM, ZIP oder PDF.

### external_scripts
Erkennt externe Scripts im HTML und bewertet diese nur im passenden Smuggling Kontext.

### css_exfil
Erkennt missbräuchliche CSS Konstrukte wie `@import`, `attr()` und grosse Base64 Blöcke in Style Bereichen.

### geo_targeting
Erkennt Geo APIs, Country Checks und Timezone basierte Selektionslogik.

### evasion
Erkennt Antisandbox und User Interaction Muster wie `navigator.webdriver`, Hardware Checks und erzwungene Maus oder Keyboard Interaktion.

### persistence
Erkennt `localStorage` und `sessionStorage` Nutzung im verdächtigen Kontext.

### domain_rotation
Erkennt Redirect oder Domain Rotation Logik.

### clickfix
Erkennt typische ClickFix, Fake CAPTCHA und Run Dialog Lures.

### wasm_staging
Erkennt WebAssembly als Stage oder Payload Brücke.

### blockchain_staging
Erkennt Web3 oder Ethers basierte Payload oder Remote Stage Muster.

### css_code_execution
Erkennt Konstrukte, bei denen CSS Inhalte später durch JavaScript ausgelesen und missbraucht werden.

### attachment_vectors
Erkennt Non HTML und Attachment Vektoren wie:

- PDF mit `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/RichMedia`
- SVG mit `<script>`, `onload`, `foreignObject`, `xlink:href`, `data:` Kontext
- CHM
- HTA
- OneNote
- LNK
- Script Dateien wie JS, VBS, PS1, BAT, CMD
- Office Macro Container wie DOCM, XLSM, PPTM
- deklarierte oder direkte WASM Attachments

### certificate_smuggling
Erkennt:

- inline PEM Blöcke
- PKCS Hinweise
- Zertifikats Dateitypen
- `data:` Kontexte mit Zertifikats oder PKCS Bezug
- grosse Base64 Blöcke im Zertifikats Kontext

### image_smuggling_info
Standardmässig deaktiviert und als Info Only gedacht. Erkennt nur einfache Indikatoren, keine echte Steganographie.

### push_abuse
Info Only Modul für Notification Permission, Push Flow und ServiceWorker Kombinationen.

### link_analysis
Vorbereitet, standardmässig deaktiviert, derzeit ohne aktive Headless URL Analyse.

### wasm_binary_analysis
Vorbereitet, standardmässig deaktiviert. Dient als Platzhalter für tiefere WASM Binary Auswertung.

### rc4_detection
Vorbereitet, standardmässig deaktiviert. Erkennt RC4 typische KSA, PRGA, XOR und Decrypt Muster.

## Standardmässige Modul Defaults

Die Modul Defaults in v4.4.0 sind:

- `appinstaller = enabled`
- `js_smuggling = enabled`
- `obfuscation = enabled`
- `decoded_payload = enabled`
- `uint8array = enabled`
- `external_scripts = enabled`
- `css_exfil = enabled`
- `geo_targeting = enabled`
- `evasion = enabled`
- `persistence = enabled`
- `domain_rotation = enabled`
- `clickfix = enabled`
- `wasm_staging = enabled`
- `blockchain_staging = enabled`
- `css_code_execution = enabled`
- `attachment_vectors = enabled`
- `certificate_smuggling = enabled`
- `image_smuggling_info = disabled, info_only = true`
- `push_abuse = enabled, info_only = true`
- `link_analysis = disabled, info_only = true`
- `wasm_binary_analysis = disabled`
- `rc4_detection = disabled`

## Config Optionen komplett

### Top Level Optionen

~~~lua
html_smuggling {
  enabled = true;
  debug = false;
  test_mode = false;

  log_score_threshold = 5.0;
  log_simple_line = true;
  score_debug = false;
  force_extended_log = true;
  force_extended_log_min_score = 5.0;
  slow_log_ms = 150.0;

  deep_scan_newsletter_header = true;

  min_score = 0.0;
  critical_boost = 0.0;
  max_final_score = 15.0;
  soft_only_cap = 4.5;

  redact_log_fields = true;
  require_script_context_for_external = true;
  require_strong_gate_for_decode = true;
  max_external_reported = 3;

  heur_mul_default = 1.0;
  heur_mul_newsletter_header = 0.3;
  heur_mul_newsletter_heuristic = 0.4;
  heur_mul_trusted_newsletter = 0.1;

  hard_fail_on_bad_config = false;
  enable_phase_debug = false;
  safe_task_access = true;
  safe_part_access = true;
  log_config_validation = true;
  strict_weight_validation = false;
  decode_debug = false;
}
~~~

### Bedeutung der wichtigsten Optionen

| Option | Standard | Bedeutung |
|---|---:|---|
| `enabled` | `true` | Modul aktiv oder inaktiv |
| `debug` | `false` | Zusätzliche Debug Logs und Debug Export |
| `test_mode` | `false` | Schreibt `HTML_SMUGGLING_TEST` statt produktivem Hauptsymbol |
| `log_score_threshold` | `5.0` | Ab welchem Score detailliert geloggt wird |
| `log_simple_line` | `true` | Kompakte Zusatzzeile im Log |
| `score_debug` | `false` | Sehr detaillierte Score Zerlegung |
| `force_extended_log` | `true` | Erzwingt Extended Log unabhängig vom Schwellenwert |
| `force_extended_log_min_score` | `5.0` | Mindestscore für Forced Extended Log |
| `slow_log_ms` | `150.0` | Meldet langsame Durchläufe separat |
| `deep_scan_newsletter_header` | `true` | Deep Scan auch bei Header Newsletter Klassifikation |
| `min_score` | `0.0` | Erzwingt Mindestscore, falls ein positiver Score berechnet wurde |
| `critical_boost` | `0.0` | Zusatzscore bei kritischem Payload |
| `max_final_score` | `15.0` | Endscore Cap |
| `soft_only_cap` | `4.5` | Cap für reine Soft Fälle ohne Hard Gründe |
| `redact_log_fields` | `true` | Maskiert sensible Felder im Log |
| `require_script_context_for_external` | `true` | Externe Scripts nur im passenden Kontext bewerten |
| `require_strong_gate_for_decode` | `true` | Decode Pfad nur bei starkem Kontext zulassen |
| `max_external_reported` | `3` | Anzahl externer Script URLs im Log |
| `heur_mul_default` | `1.0` | Normaler Soft Faktor |
| `heur_mul_newsletter_header` | `0.3` | Soft Reduktion bei Header Newsletter |
| `heur_mul_newsletter_heuristic` | `0.4` | Soft Reduktion bei heuristischer Newsletter Erkennung |
| `heur_mul_trusted_newsletter` | `0.1` | Soft Reduktion für vertrauenswürdige Newsletter Domains |
| `hard_fail_on_bad_config` | `false` | Fehlerhafte Config stoppt Modul hart |
| `enable_phase_debug` | `false` | Loggt Phasen Metriken |
| `safe_task_access` | `true` | Absicherung für Task Methoden |
| `safe_part_access` | `true` | Absicherung für Part Methoden |
| `log_config_validation` | `true` | Schreibt Config Validierungsfehler ins Log |
| `strict_weight_validation` | `false` | Strenge Prüfung der Gewichtswerte |
| `decode_debug` | `false` | Sehr detaillierte Decode Debug Logs |

## Limits

### Standardwerte

~~~lua
limits {
  scan {
    max_bytes = 204800;
    smart_chunk = 51200;
    long_html_b64_threshold = 1200;
    max_attachment_text = 307200;
  }
  b64 {
    min_len = 200;
    max_candidates = 6;
    max_scan_bytes = 512000;
    min_decode_total = 400;
    big_threshold = 5000;
    huge_threshold = 20000;
    join_max_parts = 5;
    join_max_len = 180000;
  }
  decode {
    max_bytes = 163840;
    joined_len_mul = 2;
  }
  script {
    max_check = 3;
    max_external = 5;
    max_vars = 20;
    smart_chunk = 20000;
    max_script_len = 80000;
    max_total_script_scan = 120000;
    max_script_time_ms = 80.0;
    deobfus_timeout_ms = 50.0;
    split_payload_min_vars = 6;
  }
  obfus {
    min_frag_len = 4;
    virtual_trigger_len = 120;
    virtual_max_payloads = 3;
    resolve_passes = 8;
    max_uint8array_bytes = 2048;
    max_entropy_check_bytes = 4096;
    css_max_style_size = 10000;
    max_delayed_exec_context = 500;
  }
}
~~~

### Interpretation

- `scan.max_bytes` begrenzt die HTML Rohmenge pro Teil.
- `scan.smart_chunk` steuert, wie viel Text aus Anfang, Ende und Mitte für schnelle Suchen verwendet wird.
- `b64.min_len` verhindert Kleinfragmente als Kandidaten.
- `b64.min_decode_total` verlangt eine Mindestgesamtmenge an Base64 Material vor dem Decode.
- `script.max_check` begrenzt die Zahl der priorisierten Script Blöcke.
- `script.max_total_script_scan` schützt gegen grosse Scriptmengen.
- `script.deobfus_timeout_ms` begrenzt die Deobfuskation.
- `obfus.max_uint8array_bytes` schützt vor übergrossen Byte Arrays.

## Thresholds

~~~lua
thresholds {
  entropy_high = 4.5;
  entropy_very_high = 5.0;
  hex_var_low = 2;
  hex_var_high = 5;
  array_storage_low = 1;
  array_storage_high = 3;
  uint8array_large_min = 1024;
  deobfus_reduce_len_1 = 20000;
  deobfus_reduce_len_2 = 40000;
  b64_extract_loop_budget_ms = 25.0;
  script_min_len = 20;
  normalized_script_min_len = 40;
  delayed_exec_context = 500;
}
~~~

## Weights

~~~lua
weights {
  JS_SMUGGLING = 1.2;
  OBFUSCATION = 2.5;
  SUSPICIOUS_API = 0.8;
  EVASION_LOGIC = 1.5;
  CONTAINER = 6.0;
  SCRIPT_HARD = 7.0;
  CRITICAL = 12.0;
  COMBO_JS_OBFUS = 1.5;
  COMBO_HARD_OBFUS = 2.0;
  COMBO_JS_API = 0.8;
  COMBO_JS_EVASION = 0.7;
  EXTERNAL_SCRIPT = 1.0;
  CSS_EXFIL = 2.0;
  GEO_TARGETING = 0.8;
  ROTATION_BONUS = 1.0;
  CLICKFIX_LURE = 1.2;
  WASM_STAGING = 1.4;
  BLOCKCHAIN_STAGING = 1.2;
  CSS_CODE_EXEC = 1.5;
  ATTACHMENT_VECTOR = 1.4;
  CERT_SMUGGLING = 1.1;
  IMAGE_SMUGGLING = 0.7;
}
~~~

### Scoring Prinzip

Das Modul zählt nicht einfach jede einzelne Reason hoch, sondern arbeitet mit Kategorien:

- `JS_SMUGGLING`
- `OBFUSCATION`
- `SUSPICIOUS_API`
- `EVASION`
- `CONTAINER`
- `SCRIPT_HARD`
- `CRITICAL`

Zusätzlich gibt es:

- Soft Bonus Scores
- Hard Bonus Scores
- Combo Scores
- Newsletter Multiplikatoren
- Soft Only Cap
- Final Score Cap

Das verhindert Score Explosionen durch viele ähnliche Einzelindikatoren.

## Beispiel Modulmatrix

~~~lua
modules {
  appinstaller {
    enabled = true;
    info_only = false;
  }
  js_smuggling {
    enabled = true;
    info_only = false;
  }
  obfuscation {
    enabled = true;
    info_only = false;
  }
  decoded_payload {
    enabled = true;
    info_only = false;
  }
  uint8array {
    enabled = true;
    info_only = false;
  }
  external_scripts {
    enabled = true;
    info_only = false;
  }
  css_exfil {
    enabled = true;
    info_only = false;
  }
  geo_targeting {
    enabled = true;
    info_only = false;
  }
  evasion {
    enabled = true;
    info_only = false;
  }
  persistence {
    enabled = true;
    info_only = false;
  }
  domain_rotation {
    enabled = true;
    info_only = false;
  }
  clickfix {
    enabled = true;
    info_only = false;
  }
  wasm_staging {
    enabled = true;
    info_only = false;
  }
  blockchain_staging {
    enabled = true;
    info_only = false;
  }
  css_code_execution {
    enabled = true;
    info_only = false;
  }
  attachment_vectors {
    enabled = true;
    info_only = false;
  }
  certificate_smuggling {
    enabled = true;
    info_only = false;
  }
  image_smuggling_info {
    enabled = false;
    info_only = true;
  }
  push_abuse {
    enabled = true;
    info_only = true;
  }
  link_analysis {
    enabled = false;
    info_only = true;
  }
  wasm_binary_analysis {
    enabled = false;
    info_only = false;
  }
  rc4_detection {
    enabled = false;
    info_only = false;
  }
}
~~~

### Hinweise

- `enabled = false` schaltet ein Modul vollständig aus.
- `info_only = true` lässt das Modul nur Hinweise liefern, aber keine Scoring Wirkung.
- `weight_override` kann pro Modul gesetzt werden.

Beispiel:

~~~lua
modules {
  clickfix {
    enabled = true;
    info_only = false;
    weight_override = 0.8;
  }
}
~~~

## Newsletter Detection

~~~lua
newsletter_detection {
  classify_headers = [
    "X-HEC-MailClass",
    "X-HEC-Category",
    "X-FortiMail-Profile"
  ];

  classify_keywords = [
    "newsletter",
    "marketing",
    "bulk"
  ];

  list_id_headers = ["List-Id"];
  list_unsubscribe_headers = ["List-Unsubscribe"];

  precedence_headers = ["Precedence", "X-Precedence"];
  precedence_keywords = ["bulk"];

  x_mailer_headers = ["X-Mailer"];

  x_mailer_patterns = [
    { pattern = "mailchimp"; reason = "mailer_mailchimp"; },
    { pattern = "sendgrid"; reason = "mailer_sendgrid"; },
    { pattern = "salesforce"; reason = "mailer_sfmc"; },
    { pattern = "marketing cloud"; reason = "mailer_sfmc"; }
  ];

  html_keywords = ["view in browser"];
}
~~~

### Wirkung

Bei erkannten Newslettern werden Soft Signale reduziert. Das betrifft vor allem Marketing, Bulk und vertrauenswürdige Newsletter Domains. Hard Gründe wie echte Container, Script oder Critical Payloads bleiben davon unberührt.

## Domain Maps

Optional können Maps genutzt werden:

~~~lua
html_smuggling {
  safe_script_domains_map = "/etc/rspamd/local.d/maps.d/safe_script_domains.map";
  trusted_newsletter_domains_map = "/etc/rspamd/local.d/maps.d/trusted_newsletter_domains.map";
  unsafe_script_domains_map = "/etc/rspamd/local.d/maps.d/unsafe_script_domains.map";
}
~~~

### Zweck

- `safe_script_domains_map` erlaubt ungefährliche Script Hosts.
- `trusted_newsletter_domains_map` reduziert Soft Scores für bekannte Newsletter Absender.
- `unsafe_script_domains_map` überschreibt Safe Hosts bewusst nach unten.

## Beispiel für eine vollständige lokale Konfiguration

Datei zum Beispiel unter:

`/etc/rspamd/local.d/html_smuggling.conf`

~~~lua
html_smuggling {
  enabled = true;
  debug = false;
  test_mode = false;

  log_score_threshold = 5.0;
  force_extended_log = true;
  force_extended_log_min_score = 5.0;
  log_simple_line = true;
  score_debug = false;
  enable_phase_debug = false;
  decode_debug = false;

  max_final_score = 15.0;
  soft_only_cap = 4.5;
  critical_boost = 0.0;
  min_score = 0.0;

  require_script_context_for_external = true;
  require_strong_gate_for_decode = true;
  max_external_reported = 3;

  heur_mul_default = 1.0;
  heur_mul_newsletter_header = 0.3;
  heur_mul_newsletter_heuristic = 0.4;
  heur_mul_trusted_newsletter = 0.1;

  deep_scan_newsletter_header = true;
  redact_log_fields = true;
  safe_task_access = true;
  safe_part_access = true;
  log_config_validation = true;
  strict_weight_validation = false;
  hard_fail_on_bad_config = false;

  safe_script_domains_map = "/etc/rspamd/local.d/maps.d/safe_script_domains.map";
  trusted_newsletter_domains_map = "/etc/rspamd/local.d/maps.d/trusted_newsletter_domains.map";
  unsafe_script_domains_map = "/etc/rspamd/local.d/maps.d/unsafe_script_domains.map";

  limits {
    scan {
      max_bytes = 204800;
      smart_chunk = 51200;
      long_html_b64_threshold = 1200;
      max_attachment_text = 307200;
    }
    b64 {
      min_len = 200;
      max_candidates = 6;
      max_scan_bytes = 512000;
      min_decode_total = 400;
      big_threshold = 5000;
      huge_threshold = 20000;
      join_max_parts = 5;
      join_max_len = 180000;
    }
    decode {
      max_bytes = 163840;
      joined_len_mul = 2;
    }
    script {
      max_check = 3;
      max_external = 5;
      max_vars = 20;
      smart_chunk = 20000;
      max_script_len = 80000;
      max_total_script_scan = 120000;
      max_script_time_ms = 80.0;
      deobfus_timeout_ms = 50.0;
      split_payload_min_vars = 6;
    }
    obfus {
      min_frag_len = 4;
      virtual_trigger_len = 120;
      virtual_max_payloads = 3;
      resolve_passes = 8;
      max_uint8array_bytes = 2048;
      max_entropy_check_bytes = 4096;
      css_max_style_size = 10000;
      max_delayed_exec_context = 500;
    }
  }

  thresholds {
    entropy_high = 4.5;
    entropy_very_high = 5.0;
    hex_var_low = 2;
    hex_var_high = 5;
    array_storage_low = 1;
    array_storage_high = 3;
    uint8array_large_min = 1024;
    deobfus_reduce_len_1 = 20000;
    deobfus_reduce_len_2 = 40000;
    b64_extract_loop_budget_ms = 25.0;
    script_min_len = 20;
    normalized_script_min_len = 40;
    delayed_exec_context = 500;
  }

  weights {
    JS_SMUGGLING = 1.2;
    OBFUSCATION = 2.5;
    SUSPICIOUS_API = 0.8;
    EVASION_LOGIC = 1.5;
    CONTAINER = 6.0;
    SCRIPT_HARD = 7.0;
    CRITICAL = 12.0;
    COMBO_JS_OBFUS = 1.5;
    COMBO_HARD_OBFUS = 2.0;
    COMBO_JS_API = 0.8;
    COMBO_JS_EVASION = 0.7;
    EXTERNAL_SCRIPT = 1.0;
    CSS_EXFIL = 2.0;
    GEO_TARGETING = 0.8;
    ROTATION_BONUS = 1.0;
    CLICKFIX_LURE = 1.2;
    WASM_STAGING = 1.4;
    BLOCKCHAIN_STAGING = 1.2;
    CSS_CODE_EXEC = 1.5;
    ATTACHMENT_VECTOR = 1.4;
    CERT_SMUGGLING = 1.1;
    IMAGE_SMUGGLING = 0.7;
  }

  modules {
    attachment_vectors {
      enabled = true;
      info_only = false;
    }
    certificate_smuggling {
      enabled = true;
      info_only = false;
    }
    image_smuggling_info {
      enabled = false;
      info_only = true;
    }
    push_abuse {
      enabled = true;
      info_only = true;
    }
    rc4_detection {
      enabled = false;
      info_only = false;
    }
    wasm_binary_analysis {
      enabled = false;
      info_only = false;
    }
  }

  newsletter_detection {
    classify_headers = ["X-HEC-MailClass", "X-HEC-Category", "X-FortiMail-Profile"];
    classify_keywords = ["newsletter", "marketing", "bulk"];
    list_id_headers = ["List-Id"];
    list_unsubscribe_headers = ["List-Unsubscribe"];
    precedence_headers = ["Precedence", "X-Precedence"];
    precedence_keywords = ["bulk"];
    x_mailer_headers = ["X-Mailer"];
    html_keywords = ["view in browser"];
  }
}
~~~

## Installation

Die Lua Datei liegt produktiv typischerweise hier:

`/etc/rspamd/lua.local.d/html_smuggling.lua`

Die Konfiguration liegt typischerweise hier:

`/etc/rspamd/local.d/html_smuggling.conf`

Danach sollte die Konfiguration geprüft werden:

~~~bash
rspamadm configtest
~~~

Anschliessend Rspamd neu laden oder neu starten:

~~~bash
systemctl restart rspamd
~~~

oder je nach Umgebung:

~~~bash
systemctl reload rspamd
~~~

## Empfohlene Inbetriebnahme

Für einen sauberen Rollout empfiehlt sich dieses Vorgehen:

1. Erst mit `test_mode = true` starten.
2. Logging für einige Tage beobachten.
3. False Positives gegen reale Newsletter, Marketing Mails und interne Systeme prüfen.
4. Danach in den produktiven Modus wechseln.
5. Gewichte und Caps nur gezielt anpassen, nicht pauschal.

## Ergebnis und Symbolik

Das Hauptsymbol ist:

`HTML_SMUGGLING_PAYLOAD`

Zusätzlich werden Marker und Klassen Symbole gesetzt, zum Beispiel:

- `HTML_SMUGGLING_MARKER_PDF_ACTIVE`
- `HTML_SMUGGLING_MARKER_SVG_ACTIVE`
- `HTML_SMUGGLING_MARKER_CERT_SMUGGLING`
- `HTML_SMUGGLING_MARKER_CLICKFIX`
- `HTML_SMUGGLING_MARKER_WASM_STAGING`
- `HTML_SMUGGLING_MARKER_BLOCKCHAIN_STAGING`
- `HTML_SMUGGLING_MARKER_CSS_CODE_EXEC`
- `HTML_SMUGGLING_MARKER_PUSH_ABUSE`
- `HTML_SMUGGLING_CLASS_JS`
- `HTML_SMUGGLING_CLASS_OBFUS`
- `HTML_SMUGGLING_CLASS_CONTAINER`
- `HTML_SMUGGLING_CLASS_SCRIPT_HARD`
- `HTML_SMUGGLING_CLASS_CRITICAL`

Zusätzlich existieren payloadspezifische Marker, zum Beispiel:

- `HTML_SMUGGLING_CRITICAL_PE`
- `HTML_SMUGGLING_CRITICAL_WASM`
- `HTML_SMUGGLING_CRITICAL_APPINSTALLER`
- `HTML_SMUGGLING_CRITICAL_ZIP`
- `HTML_SMUGGLING_CRITICAL_ISO`
- `HTML_SMUGGLING_CRITICAL_LNK`
- `HTML_SMUGGLING_CRITICAL_MSIX`
- `HTML_SMUGGLING_CRITICAL_APPX`
- `HTML_SMUGGLING_CRITICAL_CAB`
- `HTML_SMUGGLING_CRITICAL_7ZIP`
- `HTML_SMUGGLING_CRITICAL_RAR`
- `HTML_SMUGGLING_CRITICAL_CHM`
- `HTML_SMUGGLING_CRITICAL_ONENOTE`

Diese Marker helfen für Logging, Policies, Reports und spätere Auswertungen.

## Wichtige Betriebs Hinweise

### 1. Performance
Das Modul ist auf produktive Laufzeit optimiert. Trotzdem sollte es auf echten Mail Daten beobachtet werden, speziell bei:

- grossen HTML Newslettern
- stark obfuskierten HTML Dateien
- vielen Attachments pro Nachricht
- grossen Base64 Blöcken
- vielen Script Tags oder langen Script Bodies

### 2. False Positives
Besonders im Blick behalten:

- Marketing und Newsletter Systeme
- SVG Dateien aus legitimen Design Tools
- PDF Dokumente mit aktiven Formular oder Medien Elementen
- technische Zertifikats Mails aus PKI oder Monitoring Umgebungen
- legitime externe Script Einbindungen in HTML Reports

### 3. Zertifikats Erkennung
Die Zertifikats Erkennung ist absichtlich konservativ. Eine legitime Zertifikats Mail kann Hinweise setzen. Entscheidend ist der Kontext mit Base64, Script, Blob, Fetch oder Data URI Missbrauch.

### 4. Bild Missbrauch
Das Modul `image_smuggling_info` ist nur ein Hinweis Modul. Es liefert keine verlässliche Steganographie Erkennung.

### 5. Externe Scripts
Externe Scripts werden absichtlich nicht blind hochgewichtet. Ohne passenden Script oder Smuggling Kontext sollen sie nicht unnötig auslösen.

### 6. Decode Pfad
Der Decode Pfad ist bewusst gehärtet:

- Mindestlänge pro Kandidat
- Mindestgesamtmenge an Base64 Material
- Quality Score vor dem Decode
- optional starker Kontext erforderlich
- Limits für Kandidaten, Bytes und Laufzeit

## Was v4.4.0 im praktischen Betrieb gut kann

- frühe Erkennung moderner HTML Smuggling Muster
- gute Abdeckung für häufige Delivery Chains
- brauchbare Einordnung dekodierter Payloads
- gute Sichtbarkeit auf gefährliche Attachments
- Trennung von Soft und Hard Signalen
- brauchbare Newsletter Entschärfung
- gut lesbare Marker und Summary Tags

## Grenzen der Erkennung

Die Version v4.4.0 erreicht in der Praxis eine breite Abdeckung. Trotzdem ersetzt sie keine Sandbox und keine tiefgehende Dateianalyse. Für hoch entwickelte Kampagnen mit echter Bild Steganographie, komplexem PDF Objekt Missbrauch oder mehrstufigem Remote Staging bleiben zusätzliche Kontrollen sinnvoll.

## Empfehlung für produktiven Betrieb

Für ein sauberes Setup im Gateway Betrieb ist diese Kombination sinnvoll:

- Rspamd mit HTML Smuggling Detection als frühe Erkennung
- URL Reputation und URL Rewrite Kontrollen
- Attachment Policy für CHM, HTA, LNK, OneNote und Script Dateien
- AV oder Sandbox für tiefe Dateianalyse
- separates Monitoring für False Positives und neue Taktiken
- kontrollierte Freischaltung von Modulen wie `image_smuggling_info`, `rc4_detection` oder `wasm_binary_analysis`

## Kurzfazit

Die v4.4.0 ist eine saubere, produktionsnahe Weiterentwicklung der früheren 4.3.x Linien. Sie bleibt wartbar, erweitert aber die Erkennung spürbar in Richtung moderner Non HTML und Attachment Vektoren. Für einen produktiven Mail Gateway Betrieb ist das ein guter, ausgewogener Stand zwischen Abdeckung, Performance und Pflegeaufwand.
