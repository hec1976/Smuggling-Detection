# HTML Smuggling Detection v4.7.0

![Version](https://img.shields.io/badge/Version-4.7.0-green)
![Rspamd](https://img.shields.io/badge/Rspamd-Lua%20Local-blue)
![Security](https://img.shields.io/badge/Focus-HTML%20Smuggling%20%26%20Payload%20Detection-red)

Rspamd-Lua-Modul zur Erkennung von **HTML Smuggling**, verschleierten JavaScript-Payloads, Base64-/Byte-Array-Staging sowie ergänzenden **Non-HTML- und Attachment-Vektoren**.

Version **4.7.0** baut auf v4.6.0 auf und erweitert den Scanner gezielt bei **DOM-Sinks, Dynamic Imports, Worker-/ServiceWorker-Staging, moderner Evasion und begrenzter ZIP-Tiefenanalyse**. Die v4.6-Pfade für globale Budgets, Script-Prescan, strukturiertes ZIP-Parsing sowie XOR-/RC4-Rekonstruktion bleiben erhalten.

---

## Zweck

Das Modul ergänzt Rspamd um eine mehrstufige Erkennung moderner Smuggling-, Staging- und Delivery-Techniken.

Der Schwerpunkt liegt auf:

- HTML Smuggling mit JavaScript
- Base64- und Split-Payload-Rekonstruktion
- JavaScript-Obfuskation
- `Uint8Array`-Payloads
- Magic-Prefix- und Dateityp-Erkennung
- rekursivem Decode von Zwischenstufen
- gefährlichen oder aktiven Attachments
- Attachment-Magic-/Dateiendungs-Mismatches
- Image-Tail-Carving
- PDF-/SVG-Active-Content
- AppInstaller-, WASM-, ClickFix- und Web3-Staging
- Zertifikats-/PKCS-Smuggling-Kontexten
- Evasion-, Persistence- und Geo-Targeting-Signalen

Das Ziel ist **keine vollständige forensische Dateianalyse**, sondern eine robuste, nachvollziehbare und laufzeitbegrenzte Erkennung direkt im produktiven Mail-Gateway.

---

## Was ist neu in v4.7.0?

Die v4.7.0-Erweiterungen konzentrieren sich auf reale Lücken mit gutem Nutzen-/FP-Verhältnis:

- **DOM Dynamic Sinks** im Payload-Kontext:
  - `.innerHTML =`
  - `.outerHTML =`
  - `insertAdjacentHTML(...)`
  - `document.write(...)`
- **Dynamic `import()`**:
  - `data:`-JavaScript
  - `blob:`-JavaScript
  - Blob/ObjectURL-basierte Import-Ketten
- **Worker-Blob-Staging**:
  - `new Worker(...)`
  - Blob + `URL.createObjectURL()`
  - begrenzte Rekonstruktion statischer Worker-Scriptstrings
- **ServiceWorker-Kontext**:
  - `navigator.serviceWorker.register(...)`
  - Root-Scope bzw. auffällig breite Scope-Nutzung
- **WebSocket-Portscan-Heuristik**:
  - mehrere Ports
  - Schleifen über Portlisten
- **JSFuck-Erkennung** als Obfuskationssignal
- **erweiterte Unicode-Escape-Rekonstruktion**:
  - `\uXXXX`
  - `\u{...}`
  - bestehende `\xNN`-Dekodierung bleibt erhalten
- **Template-Literal-Obfuskation** mit Exec-/Payload-Kontext
- **ZIP-Kommentaranalyse** auf Script- und Base64-Payloads
- **Entropie-Info** für unkomprimiert gespeicherte ZIP-Mitglieder
- **begrenzte stored ZIP-in-ZIP-Rekursion** unter bestehenden Decode-/Container-Budgets
- **SharedArrayBuffer + Atomics + Timing** als Evasion-/Sidechannel-Indikator

Neue wichtige Reasons:

- `dom_dynamic_sink`
- `dynamic_import_data`
- `dynamic_import_blob`
- `worker_blob_stage`
- `worker_inline_script`
- `serviceworker_register`
- `serviceworker_broad_scope`
- `websocket_portscan`
- `jsfuck_obfuscation`
- `unicode_escape_payload`
- `template_literal_obfuscation`
- `zip_comment_payload`
- `zip_high_entropy_member`
- `sharedarraybuffer_timing`

### Basis aus v4.6.0


Die wichtigsten Erweiterungen gegenüber v4.5.0:

- **globales Nachrichtenbudget** für:
  - maximale Laufzeit
  - insgesamt verarbeitete Bytes
  - Decode-Operationen
  - Container-Operationen
  - Script-Prescan-Anzahl und Prescan-Bytes
- **billiger Vorscan aller Inline-Scripts**, bevor nur die interessantesten Scripts tief analysiert werden
- Prescan kann Scripts mit Magic-Prefixen oder typischen PE-/ZIP-Bytefolgen erzwingen
- **echtes ZIP-Parsing** von Central Directory und Local File Headers
- ZIP-Mitglieder werden auf sicherheitsrelevante Eigenschaften geprüft:
  - ausführbare Dateien
  - Script-Dateien
  - verschachtelte Archive
  - Double Extensions
  - Path Traversal
  - Encryption-Flag
  - hohe Kompressionsraten
  - sehr viele Einträge
- unkomprimierte **stored ZIP-Mitglieder** können begrenzt extrahiert und erneut klassifiziert werden
- **konstante XOR-Rekonstruktion** für statische Byte-/String-Payloads
- **konstante RC4-Rekonstruktion** für statische Schlüssel und Payload-Kandidaten
- neue Reasons wie:
  - `script_prescan_payload`
  - `zip_executable_member`
  - `zip_script_member`
  - `zip_nested_archive`
  - `zip_encrypted`
  - `zip_double_extension`
  - `zip_path_traversal`
  - `zip_stored_payload`
  - `xor_constant_payload`
  - `rc4_constant_payload`
- neue Info-Reasons für Ressourcenlimits und unvollständige ZIP-Auswertung

Die v4.6- und v4.5-Erweiterungen bleiben vollständig Bestandteil von v4.7.0, insbesondere:

- Base64 Magic-Prefix Fast-Path
- priorisierte Base64-Kandidaten
- rekursives Base64-Decoding bis Tiefe 3
- hexadezimale und dezimale `Uint8Array`-Payloads
- zusätzliche Magic-Erkennung für GZIP, BZIP2, XZ, ZSTD und TAR
- Attachment-Magic-/Dateiendungs-Abgleich
- Image-Tail-Carving für PNG, JPEG, GIF und WebP
- priorisierte Tiefenanalyse von standardmässig bis zu 5 Scripts

---

## Architektur

Die Erkennung arbeitet in mehreren Stufen.

### 1. Message- und MIME-Part-Erkennung

Rspamd-Parts werden geprüft und nach HTML-, Script-, Zertifikats-, Container- und Attachment-Kontexten klassifiziert.

### 2. Frühe HTML-Signalerkennung

Der HTML-Pfad sucht unter anderem nach:

- `atob`
- `Blob`
- `createObjectURL`
- `fetch`
- `FileReader`
- `Uint8Array`
- `data:` URIs
- dynamischen Script-Elementen
- Redirect-Logik
- WebAssembly
- ServiceWorker
- WebCrypto
- CSS-Missbrauch
- ClickFix-/Fake-CAPTCHA-Mustern

### 3. Script-Sammlung und Priorisierung

Script-Blöcke werden nur einmal aus dem HTML extrahiert.

Danach werden interessante Inline-Scripts bewertet und priorisiert. Scripts mit bekannten Base64-Magic-Prefixen erhalten eine besonders hohe Priorität.

Standardmässig werden bis zu **5 Scripts** tief geprüft. Besonders interessante Magic-Payloads können zusätzlich berücksichtigt werden.

### 4. Globaler Script-Prescan

Seit v4.6.0 werden Inline-Scripts vor der begrenzten Tiefenanalyse mit einem günstigen Prescan bewertet. Der Prescan sucht unter anderem nach:

- `atob`
- `createObjectURL`
- `Uint8Array`
- `fromCharCode` / `TextDecoder`
- `Blob`
- Crypto-/Decrypt-Kontexten
- bekannten Base64-Magic-Prefixen
- PE-/ZIP-Bytefolgen

Ein starker Prescan-Treffer kann ein Script auch dann in die Tiefenanalyse bringen, wenn das reguläre `max_check` bereits erreicht ist.

### 5. Deobfuskation

Verdächtige Script-Inhalte werden kontrolliert rekonstruiert.

Unterstützt werden unter anderem:

- String-Konkatenation
- Array-Join-Konstrukte
- Hex-Arrays
- `fromCharCode`
- Escape-Sequenzen
- Percent-Encoding
- Blob-Konkatenationen
- `_0x...`-artige Variablen
- Function-/Eval-Konstrukte

### 6. Decode-Pfad

Base64-Kandidaten werden:

1. extrahiert,
2. normalisiert,
3. bewertet,
4. priorisiert,
5. dekodiert,
6. per Magic/Inhalt klassifiziert.

Druckbare Zwischenstufen können erneut auf Base64 untersucht werden. Die Standardtiefe liegt bei **3 Decode-Ebenen**.

### 7. Payload-Klassifikation

Dekodierte Inhalte können unter anderem erkannt werden als:

- PE
- WASM
- ZIP
- RAR
- 7ZIP
- CAB
- OLE
- VHDX
- LNK
- CHM
- PDF
- HTML
- XML
- Script
- GZIP
- BZIP2
- XZ
- ZSTD
- TAR

### 8. Attachment-Inhaltsprüfung

Bei Attachments wird nicht nur der Dateiname betrachtet.

Das Modul vergleicht:

- Dateiendung
- MIME-Type
- tatsächlichen Dateiinhalt / Magic

Ein Widerspruch kann als `attachment_magic_mismatch` gewertet werden.

### 9. Image-Tail-Carving

Für PNG, JPEG, GIF und WebP kann Inhalt **hinter dem regulären Bildende** untersucht werden.

Wird dort ein weiterer erkennbarer Payload gefunden, entsteht der Grund:

`image_appended_payload`

### 10. ZIP-Analyse

ZIP-Container werden in v4.6.0 nicht nur am Magic erkannt. Der Scanner liest begrenzt das Central Directory bzw. Local Headers und klassifiziert Einträge nach Dateiname, Flags und Grössen.

Erkannt werden unter anderem:

- Executables im ZIP
- Scripts und LNK/HTA/CHM im ZIP
- verschachtelte Archive
- Double Extensions wie `rechnung.pdf.exe`
- Path-Traversal-Namen wie `../payload.exe`
- verschlüsselte ZIP-Einträge
- auffällig hohe Kompressionsverhältnisse
- zu viele Einträge
- gespeicherte, unkomprimierte Payloads, die direkt erneut klassifiziert werden können

### 11. Scoring und Marker

Alle Reasons werden einer festen Policy-Klasse zugeordnet. Daraus werden Score, Caps, Marker und Ergebnistext berechnet.

---

## Erkennungsbereiche

### HTML und JavaScript

- HTML Smuggling
- Base64-Staging
- Split Payloads
- `Array.join()`-Rekonstruktion
- `Blob`
- `createObjectURL`
- `fetch`
- `FileReader`
- `Uint8Array`
- Data-URIs
- dynamische Scripts
- Timer-/Delayed-Execution
- DOM-Clobbering
- Computed Redirects

### Obfuskation

- hohe Entropie
- Hex-Variablen
- Hex-Arrays
- String-Arrays
- `fromCharCode`
- `eval`
- `Function`
- Escape-Payloads
- Percent-Encoding
- Blob-Konkatenation
- Array-Join-Obfuskation
- konstante XOR-Rekonstruktion
- konstante RC4-Rekonstruktion

### Evasion

- `navigator.webdriver`
- Hardware-/Environment-Checks
- erzwungene User-Interaktion
- Maus-/Keyboard-Gates
- Geo-/Country-Selektion
- Timezone-Selektion

### Persistence

- `localStorage`
- `sessionStorage`

### Staging

- WASM
- WebWorker
- ServiceWorker
- WebCrypto
- Blockchain/Web3
- Ethers
- Domain-Rotation
- externe Script-Nachladung

### Social Engineering / ClickFix

- Fake CAPTCHA
- Clipboard-Execution
- Run-Dialog-Lures
- PowerShell-Lures

### PDF Active Content

Erkannt werden unter anderem:

- `/JavaScript`
- `/OpenAction`
- `/Launch`
- `/EmbeddedFile`
- `/RichMedia`

### SVG Active Content

Erkannt werden unter anderem:

- `<script>`
- Event-Handler wie `onload`
- `foreignObject`
- `xlink:href`
- `data:`-URIs

### Weitere Attachment-Vektoren

- CHM
- HTA
- OneNote
- LNK
- HTML
- JS / JSE
- VBS / VBE
- PowerShell
- WSF
- BAT / CMD
- Office-Makrocontainer:
  - DOCM
  - XLSM
  - PPTM

### ZIP-Risiken

- Executables im Archiv
- Script-Dateien im Archiv
- verschachtelte Archive
- Double Extensions
- Path Traversal
- Encryption-Flag
- hohe Kompressionsraten
- sehr viele Einträge
- Stored-Payload-Extraktion und erneute Klassifikation

### Zertifikats- und PKCS-Kontexte

- Inline-PEM
- PKCS-Hinweise
- Zertifikatsdateien
- Certificate-/PKCS-Data-URIs
- grosse Base64-Blöcke im passenden Kontext

---

## Module

| Modul | Default | Info only | Zweck |
|---|---:|---:|---|
| `appinstaller` | an | nein | AppInstaller-URI/XML-Erkennung |
| `js_smuggling` | an | nein | zentrale HTML-/JS-Smuggling-Erkennung |
| `obfuscation` | an | nein | JavaScript-Obfuskation |
| `decoded_payload` | an | nein | Decode und Payload-Klassifikation |
| `uint8array` | an | nein | Byte-Array-Payloads |
| `external_scripts` | an | nein | externe und dynamische Scripts |
| `css_exfil` | an | nein | CSS-Exfiltrationsmuster |
| `geo_targeting` | an | nein | Geo-/Timezone-Targeting |
| `evasion` | an | nein | Anti-Sandbox-/Interaktionslogik |
| `persistence` | an | nein | Browser-Storage-Persistence |
| `domain_rotation` | an | nein | Redirect-/Domain-Rotation |
| `clickfix` | an | nein | ClickFix-/Fake-CAPTCHA-Lures |
| `wasm_staging` | an | nein | WASM-Staging |
| `blockchain_staging` | an | nein | Web3-/Blockchain-Staging |
| `css_code_execution` | an | nein | CSS als Code-/Payload-Brücke |
| `attachment_vectors` | an | nein | Non-HTML- und Attachment-Vektoren |
| `certificate_smuggling` | an | nein | PEM-/PKCS-Kontexte |
| `image_smuggling_info` | aus | ja | einfache Bild-Missbrauchsindikatoren |
| `push_abuse` | an | ja | Push-/Notification-Missbrauch |
| `link_analysis` | aus | ja | vorbereiteter Link-Analyse-Pfad |
| `wasm_binary_analysis` | aus | nein | vorbereitete tiefere WASM-Analyse |
| `rc4_detection` | aus | nein | optionale RC4-Mustererkennung |

`info_only = true` bedeutet, dass ein Modul Hinweise liefern kann, ohne den regulären Score zu erhöhen.

---

## Scoring-Modell

Das Modul erhöht den Score **nicht blind pro Einzelindikator**.

Reasons werden zuerst in Klassen eingeordnet:

- `JS_SMUGGLING`
- `OBFUSCATION`
- `SUSPICIOUS_API`
- `EVASION`
- `CONTAINER`
- `SCRIPT_HARD`
- `CRITICAL`

Zusätzlich existieren:

- Soft-Boni
- Hard-Boni
- Combo-Scores
- Newsletter-Multiplikatoren
- `soft_only_cap`
- `max_final_score`
- optionaler `critical_boost`

Damit wird verhindert, dass viele ähnliche Hinweise zu einer unkontrollierten Score-Explosion führen.

### Standardgewichte

```lua
weights {
  JS_SMUGGLING       = 1.2;
  OBFUSCATION        = 2.5;
  SUSPICIOUS_API     = 0.8;
  EVASION_LOGIC      = 1.5;
  CONTAINER          = 6.0;
  SCRIPT_HARD        = 7.0;
  CRITICAL           = 12.0;

  COMBO_JS_OBFUS     = 1.5;
  COMBO_HARD_OBFUS   = 2.0;
  COMBO_JS_API       = 0.8;
  COMBO_JS_EVASION   = 0.7;

  EXTERNAL_SCRIPT    = 1.0;
  CSS_EXFIL          = 2.0;
  GEO_TARGETING      = 0.8;
  ROTATION_BONUS     = 1.0;
  CLICKFIX_LURE      = 1.2;
  WASM_STAGING       = 1.4;
  BLOCKCHAIN_STAGING = 1.2;
  CSS_CODE_EXEC      = 1.5;
  ATTACHMENT_VECTOR  = 1.4;
  CERT_SMUGGLING     = 1.1;
  IMAGE_SMUGGLING    = 0.7;
}
```

---

## Limits

Die Limits schützen den Mail-Gateway-Betrieb vor übermässigem CPU-, Speicher- und Decode-Aufwand. v4.6.0 ergänzt zu den bisherigen Teilbudgets ein globales Nachrichtenbudget sowie eigene ZIP- und Crypto-Limits.

```lua
limits {
  scan {
    max_bytes               = 204800;
    smart_chunk             = 51200;
    long_html_b64_threshold = 1200;
    max_attachment_text     = 307200;
    max_attachment_magic    = 2097152;
    image_tail_max          = 262144;
  }

  b64 {
    min_len             = 200;
    magic_min_len       = 40;
    max_candidates      = 6;
    max_pool_candidates = 32;
    max_scan_bytes      = 512000;
    min_decode_total    = 400;
    big_threshold       = 5000;
    huge_threshold      = 20000;
    join_max_parts      = 5;
    join_max_len        = 180000;
  }

  decode {
    max_bytes             = 163840;
    joined_len_mul        = 2;
    max_depth             = 3;
    nested_max_candidates = 3;
  }

  script {
    max_check                = 5;
    max_external             = 5;
    max_vars                 = 20;
    smart_chunk              = 20000;
    max_script_len           = 80000;
    max_total_script_scan    = 120000;
    max_script_time_ms       = 80.0;
    deobfus_timeout_ms       = 50.0;
    split_payload_min_vars   = 6;
    prescan_chunk            = 4096;
  }

  budget {
    max_runtime_ms           = 250.0;
    max_total_bytes          = 4194304;
    max_decode_ops           = 24;
    max_container_ops        = 8;
    max_scripts_prescanned   = 64;
    max_script_prescan_bytes = 524288;
  }

  zip {
    max_entries            = 256;
    max_central_bytes      = 524288;
    max_total_uncompressed = 67108864;
    max_entry_uncompressed = 16777216;
    max_stored_extract     = 524288;
    max_member_name        = 1024;
    high_ratio             = 100;
  }

  crypto {
    max_input_bytes = 65536;
    max_key_bytes   = 64;
    max_candidates  = 4;
  }

  obfus {
    min_frag_len             = 4;
    virtual_trigger_len      = 120;
    virtual_max_payloads     = 3;
    resolve_passes           = 8;
    max_uint8array_bytes     = 2048;
    max_entropy_check_bytes  = 4096;
    css_max_style_size       = 10000;
    max_delayed_exec_context = 500;
  }
}
```

### Wichtige Limits

| Option | Standard | Bedeutung |
|---|---:|---|
| `scan.max_bytes` | 200 KiB | maximale HTML-Rohmenge |
| `scan.max_attachment_magic` | 2 MiB | maximale Rohmenge für Magic-Prüfung |
| `scan.image_tail_max` | 256 KiB | maximales Image-Tail-Carving |
| `b64.max_pool_candidates` | 32 | Kandidatenpool vor Priorisierung |
| `decode.max_depth` | 3 | maximale rekursive Decode-Tiefe |
| `script.max_check` | 5 | regulär tief geprüfte Scripts |
| `script.prescan_chunk` | 4 KiB | günstiger Vorscan pro Script |
| `budget.max_runtime_ms` | 250 ms | globales Laufzeitbudget pro Nachricht |
| `budget.max_total_bytes` | 4 MiB | globales Bytebudget |
| `budget.max_decode_ops` | 24 | maximale Decode-Operationen |
| `budget.max_container_ops` | 8 | maximale Container-Operationen |
| `budget.max_scripts_prescanned` | 64 | maximale Anzahl Prescan-Scripts |
| `budget.max_script_prescan_bytes` | 512 KiB | maximales Prescan-Bytebudget |
| `zip.max_entries` | 256 | maximal ausgewertete ZIP-Einträge |
| `zip.max_central_bytes` | 512 KiB | maximales Central-Directory-Budget |
| `zip.max_total_uncompressed` | 64 MiB | Gesamtgrenze laut ZIP-Metadaten |
| `zip.max_entry_uncompressed` | 16 MiB | Grenze pro ZIP-Mitglied |
| `zip.max_stored_extract` | 512 KiB | maximale direkte Stored-Extraktion |
| `zip.max_comment_bytes` | 8 KiB | maximal analysierter ZIP-Kommentar pro Eintrag |
| `zip.entropy_min_bytes` | 512 B | Mindestgrösse für ZIP-Stored-Entropieprüfung |
| `zip.entropy_high` | 7.3 | Info-Schwelle für hohe Entropie |
| `zip.high_ratio` | 100 | Schwelle für auffälliges Kompressionsverhältnis |
| `crypto.max_input_bytes` | 64 KiB | maximales Payloadmaterial für XOR/RC4 |
| `crypto.max_key_bytes` | 64 | maximale statische Schlüssellänge |
| `crypto.max_candidates` | 4 | maximale Crypto-Kandidaten |

---

## Thresholds

```lua
thresholds {
  entropy_high               = 4.5;
  entropy_very_high          = 5.0;
  hex_var_low                = 2;
  hex_var_high               = 5;
  array_storage_low          = 1;
  array_storage_high         = 3;
  uint8array_large_min       = 1024;
  deobfus_reduce_len_1       = 20000;
  deobfus_reduce_len_2       = 40000;
  b64_extract_loop_budget_ms = 25.0;
  script_min_len             = 20;
  normalized_script_min_len  = 40;
  delayed_exec_context       = 500;
}
```

---

## Top-Level-Konfiguration

Beispiel:

```lua
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
```

### Wichtige Optionen

| Option | Standard | Bedeutung |
|---|---:|---|
| `enabled` | `true` | aktiviert das Modul |
| `debug` | `false` | allgemeines Debug-Logging |
| `test_mode` | `false` | schreibt Test-Symbol statt Produktivsymbol |
| `log_score_threshold` | `5.0` | Schwelle für erweitertes Logging |
| `slow_log_ms` | `150` | Schwelle für Slow-Scan-Logging |
| `max_final_score` | `15.0` | maximaler Endscore |
| `soft_only_cap` | `4.5` | Score-Cap ohne Hard-Gründe |
| `critical_boost` | `0.0` | optionaler Zusatz bei Critical Payload |
| `require_script_context_for_external` | `true` | externe Scripts nur im passenden Kontext bewerten |
| `require_strong_gate_for_decode` | `true` | Decode nur bei ausreichendem Kontext |
| `redact_log_fields` | `true` | sensible Log-Felder maskieren |
| `hard_fail_on_bad_config` | `false` | ungültige Config hart abbrechen |
| `decode_debug` | `false` | detailliertes Decode-Logging |

---

## Modulkonfiguration

Module können einzeln aktiviert, auf `info_only` gesetzt oder mit einem eigenen Gewicht versehen werden.

```lua
modules {
  clickfix {
    enabled = true;
    info_only = false;
    weight_override = 0.8;
  }

  image_smuggling_info {
    enabled = false;
    info_only = true;
  }

  rc4_detection {
    enabled = false;
    info_only = false;
  }
}
```

---

## Newsletter-Entschärfung

Legitime Newsletter und Marketing-Mails enthalten häufig JavaScript-, CSS-, Tracking- oder externe Ressourcenmuster, die isoliert wie verdächtige Signale aussehen können.

Deshalb reduziert das Modul **Soft-Signale** bei erkannten Newslettern.

Beispiel:

```lua
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
    { pattern = "mailchimp";       reason = "mailer_mailchimp"; },
    { pattern = "sendgrid";        reason = "mailer_sendgrid"; },
    { pattern = "salesforce";      reason = "mailer_sfmc"; },
    { pattern = "marketing cloud"; reason = "mailer_sfmc"; }
  ];

  html_keywords = ["view in browser"];
}
```

Hard-Gründe wie Container-, Script-Hard- oder Critical-Payloads werden dadurch nicht neutralisiert.

---

## Domain-Maps

Optional können Rspamd-Maps verwendet werden:

```lua
html_smuggling {
  safe_script_domains_map =
    "/etc/rspamd/local.d/maps.d/safe_script_domains.map";

  trusted_newsletter_domains_map =
    "/etc/rspamd/local.d/maps.d/trusted_newsletter_domains.map";

  unsafe_script_domains_map =
    "/etc/rspamd/local.d/maps.d/unsafe_script_domains.map";
}
```

### Bedeutung

- `safe_script_domains_map`
  - bekannte legitime Script-Hosts

- `trusted_newsletter_domains_map`
  - reduziert Soft-Scores für bekannte Newsletter-Domains

- `unsafe_script_domains_map`
  - explizite Negativliste
  - übersteuert einen Eintrag aus der Safe-Map

---

## Installation

### Lua-Modul

```text
/etc/rspamd/lua.local.d/html_smuggling.lua
```

### Konfiguration

```text
/etc/rspamd/local.d/html_smuggling.conf
```

Danach die Rspamd-Konfiguration prüfen:

```bash
rspamadm configtest
```

Anschliessend Rspamd neu laden:

```bash
systemctl reload rspamd
```

oder neu starten:

```bash
systemctl restart rspamd
```

---

## Empfohlene Inbetriebnahme

Für einen kontrollierten Rollout:

1. mit `test_mode = true` starten
2. Logging und Scores beobachten
3. reale Newsletter und Marketing-Mails prüfen
4. interne HTML-Reports und legitime SVG/PDF-Mails prüfen
5. False Positives bewerten
6. erst danach `test_mode = false`
7. Gewichte und Caps nur gezielt verändern
8. optionale Module erst nach separatem Test aktivieren

---

## Hauptsymbol

Im Produktivmodus:

```text
HTML_SMUGGLING_PAYLOAD
```

Im Testmodus:

```text
HTML_SMUGGLING_TEST
```

---

## Marker

Je nach Detection werden zusätzliche Marker gesetzt.

Beispiele:

```text
HTML_SMUGGLING_MARKER_SERVICEWORKER
HTML_SMUGGLING_MARKER_WEBCRYPTO
HTML_SMUGGLING_MARKER_QR_CANVAS
HTML_SMUGGLING_MARKER_SPLIT_PAYLOAD
HTML_SMUGGLING_MARKER_HEX_ARRAY
HTML_SMUGGLING_MARKER_SUSPICIOUS_API
HTML_SMUGGLING_MARKER_GEO_TARGETING
HTML_SMUGGLING_MARKER_EVASION
HTML_SMUGGLING_MARKER_PERSISTENCE
HTML_SMUGGLING_MARKER_DOMAIN_ROTATION
HTML_SMUGGLING_MARKER_CLICKFIX
HTML_SMUGGLING_MARKER_WASM_STAGING
HTML_SMUGGLING_MARKER_BLOCKCHAIN_STAGING
HTML_SMUGGLING_MARKER_CSS_CODE_EXEC
HTML_SMUGGLING_MARKER_RC4_DECRYPT
HTML_SMUGGLING_MARKER_PDF_ACTIVE
HTML_SMUGGLING_MARKER_SVG_ACTIVE
HTML_SMUGGLING_MARKER_CERT_SMUGGLING
HTML_SMUGGLING_MARKER_PUSH_ABUSE
```

---

## Klassen

```text
HTML_SMUGGLING_CLASS_JS
HTML_SMUGGLING_CLASS_OBFUS
HTML_SMUGGLING_CLASS_CONTAINER
HTML_SMUGGLING_CLASS_SCRIPT_HARD
HTML_SMUGGLING_CLASS_CRITICAL
```

---

## Payload-spezifische Critical-Marker

```text
HTML_SMUGGLING_CRITICAL_PE
HTML_SMUGGLING_CRITICAL_WASM
HTML_SMUGGLING_CRITICAL_APPINSTALLER
HTML_SMUGGLING_CRITICAL_VHDX
HTML_SMUGGLING_CRITICAL_ISO
HTML_SMUGGLING_CRITICAL_LNK
HTML_SMUGGLING_CRITICAL_OLE
HTML_SMUGGLING_CRITICAL_ZIP
HTML_SMUGGLING_CRITICAL_SCRIPT
HTML_SMUGGLING_CRITICAL_MSIX
HTML_SMUGGLING_CRITICAL_APPX
HTML_SMUGGLING_CRITICAL_CAB
HTML_SMUGGLING_CRITICAL_7ZIP
HTML_SMUGGLING_CRITICAL_RAR
HTML_SMUGGLING_CRITICAL_CHM
HTML_SMUGGLING_CRITICAL_ONENOTE
```

Diese Symbole eignen sich für:

- Rspamd Policies
- Logging
- SIEM
- Dashboards
- Statistiken
- Quarantäne-Regeln
- Threat-Hunting-Auswertungen

---

## Performance- und Sicherheitsdesign

Das Modul verwendet mehrere Schutzmechanismen:

- maximale HTML-Scan-Grösse
- Smart-Chunks für grosse Inhalte
- Script-Längenbegrenzung
- Gesamtbudget für Script-Scans
- **globales Nachrichten-Laufzeitbudget**
- **globales Bytebudget**
- **Decode- und Container-Operationsbudgets**
- Script-Prescan-Limits
- Deobfuskations-Zeitbudget
- Base64-Kandidatenlimit
- Kandidaten-Priorisierung
- rekursive Decode-Tiefenbegrenzung
- ZIP-Eintrags-, Grössen- und Extraktionslimits
- Crypto-Input-, Key- und Kandidatenlimits
- Attachment-Magic-Limit
- Image-Tail-Limit
- begrenzte Anzahl externer Scripts
- defensive `pcall`-Zugriffe auf Task-/Part-Funktionen
- Config-Validierung
- Score-Caps

Dadurch bleibt der Scanner auch bei grossen oder absichtlich problematischen Nachrichten kontrollierbar.

### Budget- und Parser-Info-Reasons

Wenn ein Schutzlimit erreicht wird oder eine ZIP-Metadaten-Heuristik greift, kann v4.7.0 unter anderem folgende Info-Reasons setzen:

```text
global_runtime_budget
global_byte_budget
global_decode_budget
global_container_budget
script_prescan_budget
script_time_budget
script_total_budget
decode_depth_limit
zip_parse_incomplete
zip_high_compression_ratio
zip_many_entries
```

Diese Gründe sind wichtig für Performance-Monitoring und die Bewertung, ob ein Scan wegen eines Limits nur teilweise durchgeführt wurde.

---

## False-Positive-Bereiche

Besonders beobachten:

- Newsletter
- Marketing-Mails
- HTML-Reports
- legitime externe Scripts
- grosse Base64-Inline-Grafiken
- SVG-Dateien aus Design-Tools
- PDFs mit Formularen oder RichMedia
- Zertifikats-/PKI-Mails
- technische Monitoring-Mails
- legitime Office-Makrocontainer

Die Bewertung sollte immer zusammen mit den gesetzten Reasons, Klassen und Markern erfolgen.

---

## Grenzen

Das Modul ersetzt keine Sandbox und keinen vollständigen Datei-Parser.

Nicht oder nur eingeschränkt umgesetzt sind:

- echte Bild-Steganographie
- vollständige PDF-Objektrekonstruktion
- tiefes Office-/VBA-Parsing
- vollständige PKCS-/Zertifikatsvalidierung
- JavaScript-Ausführung in einem Browser
- Headless-Navigation externer URLs
- dynamische Analyse von Binärdateien
- System-Call-/Behavior-Analyse
- vollständige unbeschränkte Archivrekursion

`image_smuggling_info` ist daher bewusst nur ein Hinweis-Modul. Das Image-Tail-Carving in `attachment_vectors` erkennt angehängte Inhalte, aber keine allgemeine Steganographie.

---

## Test-Suite v4.7.0-r1

Zur v4.7.0-Linie gehört eine vollständige HTML-/Script-Regressionssuite mit **68 Testfällen**.

```text
HTML_Smuggling_v4.7.0_Tests_01-68.zip
```

Tests **01–56** decken den bisherigen v4.6.0-Stand ab. Neu hinzugekommen sind:

- **57** – DOM Dynamic Sink
- **58** – Dynamic `import()` aus `data:`
- **59** – Worker Blob + statische Worker-Script-Rekonstruktion
- **60** – ServiceWorker `register()` + Root Scope
- **61** – WebSocket-Portscan
- **62** – JSFuck-Heuristik
- **63** – Unicode-Escape-Rekonstruktion
- **64** – Template-Literal-Obfuskation
- **65** – ZIP-Kommentar-Payload
- **66** – ZIP-Stored-Entry mit hoher Entropie
- **67** – Stored ZIP-in-ZIP bis zur eingebetteten PE-Payload
- **68** – SharedArrayBuffer/Atomics Timing

Die Suite enthält CSV-/JSON-Manifeste mit `ExpectedDetection`, `ExpectedScore`, `ExpectedCoreReasons` und `ExpectedInfoReasons`.

Die HTML-Suite ersetzt **keine EML-Suite**. Echte MIME-Part-Dateinamen, MIME-Typen, Newsletter-Header, Maps und reale Attachment-Strukturen sollten weiterhin separat mit EML-Testfällen geprüft werden.

---

## Empfohlener produktiver Einsatz

Sinnvolle Kombination:

- Rspamd HTML Smuggling Detection
- URL-Reputation
- DNS-/Domain-Reputation
- Attachment-Policy
- AV
- Sandbox für tiefe Analyse
- SIEM-/Logging-Anbindung
- separates False-Positive-Monitoring

Besonders riskante Dateitypen wie CHM, HTA, LNK, OneNote und Script-Dateien sollten zusätzlich durch die zentrale Mail-Policy berücksichtigt werden.

---

## Kurzfazit

**v4.7.0** erweitert v4.6.0 gezielt dort, wo moderne Browser- und Containertechnik neue Ausweichpfade eröffnet:

- DOM-Sinks und Dynamic Imports werden kontextabhängig erfasst
- Worker- und ServiceWorker-Staging werden tiefer bewertet
- WebSocket-Portscan und SharedArrayBuffer-Timing ergänzen die Evasion-Erkennung
- JSFuck, Unicode-Escapes und Template Literals erweitern die Obfuskationssicht
- ZIP-Kommentare und Stored-Entropie werden analysiert
- stored ZIP-in-ZIP kann begrenzt rekursiv verfolgt werden
- globale Budgets, Prescan, ZIP-Grenzen und Early Exit bleiben unverändert als Schutzmechanismen bestehen

Die v4.6-Stärken bleiben erhalten: Magic-Prefix-Priorisierung, rekursives Base64-Decoding, `Uint8Array`-Rekonstruktion, strukturiertes ZIP-Parsing, Attachment-Magic-Prüfung, Image-Tail-Carving sowie XOR-/RC4-Rekonstruktion.

Damit ist v4.7.0 ein stärkerer **produktionsnaher Rspamd-Mail-Gateway-Stand**, ohne den Scanner in Richtung unbeschränkter Sandbox- oder Vollforensik zu verschieben.
