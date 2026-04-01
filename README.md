# Rspamd HTML Smuggling Detection Suite (v3.3)

![Version](https://img.shields.io/badge/Version-3.3-green)
![Rspamd](https://img.shields.io/badge/Rspamd-Lua%20Local-blue)
![Security](https://img.shields.io/badge/Focus-Hardened%20Gate%20%26%20Entropy-red)

## Einführung & Vision
HTML Smuggling v3.3 ist die konsequente Weiterentwicklung der Suite hin zu einer gehärteten Enterprise-Abwehrschicht. Während v3.2 die Deobfuskation perfektionierte, fokussiert sich v3.3 auf Präzision, Rauschunterdrückung und Performance-Härtung für Umgebungen mit extrem hohem Mailaufkommen .

Die Version 3.3 führt das Konzept des "Strong Decode Gate" ein: Rechenintensive Dekodierungs-Operationen werden nur noch eingeleitet, wenn der Skript-Kontext zweifelsfrei auf bösartige Smuggling-Techniken hinweist. In Kombination mit einer neuen Entropie-Analyse und Byte-Array-Sniffing (uint8array) erkennt v3.3 selbst polymorphe Malware, die klassische statische Muster komplett vermeidet.

---

## Technische Kern-Features (v3.3 Updates)

### 1. Hardened Decode Gate & Context Validation
Um die False-Positive-Rate bei komplexen, aber legitimen Web-Mails gegen Null zu senken, nutzt v3.3 ein zweistufiges Validierungsverfahren:
* Strong Gate: Dekodierung findet nur statt, wenn "Smuggling-Werkzeuge" (wie atob, blob, fetch oder MS-AppInstaller) im selben Skript-Kontext aktiv sind.
* Entropy-Check: Base64-Kandidaten werden vor der Dekodierung auf ihre Informationsdichte geprüft. Nur hochgradig strukturierte Daten (typisch für verschlüsselte oder binäre Payloads) werden weiterverarbeitet.

### 2. Uint8Array & Byte-Stream Sniffing (v3.3)
Moderne Malware-Stämme nutzen oft keine reinen Base64-Strings mehr, sondern bauen Dateien über binäre Byte-Arrays zusammen:
* Binary Reconstruction: v3.3 analysiert uint8array-Konstruktoren direkt im JavaScript-Code und erkennt darin versteckte Datenströme.
* In-Memory Sniffing: Identifiziert binäre Signaturen (Magic Bytes) innerhalb von Byte-Arrays:
    * WASM & PE: Erkennt WebAssembly-Module und Executables direkt in Array-Daten.
    * Container: Identifiziert ZIP-Header, PDF-Signaturen und ISO-Fragmente innerhalb von Variablen-Konstrukten.

### 3. Advanced API & Marker Suite
Die Suite überwacht spezialisierte Browser-Schnittstellen und setzt interne Marker für das Rspamd-Scoring:
* WebCrypto & ServiceWorker: Identifiziert Versuche, Payloads über die Crypto-API zu entschleiern oder persistente Hintergrund-Prozesse zur Infektion zu missbrauchen.
* QR-Canvas Detection: Erkennt das "Zeichnen" von Malware-Code in unsichtbare HTML5-Canvas-Elemente (QR-Code-Lure).
* Score Caps: Neue Sicherheits-Caps verhindern, dass rein heuristische Treffer ohne harten Payload-Fund (Soft-Only) kritische Schwellenwerte überschreiten.

---

## Das 5-Stage Scoring-System (v3.3)

1. Stage 1: Heuristik & API-Scan: Gewichtung von Basis-APIs mit Fokus auf Smuggling-Kontexte.
2. Stage 2: Deobfuscation & Virtual Payloads: Rekonstruktion fragmentierter Strings (Split-Payloads).
3. Stage 3: Deep Sniffing & Critical Boost: Sofortige Eskalation bei Fund von Binär-Signaturen (PE, VHDX, WASM).
4. Stage 4: Combo- & Cross-Logik: Synergien zwischen verschiedenen Detektions-Vektoren.
5. Stage 5: Trusted Auth Reduction: Validierte Newsletter (DKIM/SPF-Alignment) erhalten eine Score-Reduktion, sofern kein harter Payload-Fund vorliegt.

---

## Konfiguration & Datenschutz

Beispiel-Konfiguration für /etc/rspamd/local.d/html_smuggling.conf:

html_smuggling {
  enabled = true;
  max_final_score = 15.0;
  soft_only_score_cap = 4.5;
  redact_log_fields = true;
  require_strong_gate_for_decode = true;

  limits {
    script {
      max_total_script_scan = 120000;
      max_script_time_ms = 80.0;
    }
  }

  weights {
    wasm_uint8array = 8.0;
    pe_uint8array = 10.0;
  }
}

---

## Performance & Härtung
* Deduplizierte Kandidaten: Identische Base64-Blobs werden über verschiedene Blöcke hinweg nur einmal gescannt (Hash-basiert).
* Privacy-Friendly Logging: Sensible Daten (Message-ID, Subject) werden in den Logs standardmäßig anonymisiert (Redaction).
* Slow-Log: Protokolliert Skripte, die das Zeitbudget überschreiten, für das Performance-Monitoring.

---

## Neu in Version 3.3 gegenüber v3.2
* [x] Entropy Validation: Verhindert das Scannen von Zufalls-Rauschen.
* [x] Uint8Array Sniffing: Detektion von Malware in JavaScript-Byte-Arrays.
* [x] Strong Gate Logic: Kontext-Prüfung vor jeder Dekodierung.
* [x] Trusted Auth Reduction: Volle Integration von SPF/DKIM-Alignment.
* [x] Privacy Redaction: DSGVO-konforme Protokollierung in den Logs.

Version: 3.3 (März 2026)
Status: Enterprise Stable
Lizenz: MIT

v3.3 ist die ultimative Antwort auf polymorphe HTML-Smuggling-Angriffe und deklassiert herkömmliche Cloud-Filter technologisch.
