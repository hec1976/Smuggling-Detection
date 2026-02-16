# Rspamd HTML Smuggling Detection Suite (v2.9-r1)

![Version](https://img.shields.io/badge/Version-2.9--r1-green)
![Rspamd](https://img.shields.io/badge/Rspamd-Lua%20Local-blue)
![Security](https://img.shields.io/badge/Focus-Enterprise%20Security-red)
![Load](https://img.shields.io/badge/Performance-High%20Volume%20Optimized-orange)

## Einführung & Vision
HTML Smuggling ist einer der effektivsten Angriffsvektoren der letzten Jahre (genutzt von Gruppen wie Qakbot, Emotet und IcedID). Klassische Email-Sicherheitslösungen (Appliances) und Sandboxen scheitern oft an diesem Vektor, da sie entweder zu träge sind oder die bösartige Logik in der Masse des täglichen E-Mail-Verkehrs nicht präzise genug isolieren können.

Diese Suite ist das **"Skalpell" für Ihre E-Mail-Infrastruktur**. Sie führt eine tiefgehende, statische Code-Analyse und Payload-Rekonstruktion in Millisekunden durch – direkt im SMTP-Dialog.

### Das Problem klassischer Gateways (Scalability vs. Security)
Klassische Gateways agieren oft als "Vorschlaghammer". Sie blockieren entweder zu viel (Business-Interrupt) oder schicken zu viel in die Sandbox.
*   **Sandbox-Limitierung:** Bei einem Volumen von z. B. > 100.000 Mails täglich ist es technisch unmöglich, jedes HTML dynamisch zu analysieren. Die Latenz und der Ressourcenverbrauch wären untragbar.
*   **Intelligente Vorfilterung:** Dieses Skript analysiert die **Absicht des Codes** (Intent Analysis). Es entscheidet basierend auf technischer Raffinesse und Absender-Reputation, ob eine Datei gefährlich ist. Dies entlastet nachgelagerte Sandbox-Infrastrukturen um bis zu 98 %.

---

##  Technische Kern-Features

### 1. Advanced Static Deobfuscation
Angreifer verschleiern ihren Code, um einfache Signatur-Scanner zu umgehen. Diese Suite nutzt eine lokale JS-Logik-Emulation:
*   **Variable Resolving:** Erkennt verschleierte Befehle wie `"a"+"t"+"o"+"b"` oder `"at".concat("ob")`.
*   **Array-Reconstruction:** Löst komplexe `.join('')`, `.reverse()` oder Array-Mapping Operationen auf.
*   **Bracket Notation:** Identifiziert versteckte Aufrufe wie `window['atob']` oder `this['eval']`.

### 2. Deep Payload Sniffing (Magic Byte Analysis)
Anstatt der Dateiendung zu vertrauen, dekodiert das Skript Base64-Blobs im Speicher und führt einen **Magic Byte Check** durch:
*   **Executables:** Windows PE-Dateien (`MZ`).
*   **Container & Disk Images:** ISO, VHDX, LNK.
*   **Archive:** ZIP, 7-Zip, RAR, CAB.
*   **Scripts:** VBS, PowerShell (PS1), Batch (BAT).
*   **WebAssembly:** Identifikation von `.wasm` Modulen (Vektor für Browser-Exploits).

### 3. Newsletter- & Kontext-Intelligence (FP-Prevention)
Echte Enterprise-Sicherheit darf den Workflow nicht stören. Das Skript erkennt legitime Massenmails:
*   **Reputations-Check:** Integration von SPF, DKIM und DMARC Ergebnissen.
*   **Newsletter-Heuristik:** Automatische Score-Dämpfung bei validierten Newslettern via `List-ID`, `X-Mailer` oder `Unsubscribe`-Header.
*   **Smart Scan:** Große HTML-Dateien werden nicht komplett, sondern in strategischen Blöcken (Header, Mitte, Footer) gescannt, um die Performance bei High-Volume-Clustern zu garantieren.

---

## Das Scoring-Modell (5-Stage-System)

Das finale Scoring basiert auf einer logischen Kette, nicht auf bloßer Addition:
1.  **Stage 1: Raw Score:** Bewertung technischer Einzelindikatoren (z.B. Vorhandensein von `Blob`).
2.  **Stage 2: Combo Logic:** Überproportionales Scoring bei gefährlichen Kombinationen (z.B. `atob` + `EXE-Header`).
3.  **Stage 3: Critical Boost:** Sofortige Eskalation bei High-Risk Funden (z.B. eine versteckte `.lnk` Datei).
4.  **Stage 4: Floor Logic:** Sicherstellung eines Mindest-Scores bei Erreichen einer Verdachts-Schwelle.
5.  **Stage 5: Auth-Multiplier:** Dynamische Anpassung des Scores basierend auf der Authentizität des Absenders (DMARC-Faktor).

---

## 🛠️ Installation & Konfiguration

### Datei-Pfade
*   **Skript:** `/etc/rspamd/lua.local.d/html_smuggling.lua`
*   **Config:** `/etc/rspamd/local.d/html_smuggling.conf`

### Konfigurations-Beispiel
```lua
html_smuggling {
  enabled = true;
  test_mode = false;             # 'true' für reines Monitoring ohne Reject
  log_score_threshold = 5.0;      # Ab diesem Score erfolgt ein detailliertes Extended-Logging
  
  # Heuristik-Gewichtung
  heur_mul_newsletter_header = 0.3; # Reduziert Sensitivität bei Newslettern massiv
  auth_mul_enabled = true;          # Nutzt SPF/DKIM zur Score-Anpassung
  
  # Verwaltung über Maps
  safe_script_domains_map = "/etc/rspamd/maps.d/safe_scripts.map";
  trusted_newsletter_domains_map = "/etc/rspamd/maps.d/trusted_newsletters.map";
}
```

---

## Roadmap v3.0 (Die nächsten 10 %)
Um den Vorsprung gegenüber professionellen Angreifern zu halten, sind folgende Features in der Entwicklung:
*   **SVG-Script Extraction:** Analyse von JavaScript innerhalb von Bild-Tags (Scalable Vector Graphics).
*   **DOM-Link Trigger:** Detektion von dynamisch erzeugten `document.createElement('a')` Downloads.
*   **Unicode De-Masking:** Automatisches Entfernen unsichtbarer Zeichen (Zero-Width-Spaces), die klassische Scanner täuschen.
*   **Anti-Analysis Engine:** Erkennung von Skripten, die Bildschirmauflösung oder Timing prüfen, um Sandboxes zu erkennen.
*   **CSS-Property Smuggling:** Extraktion von Payloads aus CSS-Custom-Properties.

---

##  Fazit
Diese Suite bietet eine **Granularität**, die proprietäre Email-Gateways systembedingt oft vermissen lassen. Sie ermöglicht es Mail-Administratoren, eine hochperformante und hochpräzise Abwehrlinie gegen HTML-Smuggling aufzubauen, ohne die Infrastruktur durch unnötige Sandboxing-Prozesse zu überlasten.

**Dieses Projekt macht aus einer Standard-Mailumgebung eine gehärtete Enterprise-Infrastruktur.**

---

**Version:** 2.9-r1  
**Lizenz:** MIT  
