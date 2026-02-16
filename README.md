# Rspamd HTML Smuggling Detection Suite (v2.9-r1)

![Version](https://img.shields.io/badge/Version-2.9--r1-green)
![Rspamd](https://img.shields.io/badge/Rspamd-Lua%20Local-blue)
![Security](https://img.shields.io/badge/Focus-Body%20%26%20Attachments-red)

## Einführung & Vision
HTML Smuggling ist einer der effektivsten Angriffsvektoren der letzten Jahre. Die Gefahr lauert dabei an zwei Stellen:
1.  **In HTML-Anhängen:** Klassische `.html` oder `.htm` Dateien, die als Anhang mitgeschickt werden.
2.  **Direkt im E-Mail-Body:** Der HTML-Teil der E-Mail selbst wird als Träger für den bösartigen Code genutzt.

Klassische Email-Gateways und Sandboxen scheitern oft an diesem Vektor, da sie entweder nur Anhänge scannen oder die bösartige Logik innerhalb der E-Mail-Struktur nicht präzise genug isolieren können. Diese Suite führt eine tiefgehende Analyse auf **allen HTML-Bestandteilen** einer E-Mail durch – in Millisekunden direkt im SMTP-Dialog.

### Das Problem klassischer Gateways (Skalierbarkeit vs. Sicherheit)
Klassische Gateways agieren oft als "Vorschlaghammer". Sie blockieren entweder zu viel oder verlassen sich auf langsame externe Prozesse.
*   **Volumen-Problem:** Bei z.B. 300.000 Mails täglich ist es technisch unmöglich, jedes HTML-Element (Body + Anhänge) dynamisch in einer Sandbox zu analysieren.
*   **Vollständige Abdeckung:** Dieses Skript scannt **jeden MIME-Part**, der HTML-Inhalt enthalten könnte. Es erkennt die **Absicht des Codes** (Intent Analysis), egal ob dieser im Körper der Mail oder in einer angehängten Datei versteckt ist. Dies entlastet nachgelagerte Sandboxen um bis zu 98 %.

---

## Technische Kern-Features

### 1. Ganzheitlicher Scan (Body & Attachments)
Das Modul unterscheidet nicht zwischen Anhang und E-Mail-Text. Es analysiert:
*   **Inline-HTML:** Smuggling-Versuche direkt im Nachrichtentext.
*   **HTML-Anhänge:** Klassische Dateien wie `Rechnung.html`.
*   **MIME-Inkonsistenz:** Erkennt HTML-Code auch dann, wenn er als `.txt` oder ohne Endung getarnt ist.

### 2. Advanced Static Deobfuscation
Angreifer verschleiern Code, um einfache Signatur-Scanner zu umgehen. Diese Suite nutzt eine lokale JS-Logik-Emulation:
*   **Variable Resolving:** Erkennt verschleierte Befehle wie `"a"+"t"+"o"+"b"` oder `"at".concat("ob")`.
*   **Array-Reconstruction:** Löst komplexe `.join('')`, `.reverse()` oder Array-Mapping Operationen auf.
*   **Bracket Notation:** Identifiziert versteckte Aufrufe wie `window['atob']` oder `this['eval']`.

### 3. Deep Payload Sniffing (Magic Byte Analysis)
Anstatt Dateiendungen zu vertrauen, dekodiert das Skript Base64-Blobs im Speicher:
*   **Executables & Images:** Windows PE-Dateien (`MZ`), ISO, VHDX, LNK.
*   **Archive:** ZIP, 7-Zip, RAR, CAB.
*   **Skripte:** VBS, PowerShell (PS1), Batch (BAT), WebAssembly (`WASM`).

---

##  Das Scoring-Modell (5-Stage-System)

Das finale Scoring basiert auf einer logischen Kette:
1.  **Stage 1: Raw Score:** Bewertung technischer Indikatoren (z.B. Vorhandensein von `Blob`).
2.  **Stage 2: Combo Logic:** "1 + 1 = 5". Bonus-Punkte bei gefährlichen Kombinationen (z.B. `atob` + `EXE-Header`).
3.  **Stage 3: Critical Boost:** Sofortige Eskalation bei High-Risk Funden (z.B. versteckte `.lnk` Datei).
4.  **Stage 4: Floor Logic:** Sicherstellung eines Mindest-Scores bei Erreichen einer Verdachts-Schwelle.
5.  **Stage 5: Auth-Multiplier:** Anpassung basierend auf der Authentizität des Absenders (SPF/DKIM/DMARC).

---

## Installation & Konfiguration

### Datei-Pfade
*   **Skript:** `/etc/rspamd/lua.local.d/html_smuggling.lua`
*   **Config:** `/etc/rspamd/rspamd.conf.local`

### Konfigurations-Beispiel
```lua
html_smuggling {
  enabled = true;
  test_mode = false;             # 'true' für reines Monitoring
  log_score_threshold = 5.0;      # Erweitertes Logging ab Score 5.0
  
  # Heuristik-Gewichtung
  heur_mul_newsletter_header = 0.3; # Entschärft validierte Newsletter
  auth_mul_enabled = true;          # Nutzt Reputation (SPF/DKIM)
  
  # Verwaltung über Maps
  safe_script_domains_map = "/etc/rspamd/maps.d/safe_scripts.map";
  trusted_newsletter_domains_map = "/etc/rspamd/maps.d/trusted_newsletters.map";
}
```

---

##  Roadmap v3.0 (Die nächsten 10 %)
*   **SVG-Script Extraction:** Analyse von JavaScript innerhalb von Bild-Tags.
*   **DOM-Link Trigger:** Detektion von dynamisch erzeugten `document.createElement('a')` Downloads.
*   **Unicode De-Masking:** Entfernung unsichtbarer Zeichen (Zero-Width-Spaces).
*   **Anti-Analysis Engine:** Erkennung von Sandbox-Checks (Screen-Resolution/Timing).
*   **CSS-Property Smuggling:** Extraktion von Payloads aus CSS-Variablen.

---

**Version:** 2.9-r1  
**Lizenz:** MIT  

**Dieses Projekt macht aus einer Standard-Mailumgebung eine gehärtete Infrastruktur, indem es Smuggling dort stoppt, wo es entsteht – egal ob im Anhang oder direkt im Text.**
