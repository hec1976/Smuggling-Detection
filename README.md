
# Rspamd HTML Smuggling Detection Suite (v3.2)

![Version](https://img.shields.io/badge/Version-3.2-green)
![Rspamd](https://img.shields.io/badge/Rspamd-Lua%20Local-blue)
![Security](https://img.shields.io/badge/Focus-Fragment%20%26%20Split%20Payload-red)

## Einführung & Vision
HTML Smuggling v3.2 ist eine hochperformante Sicherheits-Erweiterung für Rspamd, die speziell darauf ausgelegt ist, bösartige Payloads zu erkennen, die erst zur Laufzeit im Browser des Opfers zusammengesetzt werden. 

Die Version 3.2 markiert einen Meilenstein in der **Deobfuskations-Tiefe**. Während klassische Filter bei fragmentierten Variablen (Split-Payloads) versagen, rekonstruiert dieses Modul aktiv Programm-Logik, um versteckte Executables, Container und Skripte bereits im SMTP-Dialog zu enttarnen.

---

## Technische Kern-Features (v3.2 Updates)

### 1. Split Payload Power & Fragment Support
Angreifer teilen Payloads oft in winzige Stücke auf (z.B. `var p = "TVqQ"; p += "AMAA";`), um statische Signatur-Scanner zu überlisten. 
*   **Fragment-Erkennung:** Erfasst nun Fragmente ab einer Länge von nur 4 Zeichen (`min_frag_len`).
*   **Virtuelle Kandidaten:** Das Modul führt eine interne Schatten-Rekonstruktion durch. Zusammengesetzte Variablen werden als "virtuelle Kandidaten" behandelt und sofort der Sniffing-Engine übergeben.

### 2. Deep Payload Sniffing Engine (v3.2)
Anstatt alle Base64-Strings blind zu verbinden (was zu "Datenmüll" führt), nutzt v3.2 ein **Einzel-Sniffing-Verfahren**:
*   **Präzision:** Jeder Kandidat wird einzeln validiert. Ein Treffer führt zum sofortigen Abbruch des Scans (**Hard-Stop bei PE-Funden**) für maximale Performance.
*   **Erweiterte Formate:** Erkennt nun zuverlässig:
    *   **Container:** VHDX, ISO, LNK, OLE, ZIP, 7Z, RAR, CAB.
    *   **Packages:** MSIX, APPX, AppInstaller-XML.
    *   **Web-Technologien:** WebAssembly (`WASM`), JavaScript-Blobs.

### 3. Advanced API Detection
Die Suite überwacht moderne Browser-Schnittstellen, die häufig für Smuggling missbraucht werden:
*   **ServiceWorker & WebWorker:** Erkennt Versuche, Downloads im Hintergrund-Thread zu verstecken.
*   **WebCrypto & Canvas:** Identifiziert Verschlüsselung von Payloads oder das Verstecken von Code in Bilddaten (QR/Canvas).
*   **Delayed Execution:** Analysiert `setTimeout`-Kontexte auf Smuggling-Absichten.

---

## Das 5-Stage Scoring-System

Das Scoring wurde in v3.2 weiter verfeinert, um Fehlalarme (False Positives) bei Newslettern zu minimieren:

1.  **Stage 1: Heuristische Basis:** Gewichtung von APIs (Blob, atob, fetch).
2.  **Stage 2: Deobfuscation Boost:** Bonuspunkte für verschleierte Aufrufe (`window['atob']`) und rekonstruierte Fragmente.
3.  **Stage 3: Critical Payload Marker:** Massive Aufwertung bei Fund von kritischen Dateitypen (z.B. PE innerhalb eines HTML-Blobs).
4.  **Stage 4: Combo-Logik:** Synergie-Effekte (z.B. `Split-Payload` + `ZIP-Header` = Eskalation).
5.  **Stage 5: Auth-Reputation:** Dynamische Anpassung des Scores basierend auf SPF/DKIM-Status. Ein valider DKIM-Eintrag kann den Score eines Newsletters dämpfen, während ein Auth-Fail den Score multipliziert.

---

## Konfiguration & Maps

Das Modul ist hochgradig anpassbar über `/etc/rspamd/rspamd.conf.local`:

```lua
html_smuggling {
  enabled = true;
  debug = false;
  
  # Neue v3.2 Limits
  limits {
    script {
      max_script_time_ms = 80.0;     # Schutz vor ReDoS/Slow-Scripts
      deobfus_timeout_ms = 50.0;     # Timeout für Variablen-Rekonstruktion
    }
    obfus {
      min_frag_len = 4;              # Erkennt auch kleinste Code-Schnipsel
      virtual_max_payloads = 3;      # Max. rekonstruierte Schatten-Variablen
    }
  }

  # Whitelisting & Trust
  safe_script_domains_map = "/etc/rspamd/maps.d/safe_scripts.map";
  trusted_newsletter_domains_map = "/etc/rspamd/maps.d/trusted_newsletters.map";
}
```

---

## Performance & Sicherheit
*   **Pcall-Safety:** Alle kritischen Operationen (Base64-Decode, PE-Header-Parsing) sind in `pcall` gekapselt, um Rspamd-Crashes bei korrupten Daten zu verhindern.
*   **Time Budgeting:** Das Modul misst die CPU-Zeit pro Skript-Block und bricht bei Überschreitung ab, um den Mailfluss nicht zu verzögern.
*   **Extended Logging:** v3.2 schreibt detaillierte Debug-Zeilen (inkl. `dur_ms`), die genau zeigen, welcher Teil der Deobfuskation zum Treffer geführt hat.

---

## Neu in Version 3.2 gegenüber v2.9
*   [x] **MSIX/APPX Support:** Vollständige Analyse moderner Windows-App-Installer.
*   [x] **WASM Detection:** Erkennt WebAssembly-Module, die oft für In-Browser-Exploits genutzt werden.
*   [x] **Smart Text Scan:** Reduziert die Last durch intelligentes Chunking grosser HTML-Dateien.
*   [x] **Individual Sniffing:** Verhindert Fehlalarme durch zufällig zusammengesetzte Base64-Ketten.

**Version:** 3.2 (Februar 2026)  
**Status:** Stable  
**Lizenz:** MIT  

**Dieses Modul verwandelt Rspamd in eine präemptive Abwehrschicht, die Angreifer dort entlarvt, wo sie sich am sichersten fühlen: in der Komplexität von verschleiertem JavaScript.**
