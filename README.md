
# Rspamd HTML Smuggling Detection Suite (v2.9-r1)

![Rspamd](https://img.shields.io/badge/Rspamd-Lua%20Local-blue)
![Security](https://img.shields.io/badge/Focus-HTML%20Smuggling-red)
![Strategy](https://img.shields.io/badge/Strategy-Scalpel%20vs%20Sledgehammer-orange)

## Das "Skalpell" für Ihre E-Mail-Infrastruktur
In der modernen Bedrohungslandschaft stoßen **klassische Email-Gateways** oft an ihre Grenzen. Während herkömmliche Security-Appliances hervorragend darin sind, bekannte Malware und Massen-Spam zu blockieren, fehlt ihnen oft die nötige Tiefe für die Analyse von **HTML Smuggling**.

### Die perfekte Ergänzung zu klassischen Gateways
Dieses Rspamd-Modul fungiert als **"Skalpell" für die hochkomplexen 10 %** der Bedrohungen, die von herkömmlichen Systemen oft übersehen werden. Klassische Gateways agieren meist als "Vorschlaghammer" – sie sind effektiv gegen 90 % des "Rauschens", lassen aber bei gezielten, verschleierten Angriffen Lücken offen. 

Dieses Skript bietet die **Granularität und Kontext-Intelligenz**, die proprietäre Boxen systembedingt oft vermissen lassen. Es analysiert die Absicht des Codes, bevor teure und langsame Sandboxing-Prozesse überhaupt gestartet werden müssen.

---

##  Kern-Funktionen (v2.9-r1)

### 1. Intelligente Deobfuskation (Statische Analyse)
Angreifer verstecken bösartigen Code durch Zerstückelung. Dieses Skript führt eine Echtzeit-Rekonstruktion der Variablen durch:
*   **Variable Resolving:** Erkennt verschleierte Befehle wie `"a"+"t"+"o"+"b"` als `atob`.
*   **Array Reconstruction:** Löst komplexe `.join()` und Verknüpfungs-Operationen logisch auf.
*   **Bracket Notation:** Identifiziert versteckte Funktionsaufrufe wie `window['atob']`.

### 2. Deep Payload Sniffing (Magic Bytes)
Vertrauen Sie niemals einer Dateiendung. Das Skript analysiert die Header (Magic Bytes) der dekodierten Datenströme im Speicher:
*   **Executables:** Identifikation von PE/Windows-Binaries (`MZ`).
*   **Disk Images:** Erkennung von ISO-, VHDX- und LNK-Vektoren.
*   **Container:** Prüfung von ZIP, 7-Zip, RAR und CAB-Archiven auf Code-Ebene.
*   **Spezial-Vektoren:** Unterstützung für WebAssembly (`WASM`) und AppInstaller-Strukturen.

### 3. Kontext- & Newsletter-Intelligence
Echte Sicherheit braucht Kontext. Das Skript verhindert Fehlalarme (False Positives) durch tiefes Protokoll-Verständnis:
*   **Reputations-Check:** Integration von SPF, DKIM und DMARC Ergebnissen in das Scoring.
*   **Newsletter-Heuristik:** Automatische Score-Dämpfung bei validierten Massenmails durch Analyse von `List-ID` und `Unsubscribe`-Headern.
*   **Granulare Steuerung:** Differenzierung zwischen unbekannten Absendern und etablierten Kommunikationspartnern.

---

## Roadmap: Die v3.0 Features
Um den Vorsprung gegenüber professionellen Angreifern zu halten, befinden sich folgende Erweiterungen in der Entwicklung:
*   **SVG-Script Smuggling:** Extraktion von JavaScript aus scheinbar harmlosen Vektorgrafiken.
*   **DOM-Link Trigger:** Detektion von dynamisch erzeugten `document.createElement('a')` Downloads.
*   **Unicode De-Masking:** Automatisches Entfernen unsichtbarer Zeichen (Zero-Width-Spaces), die klassische Scanner täuschen.
*   **Anti-Analysis Engine:** Erkennung von Skripten, die ihre Umgebung prüfen (Sandbox-Detektion via Timing & Auflösung).
*   **CSS-Property Smuggling:** Analyse von Payloads, die in CSS-Custom-Properties versteckt sind.

---

## Installation & Konfiguration

### Datei-Struktur
*   **Skript-Pfad:** `/etc/rspamd/lua.local.d/html_smuggling.lua`
*   **Konfiguration:** `/etc/rspamd/local.d/html_smuggling.conf`

### Beispiel für `html_smuggling.conf`
```lua
html_smuggling {
  enabled = true;
  test_mode = false;             # 'true' für reines Monitoring ohne Reject
  log_score_threshold = 5.0;      # Erweitertes Logging ab einem Score von 5.0
  
  # Heuristik-Gewichtung
  heur_mul_newsletter_header = 0.3; # Reduziert Sensitivität bei Newslettern
  
  # Verwaltung über Maps
  safe_script_domains_map = "/etc/rspamd/maps.d/safe_scripts.map";
  trusted_newsletter_domains_map = "/etc/rspamd/maps.d/trusted_newsletters.map";
}
```

---

##  Das Scoring-Modell (Stage-System)
Das Modul nutzt ein transparentes Scoring-Verfahren:
1.  **Raw Score:** Bewertung technischer Einzelindikatoren.
2.  **Combo Logic:** Überproportionales Scoring bei gefährlichen Kombinationen (z.B. `atob` + `EXE-Header`).
3.  **Critical Boost:** Sofortige Eskalation bei High-Risk Payloads (z.B. ISO/VHDX).
4.  **Auth-Multiplier:** Dynamische Anpassung des Risikos basierend auf der Absender-Reputation.

---

**Version:** 2.9-r1  
**Lizenz:** MIT  

*Hinweis: Dieses Modul ist ein Werkzeug für Security-Professionals. Nutzen Sie den `test_mode`, um die Granularität optimal auf Ihre spezifische Mail-Umgebung abzustimmen.*
