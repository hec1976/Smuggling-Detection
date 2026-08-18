# HTML Smuggling Detection v4.8.1-r1 – Paketübersicht

Dieses Paket enthält die vollständige Modul-, Betriebs- und Testdokumentation.

## Vollständige READMEs

- `README_html_smuggling_v4.8.1.md`
  - Architektur
  - Module
  - Scoring
  - Limits
  - Konfiguration
  - Newsletter-/Domain-Maps
  - v4.7/v4.8/v4.8.1-Erweiterungen
  - Sandbox-Handoff
  - Header-Handoff
  - Marker
  - Betrieb
  - Grenzen
  - Regression

- `README_HTML_Smuggling_TestSuite_v4.8.1_01-72_detailed.md`
  - vollständige Testdokumentation 01–72
  - Soll-Reasons
  - Scores
  - Sandbox-Profile
  - Tests 69–72

- `HTML_Smuggling_v4.8.1_Tests_01-72/README.md`
  - identisch mit dem detaillierten Test-README

## Code

- `html_smuggling_v4.8.1.lua`

## Generator

- `create_html_pattern_test_suite_v4_8_1_r1.ps1`

## Sandbox-Konfiguration

- `sandbox_escalation_default.conf.example`
- `sandbox_escalation_override_crypto.conf.example`
- `sandbox_escalation_override_extended.conf.example`
- `sandbox_escalation_empty.conf.example`

## Header-Handoff

- `milter_headers_html_smuggling_sandbox_v4.8.1.conf.example`

## Pipeline

```text
Rspamd
  -> HTML_SMUGGLING_PAYLOAD
  -> HTML_SMUGGLING_SANDBOX_CANDIDATE
  -> optional X-HEC-Sandbox-Queue: 1
  -> externe Queue / CAPE / SIEM
```

## Regression

- Test 69: rekursiver JS-Deep-Scan / Forward-Declaration
- Test 70: score-unabhängiger Sandbox-Handoff
- Test 71: Sandbox-Reason-Override nimmt XOR auf
- Test 72: Override ersetzt Defaults
