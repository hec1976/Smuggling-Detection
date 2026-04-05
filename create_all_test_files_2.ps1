# create_realistic_test_suite.ps1
# Erstellt 30 realistische HTML Testdateien für HTML Smuggling Detection v4.3.7c-r4.1
# Ziel:
#   Alle relevanten Base64 Testpayloads so erzeugen, dass sie die Decode Gates erfüllen:
#     LB64.min_len = 200
#     LB64.min_decode_total = 400
# Ausgabe: UTF-8 ohne BOM

param(
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "╔══════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   REALISTIC HTML Smuggling Test Suite v2.2 für Rspamd v4.3.7c-r4.1                  ║" -ForegroundColor Cyan
Write-Host "║   Module: JS Smuggling | Obfuscation | WASM | PDF | SVG | Certificates | Images    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$testFolderName = 'HTML_Smuggling_TestSuite_v2'
$outputRoot = Join-Path -Path (Get-Location).Path -ChildPath $testFolderName
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# Decoder Gates aus der Lua Logik
$MinDecodeBase64Chars = 400
$TargetPayloadBytes = 320   # 320 Bytes ergeben 428 Base64 Zeichen und liegen damit sicher über 400

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
    throw "$Name ist zu kurz für den Decode Gate. Länge=$($Base64.Length), Minimum=$MinimumChars"
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
  # Minimaler, konsistenter PE Header
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
    [byte[]]$full = Join-ByteArrays -Arrays @($full, $padding)
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
$JS_ATTACHMENT_BASE64 = Convert-TextToBase64MinSize -Text "var payload = 'test'; function run() { return payload; }" -MinimumBytes $TargetPayloadBytes

$certPemB64 = Convert-TextToBase64MinSize -Text $CERT_PEM -MinimumBytes $TargetPayloadBytes
$certPkcs7B64 = Convert-TextToBase64MinSize -Text $CERT_PKCS7 -MinimumBytes $TargetPayloadBytes

# Sicherstellen, dass alle relevanten Payloads die Decode Gates erfüllen
Assert-MinBase64Length -Name 'PE_BASE64' -Base64 $PE_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'WASM_BASE64' -Base64 $WASM_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'PDF_JS_BASE64' -Base64 $PDF_JS_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'PDF_LAUNCH_BASE64' -Base64 $PDF_LAUNCH_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'ZIP_BASE64' -Base64 $ZIP_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'CHM_BASE64' -Base64 $CHM_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'LNK_BASE64' -Base64 $LNK_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'SVG_BASE64' -Base64 $SVG_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'HTA_BASE64' -Base64 $HTA_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'JS_ATTACHMENT_BASE64' -Base64 $JS_ATTACHMENT_BASE64 -MinimumChars $MinDecodeBase64Chars
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
Write-Host "JS Attachment Payload: $($JS_ATTACHMENT_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "CERT PEM Payload: $($certPemB64.Length) Zeichen" -ForegroundColor Gray
Write-Host "CERT PKCS7 Payload: $($certPkcs7B64.Length) Zeichen" -ForegroundColor Gray
Write-Host ""

$testFiles = @()

# ===== KERNEL MODULE TESTS =====

$testFiles += @{
  Name = "test01_basic_pe_smuggling.html"
  ExpectedScore = "12-18"
  ExpectedDetection = "YES"
  Description = "Basis: atob + Blob + createObjectURL + PE"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var payload = "$PE_BASE64";
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'invoice.exe';
a.click();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test02_split_payload_pe.html"
  ExpectedScore = "18-24"
  ExpectedDetection = "YES"
  Description = "Split Payload: += Concatenation + PE"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var p1 = "$($PE_BASE64.Substring(0, 250))";
var p2 = "$($PE_BASE64.Substring(250, 250))";
var p3 = "$($PE_BASE64.Substring(500))";
var payload = "";
payload += p1;
payload += p2;
payload += p3;
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'split.exe';
a.click();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test03_array_join_pe.html"
  ExpectedScore = "18-24"
  ExpectedDetection = "YES"
  Description = "Array.join() + PE"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var parts = ["$($PE_BASE64.Substring(0,250))","$($PE_BASE64.Substring(250,250))","$($PE_BASE64.Substring(500))"];
var payload = parts.join('');
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'joined.exe';
a.click();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test04_obfuscated_pe.html"
  ExpectedScore = "24-30"
  ExpectedDetection = "YES"
  Description = "Polymorphic Obfuscation + PE"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var _0x4a8b = ['atob', 'Blob', 'createObjectURL', 'createElement', 'a', 'href', 'download', 'click'];
var _0x2c9d = "$PE_BASE64";
var _0x1f3e = window[_0x4a8b[0]](_0x2c9d);
var _0x5b2a = new window[_0x4a8b[1]]([_0x1f3e], {type:'application/octet-stream'});
var _0x7d4c = URL[_0x4a8b[2]](_0x5b2a);
var _0x9e6b = document[_0x4a8b[3]](_0x4a8b[4]);
_0x9e6b[_0x4a8b[5]] = _0x7d4c;
_0x9e6b[_0x4a8b[6]] = 'obfuscated.exe';
_0x9e6b[_0x4a8b[7]]();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test05_wasm_smuggling.html"
  ExpectedScore = "12-18"
  ExpectedDetection = "YES"
  Description = "WebAssembly Module (WASM_STAGING)"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var wasmData = "$WASM_BASE64";
var decoded = atob(wasmData);
var blob = new Blob([decoded], {type: 'application/wasm'});
var url = URL.createObjectURL(blob);
if (typeof WebAssembly !== 'undefined') {
  fetch(url).then(function(r) { return r.arrayBuffer(); }).then(function(bytes) {
    WebAssembly.instantiate(bytes);
  });
}
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test06_uint8array_pe.html"
  ExpectedScore = "20-28"
  ExpectedDetection = "YES"
  Description = "Uint8Array mit PE Bytes"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var peBytes = new Uint8Array([0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x50,0x45,0x00,0x00,0x4C,0x01]);
var blob = new Blob([peBytes], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'uint8.exe';
a.click();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test07_delayed_execution_pe.html"
  ExpectedScore = "18-24"
  ExpectedDetection = "YES"
  Description = "setTimeout delayed execution + PE"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
setTimeout(function() {
  var payload = "$PE_BASE64";
  var decoded = atob(payload);
  var blob = new Blob([decoded], {type: 'application/octet-stream'});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'delayed.exe';
  a.click();
}, 100);
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test08_webworker_pe.html"
  ExpectedScore = "18-24"
  ExpectedDetection = "YES"
  Description = "Web Worker + PE Payload"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var workerCode = "self.onmessage = function(e) { var decoded = atob(e.data.payload); self.postMessage({decoded: decoded}); }";
var blob = new Blob([workerCode], {type: 'application/javascript'});
var workerUrl = URL.createObjectURL(blob);
var worker = new Worker(workerUrl);
worker.onmessage = function(e) {
  var blob2 = new Blob([e.data.decoded], {type: 'application/octet-stream'});
  var url = URL.createObjectURL(blob2);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'worker.exe';
  a.click();
};
worker.postMessage({payload: "$PE_BASE64"});
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test09_fetch_api_pe.html"
  ExpectedScore = "16-22"
  ExpectedDetection = "YES"
  Description = "Fetch API + PE Smuggling"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var payload = "$PE_BASE64";
fetch('data:application/octet-stream;base64,' + payload)
  .then(function(r) { return r.blob(); })
  .then(function(b) {
    var url = URL.createObjectURL(b);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'fetched.exe';
    a.click();
  });
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test10_appinstaller_schema.html"
  ExpectedScore = "8-12"
  ExpectedDetection = "YES"
  Description = "ms-appinstaller URI Schema"
  Content = @"
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
}

# ===== ATTACHMENT VECTORS =====

$testFiles += @{
  Name = "test11_pdf_javascript_attachment.html"
  ExpectedScore = "6-10"
  ExpectedDetection = "YES"
  Description = "PDF mit /JavaScript Action"
  Content = @"
<!DOCTYPE html>
<html><body>
<p>Please find your invoice attached.</p>
<script>
var pdfData = "$PDF_JS_BASE64";
var decoded = atob(pdfData);
var blob = new Blob([decoded], {type: 'application/pdf'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'invoice.pdf';
a.click();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test12_pdf_launch_attachment.html"
  ExpectedScore = "8-12"
  ExpectedDetection = "YES"
  Description = "PDF mit /Launch Action"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var pdfData = "$PDF_LAUNCH_BASE64";
var decoded = atob(pdfData);
var blob = new Blob([decoded], {type: 'application/pdf'});
var url = URL.createObjectURL(blob);
window.open(url);
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test13_svg_active_content.html"
  ExpectedScore = "8-12"
  ExpectedDetection = "YES"
  Description = "SVG mit script und active content"
  Content = @"
<!DOCTYPE html>
<html><body>
<object data="data:image/svg+xml;base64,$SVG_BASE64" type="image/svg+xml"></object>
</body></html>
"@
}

$testFiles += @{
  Name = "test14_chm_attachment.html"
  ExpectedScore = "10-15"
  ExpectedDetection = "YES"
  Description = "CHM Datei als Attachment"
  Content = @"
<!DOCTYPE html>
<html><body>
<p>Help documentation</p>
<script>
var chmData = "$CHM_BASE64";
var decoded = atob(chmData);
var blob = new Blob([decoded], {type: 'application/vnd.ms-htmlhelp'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'help.chm';
a.click();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test15_hta_attachment.html"
  ExpectedScore = "12-18"
  ExpectedDetection = "YES"
  Description = "HTA Datei"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var htaData = "$HTA_BASE64";
var decoded = atob(htaData);
var blob = new Blob([decoded], {type: 'application/hta'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'update.hta';
a.click();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test16_onenote_attachment.html"
  ExpectedScore = "10-15"
  ExpectedDetection = "YES"
  Description = "OneNote Datei"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var oneData = "$ZIP_BASE64";
var decoded = atob(oneData);
var blob = new Blob([decoded], {type: 'application/onenote'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'notes.one';
a.click();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test17_office_macro_container.html"
  ExpectedScore = "8-12"
  ExpectedDetection = "YES"
  Description = "Office Macro Container (DOCM/XLSM)"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var docmData = "$ZIP_BASE64";
var decoded = atob(docmData);
var blob = new Blob([decoded], {type: 'application/vnd.ms-word.document.macroEnabled.12'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'invoice.docm';
a.click();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test18_lnk_attachment.html"
  ExpectedScore = "8-12"
  ExpectedDetection = "YES"
  Description = "LNK Shortcut Datei"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var lnkData = "$LNK_BASE64";
var decoded = atob(lnkData);
var blob = new Blob([decoded], {type: 'application/x-ms-shortcut'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'shortcut.lnk';
a.click();
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test19_script_attachment_js.html"
  ExpectedScore = "10-15"
  ExpectedDetection = "YES"
  Description = "JavaScript Datei als Attachment"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var jsData = "$JS_ATTACHMENT_BASE64";
var decoded = atob(jsData);
var blob = new Blob([decoded], {type: 'text/javascript'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'script.js';
a.click();
</script>
</body></html>
"@
}

# ===== CERTIFICATE SMUGGLING =====

$testFiles += @{
  Name = "test20_certificate_inline_pem.html"
  ExpectedScore = "2-5"
  ExpectedDetection = "YES"
  Description = "Inline PEM Zertifikat"
  Content = @"
<!DOCTYPE html>
<html><body>
<pre>
$CERT_PEM
</pre>
<script>
var certData = "$certPemB64";
var decoded = atob(certData);
console.log(decoded.length);
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test21_certificate_pkcs7_inline.html"
  ExpectedScore = "2-5"
  ExpectedDetection = "YES"
  Description = "Inline PKCS7 Container"
  Content = @"
<!DOCTYPE html>
<html><body>
<pre>
$CERT_PKCS7
</pre>
<script>
var pkcsData = "$certPkcs7B64";
console.log(pkcsData.length);
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test22_certificate_smuggling_context.html"
  ExpectedScore = "6-10"
  ExpectedDetection = "YES"
  Description = "Zertifikat + Smuggling Context"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var cert = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKlQz7jYpU9MMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xDzANBgNVBAcMBk11ZW5jaDERMA8GA1UE\nCgwIVGVzdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMtCj3lZ\n-----END CERTIFICATE-----";
var payload = "$PE_BASE64";
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
console.log(cert.length, url);
</script>
</body></html>
"@
}

# ===== IMAGE SMUGGLING INFO =====

$testFiles += @{
  Name = "test23_image_double_ext.html"
  ExpectedScore = "0-2"
  ExpectedDetection = "INFO_ONLY"
  Description = "Image mit doppelter Extension"
  Content = @"
<!DOCTYPE html>
<html><body>
<img src="invoice.png.html" />
<img src="document.jpg.exe" />
</body></html>
"@
}

$testFiles += @{
  Name = "test24_image_polyglot_hint.html"
  ExpectedScore = "0-2"
  ExpectedDetection = "INFO_ONLY"
  Description = "Image mit verdächtigem Namen"
  Content = @"
<!DOCTYPE html>
<html><body>
<img src="invoice_payload.png" />
<img src="image_with_payload.jpg" />
</body></html>
"@
}

# ===== CSS CODE EXECUTION =====

$testFiles += @{
  Name = "test25_css_code_execution.html"
  ExpectedScore = "6-10"
  ExpectedDetection = "YES"
  Description = "CSS Code Execution"
  Content = @"
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
}

$testFiles += @{
  Name = "test26_css_computedstyle_exec.html"
  ExpectedScore = "4-8"
  ExpectedDetection = "YES"
  Description = "CSS getComputedStyle Execution"
  Content = @"
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
}

# ===== NEGATIVE TESTS =====

$testFiles += @{
  Name = "test27_NEGATIVE_legitimate.html"
  ExpectedScore = "0-2"
  ExpectedDetection = "NO"
  Description = "Legitime Website"
  Content = @"
<!DOCTYPE html>
<html>
<head><title>Legitimate Site</title></head>
<body>
<h1>Welcome</h1>
<img src="logo.png">
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
<script>
var userId = btoa("user123");
var canvas = document.createElement('canvas');
var ctx = canvas.getContext('2d');
ctx.fillText("Hello", 10, 10);
</script>
</body>
</html>
"@
}

$testFiles += @{
  Name = "test28_NEGATIVE_newsletter.html"
  ExpectedScore = "0-1"
  ExpectedDetection = "NO"
  Description = "Newsletter mit Tracking"
  Content = @"
<!DOCTYPE html>
<html><body>
<p>Unsubscribe: <a href="https://unsubscribe.example.com">Click here</a></p>
<img src="tracking.png" style="display:none">
<script>
var trackingData = btoa("campaign=summer2025");
fetch('https://tracking.example.com/log?data=' + trackingData);
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test29_NEGATIVE_safe_domain.html"
  ExpectedScore = "0-2"
  ExpectedDetection = "NO"
  Description = "External Script von sicherer Domain"
  Content = @"
<!DOCTYPE html>
<html><body>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
<script>
var data = "test";
console.log(data);
</script>
</body></html>
"@
}

# ===== ALL IN ONE =====

$testFiles += @{
  Name = "test30_ALL_IN_ONE_MAXIMUM.html"
  ExpectedScore = "40-55"
  ExpectedDetection = "YES"
  Description = "Alle Techniken kombiniert"
  Content = @"
<!DOCTYPE html>
<html><head>
<style>
body::before { content: "atob('$($PE_BASE64.Substring(0,100))')"; }
</style>
</head>
<body>
<canvas id="qr"></canvas>
<iframe id="hidden" style="display:none"></iframe>
<pre>
$CERT_PEM
</pre>
<script>
var _0x1a2b = ['atob', 'Blob', 'createObjectURL', 'Worker', 'fetch'];
var p1 = "$($PE_BASE64.Substring(0,250))";
var p2 = "$($PE_BASE64.Substring(250,250))";
var p3 = "$($PE_BASE64.Substring(500))";
var parts = [p1, p2, p3];
var payload = parts.join('');

setTimeout(function() {
  var canvas = document.getElementById('qr');
  var ctx = canvas.getContext('2d');
  ctx.fillRect(0, 0, 100, 100);

  var decode = window[_0x1a2b[0]];
  var decoded = decode(payload);
  var blob = new window[_0x1a2b[1]]([decoded], {type: 'application/octet-stream'});
  var url = URL[_0x1a2b[2]](blob);

  var workerCode = 'self.postMessage("ready")';
  var workerBlob = new Blob([workerCode], {type: 'application/javascript'});
  var workerUrl = URL.createObjectURL(workerBlob);
  var worker = new Worker(workerUrl);

  fetch(url).then(function(r) { return r.blob(); }).then(function(b) {
    var finalUrl = URL.createObjectURL(b);
    var a = document.createElement('a');
    a.href = finalUrl;
    a.download = 'all_in_one.exe';
    a.click();
  });

  document.getElementById('hidden').src = 'data:text/html;base64,' + payload.substring(0, 100);
}, 100);

if ('serviceWorker' in navigator) {
  var swCode = 'self.addEventListener("install", function(e) { e.waitUntil(self.skipWaiting()); })';
  var swBlob = new Blob([swCode], {type: 'application/javascript'});
  var swUrl = URL.createObjectURL(swBlob);
  navigator.serviceWorker.register(swUrl);
}

if (window.crypto && crypto.subtle) {
  crypto.subtle.generateKey({name: 'AES-CBC', length: 256}, true, ['encrypt']);
}

var wasmData = "$WASM_BASE64";
var wasmDecoded = atob(wasmData);
var wasmBlob = new Blob([wasmDecoded], {type: 'application/wasm'});
var wasmUrl = URL.createObjectURL(wasmBlob);
if (typeof WebAssembly !== 'undefined') {
  fetch(wasmUrl).then(function(r) { return r.arrayBuffer(); }).then(function(bytes) {
    WebAssembly.instantiate(bytes);
  });
}
</script>
</body></html>
"@
}

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
        Write-Host "⏭  Überspringe existierende Datei: $($file.Name) (nutze -Force)" -ForegroundColor Yellow
        continue
      }

      Write-Utf8NoBomFile -Path $path -Content $file.Content

      Write-Host "✅ $($file.Name)" -ForegroundColor Green
      Write-Host "   Score: $($file.ExpectedScore) | Detection: $($file.ExpectedDetection)" -ForegroundColor Gray
      Write-Host "   $($file.Description)" -ForegroundColor DarkGray
      Write-Host ""

      $summary += [PSCustomObject]@{
        File = $file.Name
        ExpectedScore = $file.ExpectedScore
        Detection = $file.ExpectedDetection
        Description = $file.Description
      }

      $successCount++
    }
    catch {
      Write-Host "❌ Fehler bei $($file.Name): $($_.Exception.Message)" -ForegroundColor Red
      $errorCount++
    }
  }

  $csvPath = Join-Path -Path (Get-Location).Path -ChildPath 'test_manifest.csv'
  $jsonPath = Join-Path -Path (Get-Location).Path -ChildPath 'test_manifest.json'

  $summary | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
  ($summary | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $jsonPath -Encoding UTF8

  Write-Host ""
  Write-Host "╔══════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
  Write-Host "║                         TEST SUITE ABGESCHLOSSEN                                    ║" -ForegroundColor Cyan
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
  Write-Host "║  ERWARTETE DETECTION RATE: 90% (27/30 Tests)" -ForegroundColor Yellow
  Write-Host "║" -ForegroundColor Cyan
  Write-Host "║  MODULE TEST COVERAGE:" -ForegroundColor Magenta
  Write-Host "║    ✅ JS_SMUGGLING       | Tests 01-10" -ForegroundColor Gray
  Write-Host "║    ✅ ATTACHMENT_VECTORS | Tests 11-19" -ForegroundColor Gray
  Write-Host "║    ✅ CERT_SMUGGLING     | Tests 20-22" -ForegroundColor Gray
  Write-Host "║    ✅ IMAGE_SMUGGLING    | Tests 23-24" -ForegroundColor Gray
  Write-Host "║    ✅ CSS_CODE_EXEC      | Tests 25-26" -ForegroundColor Gray
  Write-Host "║    ✅ NEGATIVE TESTS     | Tests 27-29" -ForegroundColor Gray
  Write-Host "║    ✅ ALL IN ONE         | Test 30" -ForegroundColor Gray
  Write-Host "║" -ForegroundColor Cyan
  Write-Host "║  CSV Manifest:  $csvPath" -ForegroundColor Gray
  Write-Host "║  JSON Manifest: $jsonPath" -ForegroundColor Gray
  Write-Host "╚══════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
  Write-Host ""
}
finally {
  Pop-Location
}
