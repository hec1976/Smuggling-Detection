# create_realistic_test_suite.ps1
# Erstellt 20 REALISTISCHE HTML-Testdateien fuer HTML Smuggling Detection
# Diese Tests triggern das Rspamd Lua-Script korrekt!
# Ausgabe: UTF-8 ohne BOM

param(
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   REALISTIC HTML Smuggling Test Suite v1.0                 ║" -ForegroundColor Cyan
Write-Host "║   Optimiert fuer Rspamd HTML Smuggling Detection v3.2      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$testFolder = "HTML_Smuggling_TestSuite_REALISTIC"
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
    0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,  # MZ Header
    0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00  # e_lfanew at offset 0x3C = 0x80
  )
  
  # DOS Stub (bis Offset 0x80)
  $stub = [byte[]](0x0E) * (0x80 - $dos.Length)
  
  # PE Header at offset 0x80
  $pe = [byte[]](
    0x50,0x45,0x00,0x00,  # PE\0\0 Signature
    0x4C,0x01,            # Machine: 0x014C (i386)
    0x03,0x00,            # NumberOfSections: 3
    0x00,0x00,0x00,0x00,  # TimeDateStamp
    0x00,0x00,0x00,0x00,  # PointerToSymbolTable
    0x00,0x00,0x00,0x00,  # NumberOfSymbols
    0xE0,0x00,            # SizeOfOptionalHeader: 224
    0x02,0x01             # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
  )
  
  # Optional Header (minimal, 224 Bytes)
  $optional = [byte[]](0x00) * 224
  $optional[0] = 0x0B  # Magic: PE32
  $optional[1] = 0x01
  
  $full = $dos + $stub + $pe + $optional
  
  # Padding auf mind. 512 Bytes (besser fuer Detection)
  if ($full.Length -lt 512) {
    $padding = [byte[]](0x00) * (512 - $full.Length)
    $full = $full + $padding
  }
  
  return [Convert]::ToBase64String($full)
}

function New-FakeZIPHeader {
  # Minimaler ZIP mit einer leeren Datei
  $zip = [byte[]](
    0x50,0x4B,0x03,0x04,  # Local file header signature
    0x14,0x00,            # Version needed to extract
    0x00,0x00,            # General purpose bit flag
    0x00,0x00,            # Compression method (stored)
    0x00,0x00,            # Last mod file time
    0x00,0x00,            # Last mod file date
    0x00,0x00,0x00,0x00,  # CRC-32
    0x00,0x00,0x00,0x00,  # Compressed size
    0x00,0x00,0x00,0x00,  # Uncompressed size
    0x08,0x00,            # File name length (8)
    0x00,0x00             # Extra field length (0)
  )
  
  $filename = [System.Text.Encoding]::ASCII.GetBytes("test.txt")
  
  # Central directory header
  $central = [byte[]](
    0x50,0x4B,0x01,0x02,  # Central directory file header signature
    0x14,0x00,            # Version made by
    0x14,0x00,            # Version needed to extract
    0x00,0x00,            # General purpose bit flag
    0x00,0x00,            # Compression method
    0x00,0x00,            # Last mod file time
    0x00,0x00,            # Last mod file date
    0x00,0x00,0x00,0x00,  # CRC-32
    0x00,0x00,0x00,0x00,  # Compressed size
    0x00,0x00,0x00,0x00,  # Uncompressed size
    0x08,0x00,            # File name length
    0x00,0x00,            # Extra field length
    0x00,0x00,            # File comment length
    0x00,0x00,            # Disk number start
    0x00,0x00,            # Internal file attributes
    0x00,0x00,0x00,0x00,  # External file attributes
    0x00,0x00,0x00,0x00   # Relative offset of local header
  )
  
  # End of central directory
  $eocd = [byte[]](
    0x50,0x4B,0x05,0x06,  # End of central directory signature
    0x00,0x00,            # Number of this disk
    0x00,0x00,            # Disk where central directory starts
    0x01,0x00,            # Number of central directory records on this disk
    0x01,0x00,            # Total number of central directory records
    0x2E,0x00,0x00,0x00,  # Size of central directory (46 bytes)
    0x26,0x00,0x00,0x00,  # Offset of start of central directory
    0x00,0x00             # ZIP file comment length
  )
  
  $full = $zip + $filename + $central + $filename + $eocd
  
  # Padding für bessere Detection
  if ($full.Length -lt 256) {
    $padding = [byte[]](0x00) * (256 - $full.Length)
    $full = $full + $padding
  }
  
  return [Convert]::ToBase64String($full)
}

function New-FakeWASMModule {
  # Minimales WASM-Modul
  $wasm = [byte[]](
    0x00,0x61,0x73,0x6D,  # \0asm magic
    0x01,0x00,0x00,0x00   # Version 1
  )
  
  # Type section (minimal)
  $wasm += [byte[]](0x01,0x04,0x01,0x60,0x00,0x00)
  
  # Function section
  $wasm += [byte[]](0x03,0x02,0x01,0x00)
  
  # Export section
  $wasm += [byte[]](0x07,0x08,0x01,0x04,0x6D,0x61,0x69,0x6E,0x00,0x00)
  
  # Code section
  $wasm += [byte[]](0x0A,0x04,0x01,0x02,0x00,0x0B)
  
  # Padding
  if ($wasm.Length -lt 256) {
    $padding = [byte[]](0x00) * (256 - $wasm.Length)
    $wasm = $wasm + $padding
  }
  
  return [Convert]::ToBase64String($wasm)
}

function New-FakePDF {
  $pdf = "%PDF-1.4`n1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n"
  $pdf += "2 0 obj`n<< /Type /Pages /Kids [3 0 R] /Count 1 >>`nendobj`n"
  $pdf += "3 0 obj`n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 << /Type /Font >> >> >> >>`nendobj`n"
  $pdf += "xref`n0 4`n0000000000 65535 f`n0000000009 00000 n`n0000000074 00000 n`n0000000133 00000 n`n"
  $pdf += "trailer`n<< /Size 4 /Root 1 0 R >>`nstartxref`n271`n%%EOF"
  
  return [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pdf))
}

function New-LongBase64String {
  param([string]$base, [int]$targetLength)
  
  while ($base.Length -lt $targetLength) {
    $base += $base
  }
  
  return $base.Substring(0, $targetLength)
}

# ============================================================================
# TEST DEFINITIONS
# ============================================================================

Write-Host "Generiere Payloads..." -ForegroundColor Yellow
$PE_BASE64 = New-FakePEHeader
$ZIP_BASE64 = New-FakeZIPHeader
$WASM_BASE64 = New-FakeWASMModule
$PDF_BASE64 = New-FakePDF

Write-Host "PE Payload: $($PE_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "ZIP Payload: $($ZIP_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "WASM Payload: $($WASM_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host "PDF Payload: $($PDF_BASE64.Length) Zeichen" -ForegroundColor Gray
Write-Host ""

$testFiles = @(
  # ========================================================================
  # TEST 1: Basis atob + Blob + PE (MUSS erkannt werden!)
  # ========================================================================
  @{
    Name = "test01_basic_pe_smuggling.html"
    ExpectedScore = "15-20"
    ExpectedDetection = "YES"
    Description = "Basis-Test: atob + Blob + createObjectURL + PE"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 1: Basic PE Smuggling</title></head>
<body>
<h1>Invoice Document</h1>
<p>Please download your invoice...</p>
<script>
function downloadInvoice() {
  var payload = "$PE_BASE64";
  var decoded = atob(payload);
  var blob = new Blob([decoded], {type: 'application/octet-stream'});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'invoice.exe';
  document.body.appendChild(a);
  a.click();
  URL.revokeObjectURL(url);
}
window.onload = downloadInvoice;
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 2: Split Payload (v3.2 Feature!)
  # ========================================================================
  @{
    Name = "test02_split_payload_pe.html"
    ExpectedScore = "20-25"
    ExpectedDetection = "YES"
    Description = "Split Payload: += Concatenation + PE"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 2: Split Payload</title></head>
<body>
<script>
var part1 = "$($PE_BASE64.Substring(0, 200))";
var part2 = "$($PE_BASE64.Substring(200, 200))";
var part3 = "$($PE_BASE64.Substring(400))";

var payload = "";
payload += part1;
payload += part2;
payload += part3;

var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'document.exe';
a.click();
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 3: Array.join() Method
  # ========================================================================
  @{
    Name = "test03_array_join_pe.html"
    ExpectedScore = "20-25"
    ExpectedDetection = "YES"
    Description = "Split Payload: Array.join() + PE"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 3: Array Join</title></head>
<body>
<script>
var parts = [
  "$($PE_BASE64.Substring(0, 200))",
  "$($PE_BASE64.Substring(200, 200))",
  "$($PE_BASE64.Substring(400))"
];

var payload = parts.join('');
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);

var link = document.createElement('a');
link.href = url;
link.download = 'report.exe';
link.click();
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 4: Obfuscation (Hex Variable Names + Array Index)
  # ========================================================================
  @{
    Name = "test04_obfuscated_pe.html"
    ExpectedScore = "25-30"
    ExpectedDetection = "YES"
    Description = "Polymorphic Obfuscation + PE"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 4: Obfuscated</title></head>
<body>
<script>
var _0x4a8b = ['atob', 'Blob', 'createObjectURL', 'createElement', 'a', 'href', 'download', 'click'];
var _0x2c9d = "$PE_BASE64";

var _0x1f3e = window[_0x4a8b[0]](_0x2c9d);
var _0x5b2a = new window[_0x4a8b[1]]([_0x1f3e], {type:'application/octet-stream'});
var _0x7d4c = URL[_0x4a8b[2]](_0x5b2a);

var _0x9e6b = document[_0x4a8b[3]](_0x4a8b[4]);
_0x9e6b[_0x4a8b[5]] = _0x7d4c;
_0x9e6b[_0x4a8b[6]] = 'update.exe';
_0x9e6b[_0x4a8b[7]]();
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 5: ZIP Archive
  # ========================================================================
  @{
    Name = "test05_zip_smuggling.html"
    ExpectedScore = "12-18"
    ExpectedDetection = "YES"
    Description = "ZIP Archive Smuggling"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 5: ZIP Smuggling</title></head>
<body>
<script>
var zipData = "$ZIP_BASE64";
var decoded = atob(zipData);
var blob = new Blob([decoded], {type: 'application/zip'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'files.zip';
a.click();
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 6: WASM Module
  # ========================================================================
  @{
    Name = "test06_wasm_smuggling.html"
    ExpectedScore = "15-20"
    ExpectedDetection = "YES"
    Description = "WebAssembly Module"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 6: WASM</title></head>
<body>
<script>
var wasmData = "$WASM_BASE64";
var decoded = atob(wasmData);
var blob = new Blob([decoded], {type: 'application/wasm'});
var url = URL.createObjectURL(blob);

// WebAssembly API Trigger
if (typeof WebAssembly !== 'undefined') {
  fetch(url).then(r => r.arrayBuffer()).then(bytes => {
    WebAssembly.instantiate(bytes).catch(e => console.log('wasm error'));
  });
}
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 7: PDF Smuggling
  # ========================================================================
  @{
    Name = "test07_pdf_smuggling.html"
    ExpectedScore = "4-8"
    ExpectedDetection = "YES"
    Description = "PDF Document Smuggling"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 7: PDF</title></head>
<body>
<script>
var pdfData = "$PDF_BASE64";
var decoded = atob(pdfData);
var blob = new Blob([decoded], {type: 'application/pdf'});
var url = URL.createObjectURL(blob);
window.open(url);
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 8: Web Worker + PE
  # ========================================================================
  @{
    Name = "test08_webworker_pe.html"
    ExpectedScore = "18-24"
    ExpectedDetection = "YES"
    Description = "Web Worker + PE Payload"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 8: Web Worker</title></head>
<body>
<script>
var workerCode = ``
  self.onmessage = function(e) {
    var decoded = atob(e.data.payload);
    self.postMessage({decoded: decoded});
  }
``;

var blob = new Blob([workerCode], {type: 'application/javascript'});
var workerUrl = URL.createObjectURL(blob);
var worker = new Worker(workerUrl);

worker.onmessage = function(e) {
  var resultBlob = new Blob([e.data.decoded], {type: 'application/octet-stream'});
  var url = URL.createObjectURL(resultBlob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'worker_payload.exe';
  a.click();
};

worker.postMessage({payload: "$PE_BASE64"});
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 9: setTimeout Delayed Execution
  # ========================================================================
  @{
    Name = "test09_delayed_execution_pe.html"
    ExpectedScore = "20-26"
    ExpectedDetection = "YES"
    Description = "Delayed Execution + PE"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 9: Delayed Execution</title></head>
<body>
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
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 10: ms-appinstaller Schema (CRITICAL!)
  # ========================================================================
  @{
    Name = "test10_appinstaller_schema.html"
    ExpectedScore = "8-12"
    ExpectedDetection = "YES"
    Description = "ms-appinstaller URI Schema"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 10: AppInstaller</title></head>
<body>
<script>
var schema = "ms-appinstaller:?source=https://example.com/malware.appinstaller";
console.log(schema);

// AppInstaller XML in Blob
var xml = '<?xml version="1.0" encoding="UTF-8"?>';
xml += '<AppInstaller Uri="https://example.com/app.msix" Version="1.0.0.0" xmlns="http://schemas.microsoft.com/appx/appinstaller/2017/2">';
xml += '<MainPackage Name="App" Publisher="CN=Test" Version="1.0.0.0" Uri="https://example.com/app.msix" />';
xml += '</AppInstaller>';

var xmlBlob = new Blob([xml], {type: 'application/xml'});
var xmlUrl = URL.createObjectURL(xmlBlob);
console.log(xmlUrl);
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 11: Iframe + data: URI
  # ========================================================================
  @{
    Name = "test11_iframe_data_uri.html"
    ExpectedScore = "4-8"
    ExpectedDetection = "MAYBE"
    Description = "Iframe with data: URI"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 11: Iframe</title></head>
<body>
<iframe id="hidden" style="display:none"></iframe>
<script>
var frame = document.getElementById('hidden');
frame.src = 'data:text/html;base64,' + "$($PE_BASE64.Substring(0,200))";
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 12: External Script Loading
  # ========================================================================
  @{
    Name = "test12_external_scripts.html"
    ExpectedScore = "1-3"
    ExpectedDetection = "MAYBE"
    Description = "External Script from Unsafe Domain"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 12: External Scripts</title></head>
<body>
<script src="https://malicious-cdn.example/stage1.js"></script>
<script src="https://evil-tracker.example/beacon.js"></script>
<script>
var payload = "$($PE_BASE64.Substring(0,200))";
var decoded = atob(payload);
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 13: Fetch API + Blob
  # ========================================================================
  @{
    Name = "test13_fetch_api_pe.html"
    ExpectedScore = "16-22"
    ExpectedDetection = "YES"
    Description = "Fetch API + PE Smuggling"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 13: Fetch API</title></head>
<body>
<script>
var payload = "$PE_BASE64";
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});

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
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 14: Canvas QR Code Lure
  # ========================================================================
  @{
    Name = "test14_qr_canvas_pe.html"
    ExpectedScore = "17-23"
    ExpectedDetection = "YES"
    Description = "QR Canvas + PE Smuggling"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 14: QR Canvas</title></head>
<body>
<canvas id="qr" width="300" height="300"></canvas>
<script>
var canvas = document.getElementById('qr');
var ctx = canvas.getContext('2d');

// Simple QR pattern
ctx.fillStyle = 'black';
for (var i=0; i<10; i++) {
  for (var j=0; j<10; j++) {
    if ((i+j) % 2 === 0) {
      ctx.fillRect(i*30, j*30, 28, 28);
    }
  }
}

canvas.addEventListener('click', function() {
  var payload = "$PE_BASE64";
  var decoded = atob(payload);
  var blob = new Blob([decoded], {type: 'application/octet-stream'});
  var url = URL.createObjectURL(blob);
  window.location = url;
});
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 15: ServiceWorker Registration
  # ========================================================================
  @{
    Name = "test15_serviceworker_pe.html"
    ExpectedScore = "18-24"
    ExpectedDetection = "YES"
    Description = "ServiceWorker + PE"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 15: ServiceWorker</title></head>
<body>
<script>
if ('serviceWorker' in navigator) {
  var swCode = ``
    self.addEventListener('fetch', function(event) {
      if (event.request.url.includes('payload')) {
        var payload = "$($PE_BASE64.Substring(0,400))";
        var decoded = atob(payload);
        event.respondWith(new Response(decoded));
      }
    });
  ``;
  
  var blob = new Blob([swCode], {type: 'application/javascript'});
  var url = URL.createObjectURL(blob);
  
  navigator.serviceWorker.register(url).then(function(reg) {
    console.log('SW registered');
  });
}

// Also trigger normal smuggling
var payload = "$PE_BASE64";
var decoded = atob(payload);
var blob = new Blob([decoded], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 16: WebCrypto + PE
  # ========================================================================
  @{
    Name = "test16_webcrypto_pe.html"
    ExpectedScore = "17-23"
    ExpectedDetection = "YES"
    Description = "WebCrypto + PE (simulated encryption)"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 16: WebCrypto</title></head>
<body>
<script>
var payload = "$PE_BASE64";

async function run() {
  var key = await crypto.subtle.generateKey(
    {name: 'AES-CBC', length: 256},
    true,
    ['encrypt', 'decrypt']
  );
  
  var decoded = atob(payload);
  var blob = new Blob([decoded], {type: 'application/octet-stream'});
  var url = URL.createObjectURL(blob);
  
  var a = document.createElement('a');
  a.href = url;
  a.download = 'encrypted.exe';
  a.click();
}

run();
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 17: Uint8Array Direct (CRITICAL!)
  # ========================================================================
  @{
    Name = "test17_uint8array_pe.html"
    ExpectedScore = "20-28"
    ExpectedDetection = "YES"
    Description = "Uint8Array with PE bytes"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 17: Uint8Array</title></head>
<body>
<script>
// PE Header als Uint8Array (MZ + e_lfanew + PE Signature)
var peBytes = new Uint8Array([
  0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
  0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
  0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
  // ... (simplified, normally more bytes)
  0x50, 0x45, 0x00, 0x00, 0x4C, 0x01
]);

var blob = new Blob([peBytes], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'uint8.exe';
a.click();
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 18: ALL-IN-ONE (Maximum Triggers!)
  # ========================================================================
  @{
    Name = "test18_all_in_one_MAXIMUM.html"
    ExpectedScore = "35-45"
    ExpectedDetection = "YES"
    Description = "Maximum Triggers: Alle Techniken kombiniert"
    Content = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Test 18: ALL-IN-ONE</title>
</head>
<body>
<canvas id="qr"></canvas>
<iframe id="hidden" style="display:none"></iframe>

<script>
// 1. Obfuscation
var _0x1a2b = ['atob', 'Blob', 'createObjectURL', 'Worker'];

// 2. Split Payload
var p1 = "$($PE_BASE64.Substring(0, 250))";
var p2 = "$($PE_BASE64.Substring(250, 250))";
var p3 = "$($PE_BASE64.Substring(500))";

// 3. Array Join
var parts = [p1, p2, p3];
var payload = parts.join('');

// 4. Delayed Execution
setTimeout(function() {
  // 5. Canvas API
  var canvas = document.getElementById('qr');
  var ctx = canvas.getContext('2d');
  ctx.fillRect(0, 0, 100, 100);
  
  // 6. Array Index API
  var decode = window[_0x1a2b[0]];
  var decoded = decode(payload);
  
  // 7. Blob + createObjectURL
  var blob = new window[_0x1a2b[1]]([decoded], {type: 'application/octet-stream'});
  var url = URL[_0x1a2b[2]](blob);
  
  // 8. Web Worker
  var workerCode = 'self.postMessage("ready")';
  var workerBlob = new Blob([workerCode], {type: 'application/javascript'});
  var workerUrl = URL.createObjectURL(workerBlob);
  var worker = new Worker(workerUrl);
  
  // 9. Fetch API
  fetch(url).then(r => r.blob()).then(b => {
    var finalUrl = URL.createObjectURL(b);
    
    // 10. Download
    var a = document.createElement('a');
    a.href = finalUrl;
    a.download = 'all_in_one.exe';
    a.click();
  });
  
  // 11. Iframe data: URI
  document.getElementById('hidden').src = 'data:text/html;base64,' + payload.substring(0, 100);
  
  // 12. External Script (simulated)
  var extScript = document.createElement('script');
  extScript.src = 'https://malicious.example/stage2.js';
  
}, 100);

// 13. ServiceWorker (if supported)
if ('serviceWorker' in navigator) {
  var swCode = 'self.addEventListener("install", e => e.waitUntil(self.skipWaiting()))';
  var swBlob = new Blob([swCode], {type: 'application/javascript'});
  var swUrl = URL.createObjectURL(swBlob);
  navigator.serviceWorker.register(swUrl);
}

// 14. WebCrypto
if (crypto && crypto.subtle) {
  crypto.subtle.generateKey({name: 'AES-CBC', length: 256}, true, ['encrypt']);
}
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 19: Negative Test (Should NOT trigger)
  # ========================================================================
  @{
    Name = "test19_NEGATIVE_legitimate.html"
    ExpectedScore = "0-2"
    ExpectedDetection = "NO"
    Description = "Legitimate use: Normal website (should NOT trigger)"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 19: Legitimate Site</title></head>
<body>
<h1>Welcome</h1>
<p>This is a normal website.</p>
<img src="logo.png">
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
<script>
// Normal tracking
var userId = btoa("user123");
console.log("User:", userId);

// Normal image handling
var canvas = document.createElement('canvas');
var ctx = canvas.getContext('2d');
ctx.fillText("Hello", 10, 10);
</script>
</body>
</html>
"@
  }
  
  # ========================================================================
  # TEST 20: Newsletter Test (Should NOT trigger due to heur_mul)
  # ========================================================================
  @{
    Name = "test20_NEGATIVE_newsletter.html"
    ExpectedScore = "0-1"
    ExpectedDetection = "NO"
    Description = "Newsletter with tracking (should be reduced by heur_mul)"
    Content = @"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 20: Newsletter</title></head>
<body>
<p>Unsubscribe: <a href="https://unsubscribe.example.com">Click here</a></p>
<img src="tracking.png" style="display:none">
<script>
// Newsletter tracking
var trackingData = btoa("campaign=summer2025");
fetch('https://tracking.example.com/log?data=' + trackingData);
</script>
</body>
</html>
"@
  }
)

# ============================================================================
# CREATE FILES
# ============================================================================

$successCount = 0
$errorCount = 0
$summary = @()

foreach ($file in $testFiles) {
  try {
    $path = Join-Path (Get-Location) $file.Name

    if (Test-Path -LiteralPath $path) {
      if (-not $Force) {
        Write-Host "⏭  Existiert bereits: $($file.Name) (nutze -Force)" -ForegroundColor Yellow
        continue
      }
    }

    [System.IO.File]::WriteAllText(
      $path,
      $file.Content,
      [System.Text.UTF8Encoding]::new($false)
    )

    Write-Host "   $($file.Name)" -ForegroundColor Green
    Write-Host "   Expected Score: $($file.ExpectedScore) | Detection: $($file.ExpectedDetection)" -ForegroundColor Gray
    Write-Host "   $($file.Description)" -ForegroundColor DarkGray
    
    $summary += [PSCustomObject]@{
      File = $file.Name
      ExpectedScore = $file.ExpectedScore
      Detection = $file.ExpectedDetection
      Description = $file.Description
    }
    
    $successCount++
  }
  catch {
    Write-Host "Fehler bei $($file.Name): $($_.Exception.Message)" -ForegroundColor Red
    $errorCount++
  }
}


Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    ABGESCHLOSSEN                           ║" -ForegroundColor Cyan
Write-Host "╠════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Ordner: $testFolder" -ForegroundColor White
Write-Host "║  Erfolgreich: $successCount von $($testFiles.Count)" -ForegroundColor Green
if ($errorCount -gt 0) {
  Write-Host "║  Fehler: $errorCount" -ForegroundColor Red
}
Write-Host "║" -ForegroundColor Cyan
Write-Host "║  Erwartete Detection-Rate: 90% (18/20 Tests)" -ForegroundColor Yellow
Write-Host "║" -ForegroundColor Cyan
Write-Host "║  Pfad: $((Get-Location).Path)\$testFolder" -ForegroundColor Gray
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host ""
