#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$GatewayBinary = "$PSScriptRoot\..\target\m4\windows\go-pcap2socks.exe",
    [string]$GatewaySource = "$PSScriptRoot\..\target\m4\go-pcap2socks",
    [string]$GoodbyeDpiArchive = "$env:TEMP\goodbyedpi-0.2.2.zip",
    [string]$OutputRoot = "$PSScriptRoot\..\target\m4",
    [string]$SignTool = '',
    [string]$CertificateSha1 = ''
)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path "$PSScriptRoot\..").Path
$HasSignTool = $SignTool -ne ''
$HasCertificate = $CertificateSha1 -ne ''
if ($HasSignTool -xor $HasCertificate) { throw 'SignTool and CertificateSha1 must be supplied together.' }
$Unsigned = -not $HasSignTool
if ($Unsigned -and $env:ALLOW_UNSIGNED_RC -ne '1') {
    throw 'Authenticode identity is required for a stable Windows package.'
}
$Suffix = if ($Unsigned) { '-rc-unsigned' } else { '' }
$Package = Join-Path $OutputRoot "KonsolLink-1.0.0$Suffix-windows-x64"
$ArchiveHash = '00a2f8b99cd817f8c7fc4c449033015f039d18af213de78cb66bf202277c0628'

if (-not (Test-Path -LiteralPath $GatewayBinary -PathType Leaf)) { throw "Missing patched gateway: $GatewayBinary" }
if (-not (Test-Path -LiteralPath (Join-Path $GatewaySource '.git') -PathType Container)) { throw "Missing pinned gateway source: $GatewaySource" }
$GatewayCommit = (git -C $GatewaySource rev-parse HEAD).Trim()
if ($GatewayCommit -ne 'ec40773869e835bd09cb134e638e4e3333d89e0c') { throw 'Gateway source commit differs from the reviewed pin.' }
if (-not (Test-Path -LiteralPath $GoodbyeDpiArchive -PathType Leaf)) {
    throw "Missing local GoodbyeDPI archive: $GoodbyeDpiArchive"
}
if ((Get-FileHash -Algorithm SHA256 $GoodbyeDpiArchive).Hash.ToLowerInvariant() -ne $ArchiveHash) {
    throw 'GoodbyeDPI archive SHA-256 mismatch.'
}

$ServiceDir = Join-Path $Root 'platform\windows\service'
Push-Location $ServiceDir
$PreviousGoProxy = $env:GOPROXY
$PreviousGoSumDb = $env:GOSUMDB
try {
    $env:GOPROXY = 'off'; $env:GOSUMDB = 'off'
    $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Windows service tests failed or local Go dependencies are missing.' }
    New-Item -ItemType Directory -Force -Path (Join-Path $Root 'target\m4\windows') | Out-Null
    go build -trimpath -ldflags='-s -w' -o (Join-Path $Root 'target\m4\windows\KonsolLinkService.exe') .
    if ($LASTEXITCODE -ne 0) { throw 'Windows service build failed or local Go dependencies are missing.' }
} finally {
    $env:GOPROXY = $PreviousGoProxy; $env:GOSUMDB = $PreviousGoSumDb
    Pop-Location
}

$Extract = Join-Path $env:TEMP 'konsollink-goodbyedpi-0.2.2'
if (Test-Path $Extract) { Remove-Item -Recurse -Force $Extract }
Expand-Archive -LiteralPath $GoodbyeDpiArchive -DestinationPath $Extract
if (Test-Path $Package) { Remove-Item -Recurse -Force $Package }
New-Item -ItemType Directory -Force -Path $Package | Out-Null

$Gdpi = Join-Path $Extract 'goodbyedpi-0.2.2\x86_64'
Copy-Item $GatewayBinary (Join-Path $Package 'go-pcap2socks.exe')
Copy-Item (Join-Path $Root 'target\m4\windows\KonsolLinkService.exe') $Package
Copy-Item (Join-Path $Gdpi 'goodbyedpi.exe') $Package
Copy-Item (Join-Path $Gdpi 'WinDivert.dll') $Package
Copy-Item (Join-Path $Gdpi 'WinDivert64.sys') $Package
Copy-Item (Join-Path $Root 'services\discord\hosts.txt') (Join-Path $Package 'discord-hosts.txt')
Copy-Item (Join-Path $Root 'engines\gateway-windows.json') $Package
Copy-Item (Join-Path $Root 'platform\windows\install.ps1') $Package
Copy-Item (Join-Path $Extract 'goodbyedpi-0.2.2\licenses') $Package -Recurse
Copy-Item (Join-Path $Root 'engines\go-pcap2socks-ec407738-konsollink.patch') $Package
Copy-Item (Join-Path $Root 'engines\go-pcap2socks-LICENSE') $Package
Copy-Item (Join-Path $Root 'THIRD_PARTY_NOTICES.md') $Package
$GatewaySourceArchive = Join-Path $Package 'go-pcap2socks-ec407738-source.zip'
git -C $GatewaySource archive --format=zip "--output=$GatewaySourceArchive" HEAD
if ($LASTEXITCODE -ne 0) { throw 'Could not archive corresponding go-pcap2socks source.' }

if (-not $Unsigned) {
    foreach ($name in @('KonsolLinkService.exe', 'go-pcap2socks.exe')) {
        & $SignTool sign /fd SHA256 /sha1 $CertificateSha1 /tr 'http://timestamp.digicert.com' /td SHA256 (Join-Path $Package $name)
        if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed: $name" }
        & $SignTool verify /pa /all (Join-Path $Package $name)
        if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed: $name" }
    }
}

$files = @{}
foreach ($name in @('WinDivert.dll','WinDivert64.sys','discord-hosts.txt','gateway-windows.json','go-pcap2socks.exe','goodbyedpi.exe')) {
    $files[$name] = (Get-FileHash -Algorithm SHA256 (Join-Path $Package $name)).Hash.ToLowerInvariant()
}
@{ schema = 1; files = $files } | ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8NoBOM (Join-Path $Package 'runtime-manifest.json')
@{
    schema = 1
    service_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $Package 'KonsolLinkService.exe')).Hash.ToLowerInvariant()
} | ConvertTo-Json | Set-Content -Encoding utf8NoBOM (Join-Path $Package 'installer-manifest.json')

$Expected = @{
    'goodbyedpi.exe'='331ac6c1d22ba5a0a217f3f27d0d823051869cafc8b8ef7f2002fa2accebc74e';
    'WinDivert.dll'='a97859785a2df1d4462e7d48d33ccbd89fedd40dac4970f4afd89e63f59ee1ec';
    'WinDivert64.sys'='53ab28ec00be6e6f8aefa9ee76fc2735e94d7f3f9dbc06eb2b7ac8cd3084a6af'
}
foreach ($name in $Expected.Keys) { if ($files[$name] -ne $Expected[$name]) { throw "Pinned artifact mismatch: $name" } }
$Zip = "$Package.zip"
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path "$Package\*" -DestinationPath $Zip
Get-FileHash -Algorithm SHA256 $Zip
