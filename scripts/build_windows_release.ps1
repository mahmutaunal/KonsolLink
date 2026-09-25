#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$GatewayBinary = "$PSScriptRoot\..\target\m4\windows\go-pcap2socks.exe",
    [string]$GatewaySource = "$PSScriptRoot\..\target\m4\go-pcap2socks",
    [string]$CertificateSha1 = $env:WINDOWS_CERTIFICATE_SHA1,
    [string]$SignTool = $env:SIGNTOOL_PATH
)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path "$PSScriptRoot\..").Path
$Out = Join-Path $Root 'target\release-packages\windows'
if (Test-Path -LiteralPath $Out) { Remove-Item -LiteralPath $Out -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Unsigned = $env:ALLOW_UNSIGNED_RC -eq '1'
if (($CertificateSha1 -eq '' -or $SignTool -eq '') -and -not $Unsigned) {
    throw 'Authenticode certificate thumbprint and signtool are required for a stable release.'
}
$Suffix = if ($Unsigned) { '-rc-unsigned' } else { '' }

$TauriConfigPath = Join-Path $Root 'apps\desktop\src-tauri\tauri.conf.json'
$TauriConfigOriginal = Get-Content -LiteralPath $TauriConfigPath -Raw
if (-not $Unsigned) {
    $TauriConfig = $TauriConfigOriginal | ConvertFrom-Json
    if ($null -eq $TauriConfig.bundle.windows) {
        $TauriConfig.bundle | Add-Member -NotePropertyName windows -NotePropertyValue ([pscustomobject]@{})
    }
    $TauriConfig.bundle.windows | Add-Member -Force -NotePropertyName certificateThumbprint -NotePropertyValue $CertificateSha1
    $TauriConfig.bundle.windows | Add-Member -Force -NotePropertyName digestAlgorithm -NotePropertyValue 'sha256'
    $TauriConfig.bundle.windows | Add-Member -Force -NotePropertyName timestampUrl -NotePropertyValue 'http://timestamp.digicert.com'
    $TauriConfig | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $TauriConfigPath -Encoding utf8NoBOM
}
Push-Location (Join-Path $Root 'apps\desktop')
try {
    npm ci
    npm run build
    npm run tauri -- build --bundles nsis --ci -- --locked
} finally {
    Pop-Location
    Set-Content -LiteralPath $TauriConfigPath -Value $TauriConfigOriginal -Encoding utf8NoBOM -NoNewline
}

$NsisCandidates = @(Get-ChildItem -Path (Join-Path $Root 'target\release\bundle\nsis') -Filter '*.exe')
if ($NsisCandidates.Count -ne 1) { throw "Expected exactly one Tauri NSIS installer; found $($NsisCandidates.Count)." }
$Nsis = $NsisCandidates[0]
if (-not $Unsigned) {
    & $SignTool sign /fd SHA256 /sha1 $CertificateSha1 /tr 'http://timestamp.digicert.com' /td SHA256 $Nsis.FullName
    if ($LASTEXITCODE -ne 0) { throw 'NSIS Authenticode signing failed.' }
    & $SignTool verify /pa /all $Nsis.FullName
    if ($LASTEXITCODE -ne 0) { throw 'NSIS Authenticode verification failed.' }
}

& (Join-Path $Root 'scripts\build_windows_package.ps1') -GatewayBinary $GatewayBinary -GatewaySource $GatewaySource -OutputRoot (Join-Path $Root 'target\m4') -SignTool $(if ($Unsigned) { '' } else { $SignTool }) -CertificateSha1 $(if ($Unsigned) { '' } else { $CertificateSha1 })
$RuntimeZip = Join-Path $Root "target\m4\KonsolLink-1.0.0$Suffix-windows-x64.zip"
Copy-Item $Nsis.FullName (Join-Path $Out "KonsolLink-1.0.0$Suffix-windows-x64-setup.exe") -Force
Copy-Item $RuntimeZip $Out -Force
Copy-Item (Join-Path $Root 'target\release-metadata\konsollink-1.0.0.cdx.json') $Out -Force
Copy-Item (Join-Path $Root 'target\release-metadata\LICENSES.md') $Out -Force
Copy-Item (Join-Path $Root 'THIRD_PARTY_NOTICES.md') $Out -Force
python (Join-Path $Root 'scripts\make_release_checksums.py') create $Out
python (Join-Path $Root 'scripts\make_release_checksums.py') verify $Out
