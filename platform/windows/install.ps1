#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall')]
    [string]$Action = 'Install',
    [string]$PackageRoot = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'KonsolLink'
$InstallRoot = Join-Path $env:ProgramFiles 'KonsolLink'
$RuntimeFiles = @(
    'KonsolLinkService.exe', 'go-pcap2socks.exe', 'goodbyedpi.exe',
    'WinDivert.dll', 'WinDivert64.sys', 'discord-hosts.txt',
    'gateway-windows.json', 'runtime-manifest.json', 'installer-manifest.json'
)

function Invoke-Sc([string[]]$Arguments) {
    $process = Start-Process -FilePath "$env:SystemRoot\System32\sc.exe" -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) { throw "sc.exe failed ($($process.ExitCode)): $($Arguments -join ' ')" }
}

function Stop-KonsolLinkService {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -ErrorAction Stop
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    return $null -ne $service
}

if ($Action -eq 'Uninstall') {
    if (Stop-KonsolLinkService) { Invoke-Sc -Arguments @('delete', $ServiceName) }
    foreach ($name in $RuntimeFiles) {
        $path = Join-Path $InstallRoot $name
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
    exit 0
}

# Npcap owns system capture. Never silently install a network driver.
$Npcap = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Npcap' -ErrorAction SilentlyContinue
if ($null -eq $Npcap) { throw 'Npcap is required. Install it with WinPcap API-compatible Mode enabled.' }
if (-not (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll" -PathType Leaf)) {
    throw 'The protected Npcap capture DLL is missing.'
}

foreach ($name in $RuntimeFiles) {
    $path = Join-Path $PackageRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Package file is missing: $name" }
}

$manifest = Get-Content -LiteralPath (Join-Path $PackageRoot 'runtime-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1 -or $manifest.health_schema -ne 1) { throw 'Unsupported runtime manifest.' }
$installerManifest = Get-Content -LiteralPath (Join-Path $PackageRoot 'installer-manifest.json') -Raw | ConvertFrom-Json
if ($installerManifest.schema -ne 1 -or $installerManifest.service_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Unsupported installer manifest.'
}
$serviceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PackageRoot 'KonsolLinkService.exe')).Hash.ToLowerInvariant()
if ($serviceHash -ne $installerManifest.service_sha256) { throw 'SHA-256 mismatch: KonsolLinkService.exe' }
$HashedFiles = $RuntimeFiles | Where-Object { $_ -notin @('KonsolLinkService.exe', 'runtime-manifest.json', 'installer-manifest.json') }
foreach ($name in $HashedFiles) {
    $expected = $manifest.files.$name
    if ($expected -notmatch '^[0-9a-f]{64}$') { throw "Missing manifest hash: $name" }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PackageRoot $name)).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "SHA-256 mismatch: $name" }
}

$ExistingService = Stop-KonsolLinkService
$BackupRoot = Join-Path $env:TEMP ([Guid]::NewGuid().ToString('N'))
$CreatedService = $false
New-Item -ItemType Directory -Path $BackupRoot | Out-Null
try {
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    foreach ($name in $RuntimeFiles) {
        $installed = Join-Path $InstallRoot $name
        if (Test-Path -LiteralPath $installed -PathType Leaf) {
            Copy-Item -LiteralPath $installed -Destination $BackupRoot -Force
        }
    }
    foreach ($name in $RuntimeFiles) {
        Copy-Item -LiteralPath (Join-Path $PackageRoot $name) -Destination $InstallRoot -Force
    }

    # The desktop executable must remain readable; runtime files stay restricted.
    foreach ($name in $RuntimeFiles) {
        & "$env:SystemRoot\System32\icacls.exe" (Join-Path $InstallRoot $name) '/inheritance:r' '/grant:r' 'SYSTEM:F' 'BUILTIN\Administrators:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not secure runtime file: $name" }
    }
    & "$env:SystemRoot\System32\icacls.exe" $InstallRoot '/inheritance:r' '/grant:r' 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'BUILTIN\Users:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not secure the KonsolLink installation directory.' }
    $binary = '"' + (Join-Path $InstallRoot 'KonsolLinkService.exe') + '"'
    if (-not $ExistingService) {
        Invoke-Sc -Arguments @('create', $ServiceName, "binPath= $binary", 'start= demand', 'DisplayName= KonsolLink')
        $CreatedService = $true
    }
    Invoke-Sc -Arguments @('failure', $ServiceName, 'reset= 86400', 'actions= restart/3000/restart/10000//')
    Invoke-Sc -Arguments @('failureflag', $ServiceName, '1')
    if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {
        New-EventLog -LogName Application -Source $ServiceName
    }
    # Authenticated desktop users may query/start/stop this one service; they cannot reconfigure it.
    Invoke-Sc -Arguments @('sdset', $ServiceName, 'D:(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)')
    if ($ExistingService) {
        Invoke-Sc -Arguments @('config', $ServiceName, "binPath= $binary", 'start= demand', 'DisplayName= KonsolLink')
    }
} catch {
    if ($CreatedService) { Invoke-Sc -Arguments @('delete', $ServiceName) }
    foreach ($name in $RuntimeFiles) {
        $installed = Join-Path $InstallRoot $name
        $backup = Join-Path $BackupRoot $name
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            Copy-Item -LiteralPath $backup -Destination $installed -Force
        } elseif (Test-Path -LiteralPath $installed -PathType Leaf) {
            Remove-Item -LiteralPath $installed -Force
        }
    }
    throw
} finally {
    Remove-Item -LiteralPath $BackupRoot -Recurse -Force
}
Write-Host 'KonsolLink Windows service installed. No network setting was changed.'
