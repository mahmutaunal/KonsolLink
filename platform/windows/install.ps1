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

if ($Action -eq 'Uninstall') {
    & "$env:SystemRoot\System32\sc.exe" stop $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 2
    & "$env:SystemRoot\System32\sc.exe" delete $ServiceName 2>$null | Out-Null
    if (Test-Path -LiteralPath $InstallRoot) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force }
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
if ($manifest.schema -ne 1) { throw 'Unsupported runtime manifest.' }
$installerManifest = Get-Content -LiteralPath (Join-Path $PackageRoot 'installer-manifest.json') -Raw | ConvertFrom-Json
if ($installerManifest.schema -ne 1 -or $installerManifest.service_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Unsupported installer manifest.'
}
$serviceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PackageRoot 'KonsolLinkService.exe')).Hash.ToLowerInvariant()
if ($serviceHash -ne $installerManifest.service_sha256) { throw 'SHA-256 mismatch: KonsolLinkService.exe' }
$HashedFiles = $RuntimeFiles | Where-Object { $_ -notin @('KonsolLinkService.exe', 'runtime-manifest.json') }
foreach ($name in $HashedFiles) {
    $expected = $manifest.files.$name
    if ($expected -notmatch '^[0-9a-f]{64}$') { throw "Missing manifest hash: $name" }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PackageRoot $name)).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "SHA-256 mismatch: $name" }
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw 'KonsolLink service already exists. Uninstall it before replacing the runtime.'
}
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
foreach ($name in $RuntimeFiles) { Copy-Item -LiteralPath (Join-Path $PackageRoot $name) -Destination $InstallRoot -Force }

# Inheritance is removed: only SYSTEM and Administrators can replace runtime files.
& "$env:SystemRoot\System32\icacls.exe" $InstallRoot '/inheritance:r' '/grant:r' 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
$binary = '"' + (Join-Path $InstallRoot 'KonsolLinkService.exe') + '"'
Invoke-Sc -Arguments @('create', $ServiceName, "binPath= $binary", 'start= demand', 'DisplayName= KonsolLink')
Invoke-Sc -Arguments @('failure', $ServiceName, 'reset= 86400', 'actions= restart/3000/restart/10000//')
# Authenticated desktop users may query/start/stop this one service; they cannot reconfigure it.
Invoke-Sc -Arguments @('sdset', $ServiceName, 'D:(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)')
Write-Host 'KonsolLink Windows service installed. No network setting was changed.'
