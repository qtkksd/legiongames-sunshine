<#
.SYNOPSIS
    Installs the Steam Streaming Microphone virtual audio driver, if not already present.

.DESCRIPTION
    Idempotent installer for the "Steam Streaming Microphone" device used by
    client-to-host microphone passthrough. It checks the PnP device store first;
    if the device is already registered (even if disabled or unplugged) it does
    nothing. Otherwise it installs the driver package bundled next to this
    script (x64\). The install is self-contained and never consults a local
    Steam installation.

    Must be run as Administrator (or as SYSTEM). No reboot is required, but the
    virtual device may take a few seconds to appear in Sound settings.

.PARAMETER Force
    Re-run the install even if the device is already present.

.PARAMETER InfPath
    Optional explicit path to SteamStreamingMicrophone.inf. Defaults to the
    package bundled in x64\ next to this script.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install_steam_microphone.ps1
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [string]$InfPath
)

$ErrorActionPreference = 'Stop'
$Arch = 'x64'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SteamMicInstalled {
    # Present in the PnP device store (true even if disabled/unplugged).
    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\SteamStreamingMicrophone') {
        return $true
    }
    # Fallback: enumerate MEDIA devices.
    $dev = Get-PnpDevice -Class Media -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -like 'ROOT\SteamStreamingMicrophone*' }
    return [bool]$dev
}

function Resolve-SteamMicInf {
    if ($InfPath) {
        return (Resolve-Path -LiteralPath $InfPath).Path
    }
    # Driver package bundled next to this script.
    $bundled = Join-Path $Here "$Arch\SteamStreamingMicrophone.inf"
    if (Test-Path $bundled) {
        return $bundled
    }
    return $null
}

if (-not (Test-Administrator)) {
    Write-Error '[fail] Administrator privileges are required.'
    exit 1
}

if ((Test-SteamMicInstalled) -and (-not $Force)) {
    Write-Host '[skip] Steam Streaming Microphone is already installed.'
    exit 0
}

$inf = Resolve-SteamMicInf
if (-not $inf) {
    Write-Error "[fail] SteamStreamingMicrophone.inf not found. Expected the bundled driver at '$Here\$Arch'."
    exit 2
}

Write-Host "[info] Installing Steam Streaming Microphone from: $inf"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class NewDevApi {
    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool DiInstallDriverW(IntPtr hwndParent, string driverPath, uint flags, out bool needReboot);
}
"@

[bool]$needReboot = $false
if (-not [NewDevApi]::DiInstallDriverW([IntPtr]::Zero, $inf, 0, [ref]$needReboot)) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Error "[fail] DiInstallDriverW failed (Win32 error $err)."
    exit 3
}

# Give the audio subsystem a moment, then enable the device if it came up disabled.
Start-Sleep -Seconds 5
Get-PnpDevice -Class Media -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -like 'ROOT\SteamStreamingMicrophone*' -and $_.Status -ne 'OK' } |
    ForEach-Object { pnputil /enable-device "$($_.InstanceId)" | Out-Null }

if (Test-SteamMicInstalled) {
    Write-Host '[ok] Steam Streaming Microphone installed and enabled.'
    exit 0
}

Write-Error '[fail] Install reported success but the device was not found. Check setupapi.dev.log.'
exit 4
