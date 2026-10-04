<#
.SYNOPSIS
  Post-update health supervisor for LegionGames Sunshine.

.DESCRIPTION
  Launched as SYSTEM by the one-shot "SunshineUpdateVerify" scheduled task that the
  /api/upgrade pre-flight arms just before running the installer. It outlives the
  SunshineService stop/delete/recreate and:

    1. Polls the local /api/health endpoint until the new build reports the expected
       commit (to_commit) three times in a row, or the timeout elapses.
    2. On success: records phase=success.
    3. On failure: stops the service, restores the pre-update program files from the
       rollback backup, starts the service, and records phase=rolled_back.

  It is one-shot: it writes the outcome into upgrade_state.json and removes its task.

.NOTES
  Must run elevated (SYSTEM). Uses only built-in Windows components.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$State,

    [Parameter(Mandatory = $false)]
    [string]$Log,

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSec = 180,

    [Parameter(Mandatory = $false)]
    [int]$PollSec = 5,

    [Parameter(Mandatory = $false)]
    [int]$StableCount = 3
)

$ErrorActionPreference = 'Continue'

$ServiceName = 'SunshineService'
$TaskName = 'SunshineUpdateVerify'

if (-not $State) {
    $State = Join-Path $PSScriptRoot '..\config\upgrade_state.json'
}
if (-not $Log) {
    $Log = Join-Path (Split-Path -Parent $State) 'update-supervisor.log'
}

# Accept the self-signed Sunshine HTTPS certificate for the loopback health probe.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

function Write-Log {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    try { Add-Content -Path $Log -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

function Read-State {
    if (-not (Test-Path -LiteralPath $State)) { return $null }
    try { return (Get-Content -LiteralPath $State -Raw | ConvertFrom-Json) } catch { return $null }
}

function Write-State {
    param($StateObj)
    try {
        $json = $StateObj | ConvertTo-Json -Depth 5
        # Write without a BOM so the C++ side (nlohmann::json) can parse it.
        [System.IO.File]::WriteAllText($State, $json, (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        Write-Log "Failed to write state: $($_.Exception.Message)"
    }
}

function Test-Health {
    param([int]$Port, [string]$ExpectCommit)
    try {
        $r = Invoke-RestMethod -Uri "https://127.0.0.1:$Port/api/health" -TimeoutSec 5 -ErrorAction Stop
        if ($r.status -ne 'ok') { return $false }
        if ($ExpectCommit -and ($r.commit -ne $ExpectCommit)) { return $false }
        return $true
    } catch {
        return $false
    }
}

function Test-PortUp {
    param([int]$Port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(3000, $false)) { $tcp.Close(); return $false }
        $tcp.EndConnect($iar)
        $tcp.Close()
        return $true
    } catch {
        return $false
    }
}

function Remove-Task {
    try { schtasks.exe /Delete /TN $TaskName /F | Out-Null } catch {}
}

function Prune-Backups {
    param([string]$RollbackRoot)
    try {
        if (-not (Test-Path -LiteralPath $RollbackRoot)) { return }
        Get-ChildItem -LiteralPath $RollbackRoot -Directory |
            Sort-Object LastWriteTime -Descending |
            Select-Object -Skip 2 |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    } catch {}
}

# --- main ---
Write-Log "Supervisor started (state=$State)"

$state = Read-State
if (-not $state) {
    Write-Log "No upgrade state found; nothing to do."
    Remove-Task
    exit 0
}

if ($state.phase -in @('success', 'rolled_back', 'rollback_failed')) {
    Write-Log "State already terminal (phase=$($state.phase)); nothing to do."
    Remove-Task
    exit 0
}

$port = [int]$state.port
$toCommit = [string]$state.to_commit
$fromCommit = [string]$state.from_commit
$installDir = [string]$state.install_dir
$backupDir = [string]$state.backup_dir

Write-Log "Verifying new build $toCommit on port $port (rollback -> $fromCommit)"

$state.phase = 'verifying'
Write-State $state

# 1. Wait for the new build to report the expected commit.
$stable = 0
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline) {
    if (Test-Health -Port $port -ExpectCommit $toCommit) {
        $stable++
        if ($stable -ge $StableCount) { break }
    } else {
        $stable = 0
    }
    Start-Sleep -Seconds $PollSec
}

if ($stable -ge $StableCount) {
    Write-Log "New build is online (commit $toCommit). Update successful."
    $state.phase = 'success'
    Write-State $state
    Prune-Backups -RollbackRoot (Split-Path -Parent $backupDir)
    Remove-Task
    exit 0
}

# 2. New build never came online: roll back to the previous version.
Write-Log "New build did not come online within ${TimeoutSec}s. Rolling back to $fromCommit."
$state.phase = 'rolling_back'
Write-State $state

try {
    Write-Log "Stopping $ServiceName"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    if ((Test-Path -LiteralPath $backupDir) -and $installDir) {
        Write-Log "Restoring program files from $backupDir"
        # /MIR mirrors the backup onto the install dir; config/ and rollback/ are excluded.
        robocopy.exe $backupDir $installDir /MIR /XD (Join-Path $installDir 'config') (Join-Path $installDir 'rollback') /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
        Write-Log "robocopy exit code: $LASTEXITCODE"
    } else {
        Write-Log "Backup directory missing; cannot restore program files."
    }

    Start-Sleep -Seconds 2
    Write-Log "Starting $ServiceName"
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
} catch {
    Write-Log "Rollback error: $($_.Exception.Message)"
}

# 3. Confirm the (restored) service is up. Older versions lack /api/health, so accept
#    a running service plus an open HTTPS port.
$ok = $false
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running' -and (Test-PortUp -Port $port)) {
        $ok = $true
        break
    }
    Start-Sleep -Seconds $PollSec
}

if ($ok) {
    Write-Log "Rollback complete; service is online on the previous version."
    $state.phase = 'rolled_back'
} else {
    Write-Log "Rollback attempted but the service did not come online."
    $state.phase = 'rollback_failed'
}
Write-State $state
Remove-Task
exit 0
