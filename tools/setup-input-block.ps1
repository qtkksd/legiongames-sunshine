#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies LegionGames input blocking prerequisites.
    
.DESCRIPTION
    This script verifies devcon.exe is available for the Sunshine API endpoints.
    Device detection is done automatically via GET /api/input-block/status.
    
    Run automatically by NSIS installer or manually post-install.
    
.NOTES
    File: setup-input-block.ps1
    Version: 3.0.0
    Author: LegionGames
    Requires: Windows 10/11, Administrator rights, DevCon.exe in tools\ directory
#>

[CmdletBinding()]
param()

$DevConPath = "$PSScriptRoot\devcon.exe"

# Verify DevCon exists
if (-not (Test-Path $DevConPath)) {
    Write-Error "DevCon.exe not found at: $DevConPath"
    Write-Host "Please place devcon.exe in: $PSScriptRoot" -ForegroundColor Yellow
    exit 1
}

# Quick test
$testResult = & $DevConPath find "*HID*" 2>&1 | Out-String
if ($LASTEXITCODE -eq 0 -or $testResult -match "matching device") {
    Write-Host "DevCon.exe verified. Input blocking API is ready." -ForegroundColor Green
    Write-Host ""
    Write-Host "API Endpoints:" -ForegroundColor Cyan
    Write-Host "  GET  /api/input-block/status   - Detect keyboard/mouse devices" -ForegroundColor White
    Write-Host "  POST /api/input-block/block    - Block input (with vid_patterns from status)" -ForegroundColor White
    Write-Host "  POST /api/input-block/unblock  - Unblock input" -ForegroundColor White
    Write-Host ""
    Write-Host "Example flow from Django:" -ForegroundColor Cyan
    Write-Host "  1. GET /api/input-block/status -> get device VID patterns" -ForegroundColor White
    Write-Host "  2. POST /api/input-block/block with {vid_patterns: [...]}" -ForegroundColor White
    Write-Host "  3. POST /api/input-block/unblock to restore input" -ForegroundColor White
    exit 0
} else {
    Write-Error "DevCon.exe test failed"
    exit 1
}
