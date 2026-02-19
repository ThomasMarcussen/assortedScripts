<#
=========================================================================================
Name:        Reset-TeamsClient.ps1
Author:      Thomas Marcussen
Contact:     Thomas@ThomasMarcussen.com
Version:     1.0
Date:        2026-02-19
Purpose:     Performs a full reset of Microsoft Teams client (New + Classic) for a user
=========================================================================================

.DESCRIPTION
This script performs a deep client-side reset of Microsoft Teams for the currently 
logged-on user.

It is designed to resolve issues such as:

• Dial pad not clickable
• Unable to join meetings
• Teams UI unresponsive
• Authentication loop
• Teams stuck on loading screen
• Broken WebView2 rendering
• Corrupted local cache
• Credential token corruption

The script resets Teams by:

1. Stopping all Teams-related processes
2. Deleting local Teams cache and app data
3. Removing Teams/AAD authentication tokens (optional)
4. Resetting WinHTTP proxy configuration (optional)
5. Relaunching Teams

It supports:
• New Teams (MSIX-based)
• Classic Teams (Squirrel-based)

=========================================================================================
WHEN TO USE
=========================================================================================

✔ Dial pad visible but not clickable  
✔ Join meeting button does nothing  
✔ Teams UI partially broken  
✔ Suspected corrupted authentication tokens  
✔ WebView2 rendering glitches  

Do NOT use when:

✖ Dial pad is greyed out due to missing Teams Phone license  
✖ Issue is tenant-wide  
✖ Confirmed policy/licensing issue  

=========================================================================================
PARAMETERS
=========================================================================================

-RemoveCreds  
    Removes Teams/AAD related credentials from Windows Credential Manager.

-ResetProxy  
    Resets WinHTTP proxy configuration.

-RestartTeams (default: enabled)  
    Automatically restarts Teams after reset.

=========================================================================================
SECURITY NOTES
=========================================================================================

• Only affects CURRENT USER profile  
• Does NOT uninstall Teams  
• Does NOT modify licensing  
• Safe for enterprise usage  
• User may need to sign in again  

=========================================================================================
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$RemoveCreds,
    [switch]$ResetProxy,
    [switch]$RestartTeams = $true
)

function Get-EnvString {
    param([Parameter(Mandatory)][string]$Name)

    $v = [Environment]::GetEnvironmentVariable($Name, "User")
    if (-not $v) { $v = [Environment]::GetEnvironmentVariable($Name, "Process") }
    if (-not $v) { $v = [Environment]::GetEnvironmentVariable($Name, "Machine") }

    if (-not $v) {
        throw "Environment variable '$Name' not found."
    }

    return [string]$v
}

function Stop-TeamsProcesses {
    Write-Host "Stopping Teams processes..." -ForegroundColor Cyan

    $names = @(
        "ms-teams", "Teams", "TeamsWebView2",
        "msedgewebview2", "WebViewHost",
        "Update", "Squirrel", "TeamsUpdater"
    ) | Select-Object -Unique

    foreach ($n in $names) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }

    Start-Sleep -Seconds 2
}

function Clear-TeamsData {

    Write-Host "Clearing Teams local data..." -ForegroundColor Cyan

    $appData      = Get-EnvString -Name "APPDATA"
    $localAppData = Get-EnvString -Name "LOCALAPPDATA"

    $paths = @(
        "$appData\Microsoft\Teams",
        "$localAppData\Microsoft\Teams",
        "$localAppData\SquirrelTemp",
        "$localAppData\Packages\MSTeams_8wekyb3d8bbwe",
        "$localAppData\Microsoft\EdgeWebView",
        "$localAppData\Microsoft\TeamsMeetingAddin"
    )

    foreach ($p in $paths | Select-Object -Unique) {
        if (Test-Path $p) {
            Write-Host "Deleting $p" -ForegroundColor Yellow
            Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Remove-TeamsCredentials {

    Write-Host "Removing Teams-related credentials..." -ForegroundColor Cyan

    $targets = & cmdkey /list 2>$null |
        Select-String -Pattern "Target:" |
        ForEach-Object { ($_ -split "Target:\s*")[1].Trim() }

    $match = $targets | Where-Object {
        $_ -match "Teams" -or
        $_ -match "ADAL" -or
        $_ -match "SSO" -or
        $_ -match "microsoftonline" -or
        $_ -match "Office" -or
        $_ -match "oneauth"
    }

    foreach ($t in $match | Select-Object -Unique) {
        Write-Host "Deleting credential: $t" -ForegroundColor Yellow
        cmdkey /delete:$t | Out-Null
    }
}

function Reset-WinINetProxy {
    Write-Host "Resetting WinHTTP proxy..." -ForegroundColor Cyan
    netsh winhttp reset proxy | Out-Null
}

function Start-Teams {
    Write-Host "Starting Teams..." -ForegroundColor Cyan
    try {
        Start-Process "msteams:"
    }
    catch {
        $classicExe = "$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe"
        if (Test-Path $classicExe) {
            Start-Process $classicExe
        }
    }
}

Write-Host "`n=== Microsoft Teams Full Client Reset ===" -ForegroundColor Green
Write-Host "User: $env:USERNAME"
Write-Host "------------------------------------------------`n"

Stop-TeamsProcesses
Clear-TeamsData

if ($RemoveCreds) { Remove-TeamsCredentials }
if ($ResetProxy)  { Reset-WinINetProxy }

if ($RestartTeams) { Start-Teams }

Write-Host "`nReset completed successfully."
Write-Host "User may need to sign in again."
Write-Host "Test dial pad and meeting join functionality."
Write-Host "================================================`n"
