###################################################################################################################
# Name: Remove-ClassicTeams.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: April,2026
# Version: 1.0
# Description: Removes Classic Microsoft Teams including Teams Machine-Wide Installer,
#              per-user installs, and common leftovers. Creates logfile in C:\Windows\Logs
###################################################################################################################

# ------------------------------------------------------------
# Logging setup
# ------------------------------------------------------------
$LogPath = "C:\Windows\Logs"
$LogFile = Join-Path $LogPath "Remove-ClassicTeams.log"

if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp [$Level] $Message"

    Write-Output $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

Write-Log "=== Starting Classic Teams Cleanup ==="

# ------------------------------------------------------------
# Stop Teams related processes
# ------------------------------------------------------------
Write-Log "Stopping Teams related processes"

$Processes = @("Teams", "Update")
foreach ($Process in $Processes) {
    try {
        Get-Process -Name $Process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Log "Stopped process: $Process"
    }
    catch {
        Write-Log "Failed stopping process: $Process. $_" "ERROR"
    }
}

# ------------------------------------------------------------
# Remove Teams Machine-Wide Installer
# ------------------------------------------------------------
Write-Log "Checking for Teams Machine-Wide Installer"

$UninstallKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$MachineWideInstaller = Get-ItemProperty -Path $UninstallKeys -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -like "Teams Machine-Wide Installer*"
}

if ($MachineWideInstaller) {
    foreach ($App in $MachineWideInstaller) {
        try {
            Write-Log "Uninstalling $($App.DisplayName) with product code $($App.PSChildName)"
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $($App.PSChildName) /qn /norestart" -Wait -NoNewWindow
            Write-Log "Successfully uninstalled $($App.DisplayName)"
        }
        catch {
            Write-Log "Failed to uninstall $($App.DisplayName). $_" "ERROR"
        }
    }
}
else {
    Write-Log "Teams Machine-Wide Installer not found"
}

# ------------------------------------------------------------
# Remove per-user Teams installations
# ------------------------------------------------------------
Write-Log "Checking user profiles for Classic Teams"

$ExcludedProfiles = @("Public", "Default", "Default User", "All Users", "defaultuser0")
$UserProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -notin $ExcludedProfiles
}

foreach ($UserProfile in $UserProfiles) {
    $TeamsPath = Join-Path $UserProfile.FullName "AppData\Local\Microsoft\Teams"
    $UpdateExe = Join-Path $TeamsPath "Update.exe"

    if (Test-Path $TeamsPath) {
        Write-Log "Found Classic Teams in profile: $($UserProfile.Name)"

        try {
            if (Test-Path $UpdateExe) {
                Write-Log "Running uninstall command for user profile: $($UserProfile.Name)"
                Start-Process -FilePath $UpdateExe -ArgumentList "--uninstall -s" -Wait -NoNewWindow -ErrorAction SilentlyContinue
            }

            Start-Sleep -Seconds 2

            if (Test-Path $TeamsPath) {
                Remove-Item -Path $TeamsPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Removed Teams folder for profile: $($UserProfile.Name)"
            }
        }
        catch {
            Write-Log "Failed to remove Teams from profile $($UserProfile.Name). $_" "ERROR"
        }
    }
    else {
        Write-Log "Classic Teams not found in profile: $($UserProfile.Name)"
    }
}

# ------------------------------------------------------------
# Remove Teams autorun entries from HKLM
# ------------------------------------------------------------
Write-Log "Cleaning HKLM Run entries"

$RunKeyHKLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
if (Test-Path $RunKeyHKLM) {
    try {
        Remove-ItemProperty -Path $RunKeyHKLM -Name "Teams" -ErrorAction SilentlyContinue
        Write-Log "Removed Teams autorun entry from HKLM"
    }
    catch {
        Write-Log "Failed to remove Teams autorun entry from HKLM. $_" "ERROR"
    }
}

# ------------------------------------------------------------
# Remove Teams desktop shortcuts from user desktops
# ------------------------------------------------------------
Write-Log "Cleaning Teams shortcuts from desktops"

foreach ($UserProfile in $UserProfiles) {
    $DesktopPath = Join-Path $UserProfile.FullName "Desktop"

    if (Test-Path $DesktopPath) {
        try {
            Get-ChildItem -Path $DesktopPath -Filter "*Teams*.lnk" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Log "Removed Teams shortcuts from desktop for profile: $($UserProfile.Name)"
        }
        catch {
            Write-Log "Failed to clean Teams shortcuts for profile $($UserProfile.Name). $_" "ERROR"
        }
    }
}

# ------------------------------------------------------------
# Final validation
# ------------------------------------------------------------
Write-Log "Running final validation"

$RemainingTeams = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $Path = Join-Path $_.FullName "AppData\Local\Microsoft\Teams\current\Teams.exe"
    if (Test-Path $Path) { $Path }
}

if ($RemainingTeams) {
    Write-Log "Classic Teams remnants still detected:" "WARN"
    foreach ($Item in $RemainingTeams) {
        Write-Log $Item "WARN"
    }
}
else {
    Write-Log "Classic Teams successfully removed"
}

Write-Log "=== Cleanup Completed ==="
