###################################################################################################################
# Name: Detect-ClassicTeams.ps1
# Author: Thomas Marcussen
# Title: Microsoft MVP | Technology Architect
# Email: Thomas@ThomasMarcussen.com
# Date: 2026-04-18
# Version: 1.0
# Description: Detection script for Intune Proactive Remediations. Checks whether Classic Microsoft Teams
#              or Teams Machine-Wide Installer is still present on the device.
###################################################################################################################

$LogPath = "C:\Windows\Logs"
$LogFile = Join-Path $LogPath "Detect-ClassicTeams.log"

if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "$Timestamp [$Level] $Message"

    Write-Output $Line
    Add-Content -Path $LogFile -Value $Line
}

Write-Log "=== Starting Classic Teams detection ==="

$ClassicTeamsFound = $false
$Findings = New-Object System.Collections.Generic.List[string]

# ------------------------------------------------------------
# Check for Teams Machine-Wide Installer
# ------------------------------------------------------------
$UninstallKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$MachineWideInstaller = Get-ItemProperty -Path $UninstallKeys -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -like "Teams Machine-Wide Installer*"
}

if ($MachineWideInstaller) {
    $ClassicTeamsFound = $true
    foreach ($Item in $MachineWideInstaller) {
        $Findings.Add("Machine-Wide Installer detected: $($Item.DisplayName) [$($Item.PSChildName)]")
    }
}

# ------------------------------------------------------------
# Check user profiles for classic Teams
# ------------------------------------------------------------
$ExcludedProfiles = @("Public", "Default", "Default User", "All Users", "defaultuser0")
$UserProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -notin $ExcludedProfiles
}

foreach ($UserProfile in $UserProfiles) {
    $TeamsRoot = Join-Path $UserProfile.FullName "AppData\Local\Microsoft\Teams"
    $TeamsExe = Join-Path $TeamsRoot "current\Teams.exe"
    $UpdateExe = Join-Path $TeamsRoot "Update.exe"

    if (Test-Path $TeamsRoot) {
        $ClassicTeamsFound = $true
        $Findings.Add("Classic Teams folder detected in profile: $($UserProfile.Name) [$TeamsRoot]")
    }

    if (Test-Path $TeamsExe) {
        $ClassicTeamsFound = $true
        $Findings.Add("Classic Teams executable detected in profile: $($UserProfile.Name) [$TeamsExe]")
    }

    if (Test-Path $UpdateExe) {
        $ClassicTeamsFound = $true
        $Findings.Add("Classic Teams Update.exe detected in profile: $($UserProfile.Name) [$UpdateExe]")
    }

    $DesktopPath = Join-Path $UserProfile.FullName "Desktop"
    if (Test-Path $DesktopPath) {
        $Shortcuts = Get-ChildItem -Path $DesktopPath -Filter "*Teams*.lnk" -ErrorAction SilentlyContinue
        if ($Shortcuts) {
            $ClassicTeamsFound = $true
            foreach ($Shortcut in $Shortcuts) {
                $Findings.Add("Teams shortcut detected in profile: $($UserProfile.Name) [$($Shortcut.FullName)]")
            }
        }
    }
}

# ------------------------------------------------------------
# Check HKLM Run entry
# ------------------------------------------------------------
$RunKeyHKLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
try {
    $RunValue = Get-ItemProperty -Path $RunKeyHKLM -Name "Teams" -ErrorAction SilentlyContinue
    if ($null -ne $RunValue) {
        $ClassicTeamsFound = $true
        $Findings.Add("HKLM Run entry for Teams detected")
    }
}
catch {
    Write-Log "Unable to read HKLM Run entry. $_" "WARN"
}

# ------------------------------------------------------------
# Final result
# ------------------------------------------------------------
if ($ClassicTeamsFound) {
    Write-Log "Classic Teams detected. Device is non-compliant." "WARN"
    foreach ($Finding in $Findings) {
        Write-Log $Finding "WARN"
    }

    Write-Output "Classic Teams detected"
    exit 1
}
else {
    Write-Log "No Classic Teams detected. Device is compliant."
    Write-Output "No Classic Teams detected"
    exit 0
}
