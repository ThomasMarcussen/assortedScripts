###################################################################################################################
# Name: Remediate-ClassicTeams.ps1
# Author: Thomas Marcussen
# Title: Microsoft MVP | Technology Architect
# Email: Thomas@ThomasMarcussen.com
# Date: 2026-04-18
# Version: 1.0
# Description: Remediation script for Intune Proactive Remediations. Removes Classic Microsoft Teams,
#              Teams Machine-Wide Installer, and common leftovers. Creates logfile in C:\Windows\Logs
###################################################################################################################

$LogPath = "C:\Windows\Logs"
$LogFile = Join-Path $LogPath "Remediate-ClassicTeams.log"

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

Write-Log "=== Starting Classic Teams remediation ==="

# ------------------------------------------------------------
# Stop classic Teams related processes
# ------------------------------------------------------------
$Processes = @("Teams", "Update")
foreach ($Process in $Processes) {
    try {
        $RunningProcesses = Get-Process -Name $Process -ErrorAction SilentlyContinue
        if ($RunningProcesses) {
            $RunningProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Log "Stopped process: $Process"
        }
        else {
            Write-Log "Process not running: $Process"
        }
    }
    catch {
        Write-Log "Failed stopping process $Process. $_" "ERROR"
    }
}

# ------------------------------------------------------------
# Remove Teams Machine-Wide Installer
# ------------------------------------------------------------
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
            $ProductCode = $App.PSChildName
            Write-Log "Uninstalling $($App.DisplayName) with product code $ProductCode"
            $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $ProductCode /qn /norestart" -Wait -PassThru -NoNewWindow
            Write-Log "msiexec exit code for $($App.DisplayName): $($Process.ExitCode)"
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
# Remove per-user classic Teams
# ------------------------------------------------------------
$ExcludedProfiles = @("Public", "Default", "Default User", "All Users", "defaultuser0")
$UserProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -notin $ExcludedProfiles
}

foreach ($UserProfile in $UserProfiles) {
    $TeamsRoot = Join-Path $UserProfile.FullName "AppData\Local\Microsoft\Teams"
    $UpdateExe = Join-Path $TeamsRoot "Update.exe"
    $DesktopPath = Join-Path $UserProfile.FullName "Desktop"
    $StartMenuPath = Join-Path $UserProfile.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
    $StartupPath = Join-Path $UserProfile.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

    if (Test-Path $TeamsRoot) {
        Write-Log "Found Classic Teams in profile: $($UserProfile.Name)"

        try {
            if (Test-Path $UpdateExe) {
                Write-Log "Running Update.exe uninstall for profile: $($UserProfile.Name)"
                $UninstallProcess = Start-Process -FilePath $UpdateExe -ArgumentList "--uninstall -s" -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue
                if ($UninstallProcess) {
                    Write-Log "Update.exe exit code for profile $($UserProfile.Name): $($UninstallProcess.ExitCode)"
                }
            }
            else {
                Write-Log "Update.exe not found for profile: $($UserProfile.Name)"
            }

            Start-Sleep -Seconds 2

            if (Test-Path $TeamsRoot) {
                Remove-Item -Path $TeamsRoot -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Removed Teams folder from profile: $($UserProfile.Name)"
            }
        }
        catch {
            Write-Log "Failed removing Classic Teams from profile $($UserProfile.Name). $_" "ERROR"
        }
    }
    else {
        Write-Log "Classic Teams folder not found in profile: $($UserProfile.Name)"
    }

    # Desktop shortcuts
    if (Test-Path $DesktopPath) {
        try {
            Get-ChildItem -Path $DesktopPath -Filter "*Teams*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                Write-Log "Removed desktop shortcut: $($_.FullName)"
            }
        }
        catch {
            Write-Log "Failed removing desktop shortcuts for profile $($UserProfile.Name). $_" "ERROR"
        }
    }

    # Start menu shortcuts
    if (Test-Path $StartMenuPath) {
        try {
            Get-ChildItem -Path $StartMenuPath -Filter "*Teams*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                Write-Log "Removed Start Menu shortcut: $($_.FullName)"
            }
        }
        catch {
            Write-Log "Failed removing Start Menu shortcuts for profile $($UserProfile.Name). $_" "ERROR"
        }
    }

    # Startup shortcuts
    if (Test-Path $StartupPath) {
        try {
            Get-ChildItem -Path $StartupPath -Filter "*Teams*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                Write-Log "Removed Startup shortcut: $($_.FullName)"
            }
        }
        catch {
            Write-Log "Failed removing Startup shortcuts for profile $($UserProfile.Name). $_" "ERROR"
        }
    }

    # Per-user Run value via user hive
    try {
        $NtUserDatPath = Join-Path $UserProfile.FullName "NTUSER.DAT"
        $HiveName = "HKU\Temp_$($UserProfile.Name)"
        $HiveLoaded = $false

        if (Test-Path $NtUserDatPath) {
            & reg.exe load $HiveName $NtUserDatPath | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $HiveLoaded = $true
                Write-Log "Loaded user hive for profile: $($UserProfile.Name)"
            }
        }

        if ($HiveLoaded) {
            $RunKeyUser = "Registry::$HiveName\Software\Microsoft\Windows\CurrentVersion\Run"
            if (Test-Path $RunKeyUser) {
                Remove-ItemProperty -Path $RunKeyUser -Name "Teams" -ErrorAction SilentlyContinue
                Write-Log "Removed Teams Run entry from profile: $($UserProfile.Name)"
            }

            & reg.exe unload $HiveName | Out-Null
            Write-Log "Unloaded user hive for profile: $($UserProfile.Name)"
        }
    }
    catch {
        Write-Log "Failed handling user hive for profile $($UserProfile.Name). $_" "ERROR"
        try {
            & reg.exe unload $HiveName | Out-Null
        }
        catch {
        }
    }
}

# ------------------------------------------------------------
# Remove HKLM Run entry
# ------------------------------------------------------------
$RunKeyHKLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
if (Test-Path $RunKeyHKLM) {
    try {
        Remove-ItemProperty -Path $RunKeyHKLM -Name "Teams" -ErrorAction SilentlyContinue
        Write-Log "Removed HKLM Teams Run entry"
    }
    catch {
        Write-Log "Failed removing HKLM Teams Run entry. $_" "ERROR"
    }
}

# ------------------------------------------------------------
# Remove Teams Installer folder
# ------------------------------------------------------------
$TeamsInstallerPath = "C:\Program Files (x86)\Teams Installer"
if (Test-Path $TeamsInstallerPath) {
    try {
        Remove-Item -Path $TeamsInstallerPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Removed folder: $TeamsInstallerPath"
    }
    catch {
        Write-Log "Failed removing folder $TeamsInstallerPath. $_" "ERROR"
    }
}
else {
    Write-Log "Folder not found: $TeamsInstallerPath"
}

# ------------------------------------------------------------
# Final validation
# ------------------------------------------------------------
$ClassicTeamsStillPresent = $false

$MachineWideInstallerCheck = Get-ItemProperty -Path $UninstallKeys -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -like "Teams Machine-Wide Installer*"
}
if ($MachineWideInstallerCheck) {
    $ClassicTeamsStillPresent = $true
    Write-Log "Machine-Wide Installer still detected after remediation" "WARN"
}

foreach ($UserProfile in $UserProfiles) {
    $TeamsRoot = Join-Path $UserProfile.FullName "AppData\Local\Microsoft\Teams"
    $TeamsExe = Join-Path $TeamsRoot "current\Teams.exe"

    if ((Test-Path $TeamsRoot) -or (Test-Path $TeamsExe)) {
        $ClassicTeamsStillPresent = $true
        Write-Log "Classic Teams still detected in profile: $($UserProfile.Name)" "WARN"
    }
}

if ($ClassicTeamsStillPresent) {
    Write-Log "Remediation completed with warnings. Some remnants still exist." "WARN"
    Write-Output "Classic Teams remnants still detected"
    exit 1
}
else {
    Write-Log "Classic Teams remediation completed successfully"
    Write-Output "Classic Teams removed successfully"
    exit 0
}
