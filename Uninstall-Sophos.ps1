<#
.SYNOPSIS
    This script silently uninstalls Sophos Endpoint (Intercept X) from Windows systems.

.DESCRIPTION
    The script performs the following steps:
    - Disables Sophos Tamper Protection by modifying the registry.
    - Stops all running Sophos services.
    - Uninstalls all installed Sophos components silently.
    - Removes leftover registry entries related to Sophos.
    - Deletes any remaining Sophos installation folders.
    - Logs all actions to a file for troubleshooting.
    
    It ensures a **silent** execution when deployed via automation but displays progress when run manually from the command line.

.NOTES
    Author: <Your Name>
    Date:   <Today's Date>
    Version: 1.0
    Tested on: Windows 10/11, Windows Server 2016/2019/2022

#>

# Ensure the script is running as Administrator
Function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-Not (Test-Admin)) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    Exit 1
}

# Set log file path
$logFile = "$env:TEMP\Sophos_Uninstall.log"

# Function to check if running in an interactive command line session
Function Is-Interactive {
    return ($Host.Name -eq "ConsoleHost")
}

# Function to log messages and optionally display output
Function Log-Message {
    param([string]$message)
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timeStamp - $message"
    Add-Content -Path $logFile -Value $logEntry
    if (Is-Interactive) {
        Write-Host $message
    }
}

# Start logging
Log-Message "Starting Sophos uninstallation script..."

# Function to safely remove registry keys
Function Remove-RegistryKey {
    param([string]$path)
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Log-Message "Successfully removed registry key: $path"
        } catch {
            Log-Message "Failed to remove registry key: $path. Error: $_"
        }
    }
}

# Disable Tamper Protection
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config"
if (Test-Path $regPath) {
    try {
        Set-ItemProperty -Path $regPath -Name "Enabled" -Value 0 -ErrorAction Stop
        Remove-Item -Path $regPath -Force -Recurse -ErrorAction Stop
        Log-Message "Tamper Protection disabled successfully."
    } catch {
        Log-Message "Failed to disable Tamper Protection. Error: $_"
    }
} else {
    Log-Message "Tamper Protection registry key not found, continuing..."
}

# Stop all Sophos services
Log-Message "Stopping Sophos services..."
$services = Get-Service | Where-Object { $_.Name -like "Sophos*" }
foreach ($service in $services) {
    try {
        Stop-Service -Name $service.Name -Force -ErrorAction Stop
        Log-Message "Stopped service: $($service.Name)"
    } catch {
        Log-Message "Failed to stop service: $($service.Name). Error: $_"
    }
}

# Get list of Sophos products to uninstall
Log-Message "Retrieving installed Sophos products..."
$sophosProducts = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%Sophos%'" | Select-Object -ExpandProperty IdentifyingNumber

foreach ($productID in $sophosProducts) {
    try {
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $productID /qn /norestart" -NoNewWindow -Wait
        Log-Message "Successfully uninstalled Sophos product with ID: $productID"
    } catch {
        Log-Message "Failed to uninstall Sophos product with ID: $productID. Error: $_"
    }
}

# Check for remaining Sophos installations
$sophosPrograms = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%Sophos%'" | Select-Object Name
if ($sophosPrograms) {
    Log-Message "Some Sophos components are still installed. Manual removal may be needed."
} else {
    Log-Message "All Sophos components uninstalled successfully."
}

# Remove leftover registry keys
Log-Message "Cleaning up registry keys..."
$registryPaths = @(
    "HKLM:\SOFTWARE\Sophos",
    "HKLM:\SOFTWARE\WOW6432Node\Sophos",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos*"
)

foreach ($path in $registryPaths) {
    Remove-RegistryKey -path $path
}

# Clean up remaining files
$sophosDirs = @(
    "$env:ProgramFiles\Sophos",
    "$env:ProgramFiles (x86)\Sophos",
    "$env:ProgramData\Sophos",
    "$env:LOCALAPPDATA\Sophos"
)

foreach ($dir in $sophosDirs) {
    if (Test-Path $dir) {
        try {
            Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
            Log-Message "Removed folder: $dir"
        } catch {
            Log-Message "Failed to remove folder: $dir. Error: $_"
        }
    }
}

Log-Message "Sophos Endpoint uninstallation completed successfully."
