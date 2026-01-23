###################################################################################################################
# Name: Remove-WindowsAutopilotDeviceBySerialNumber.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: January, 2026
###################################################################################################################

# ==============================
# PROMPT FOR SERIAL NUMBER
# ==============================
$SerialNumber = Read-Host "Enter the serial number of the Autopilot device to delete"

if ([string]::IsNullOrWhiteSpace($SerialNumber)) {
    Write-Error "No serial number entered. Exiting."
    return
}

# Normalize input (helps with copy/paste issues)
$SerialNumber = $SerialNumber.Trim().ToUpper()

# ==============================
# CONNECT TO GRAPH
# ==============================
Import-Module Microsoft.Graph.DeviceManagement

Connect-MgGraph -Scopes "DeviceManagementServiceConfig.ReadWrite.All"

# ==============================
# FIND AUTOPILOT DEVICE
# ==============================
Write-Host "Searching for Autopilot device with serial number: $SerialNumber" -ForegroundColor Cyan

$Devices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity `
    -Filter "contains(serialNumber,'$SerialNumber')"

if (-not $Devices) {
    Write-Warning "No Autopilot device found with serial number: $SerialNumber"
    Disconnect-MgGraph
    return
}

# ==============================
# CONFIRM & DELETE
# ==============================
foreach ($Device in $Devices) {

    Write-Host ""
    Write-Host "Autopilot device found:" -ForegroundColor Yellow
    Write-Host "  Serial Number : $($Device.SerialNumber)"
    Write-Host "  Model         : $($Device.Model)"
    Write-Host "  Manufacturer  : $($Device.Manufacturer)"
    Write-Host "  Device ID     : $($Device.Id)"

    $Confirm = Read-Host "Type DELETE to confirm removal of this Autopilot device"

    if ($Confirm -ne "DELETE") {
        Write-Warning "Deletion cancelled for serial number $($Device.SerialNumber)"
        continue
    }

    Remove-MgDeviceManagementWindowsAutopilotDeviceIdentity `
        -WindowsAutopilotDeviceIdentityId $Device.Id

    Write-Host "✅ Autopilot device deleted successfully" -ForegroundColor Green
}

Disconnect-MgGraph
