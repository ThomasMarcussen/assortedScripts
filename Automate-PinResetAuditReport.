###################################################################################################################
# Name: Automated-PINResetAuditReport.ps1
# Author: Thomas Marcussen
# Date: December,2025
# Version: 1.0
###################################################################################################################
<#
.SYNOPSIS
Generates an audit report for devices configured for non-destructive PIN reset.

.DESCRIPTION
This script connects to Microsoft Graph, fetches data from Intune, and generates a report summarizing:
    - Devices configured for non-destructive PIN reset.
    - Compliance status of policies.
    - Devices missing the configuration.

.REQUIREMENTS
    - Azure Active Directory Global Administrator
    - Microsoft Graph PowerShell module
    - Permissions: DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All
    - Minimum Windows PowerShell version 7.2

.PARAMETER ReportPath
Specifies the path to save the audit report.

.PARAMETER Group
Specifies the Azure AD group to audit.

.EXAMPLE
.\Automated-PINResetAuditReport.ps1 -ReportPath "C:\Reports" -Group "PIN Reset Devices"

#>
param (
    [Parameter(Mandatory = $true)]
    [string] $ReportPath,
    
    [Parameter(Mandatory = $true)]
    [string] $Group
)

# Ensure Microsoft Graph Module is installed
if (-not(Get-InstalledModule -Name Microsoft.Graph -MinimumVersion 1.9.6 -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Microsoft Graph PowerShell module..." -ForegroundColor Yellow
    Install-Module -Name Microsoft.Graph -Force -Scope CurrentUser
}

# Connect to Microsoft Graph API
Write-Host "`nConnecting to Microsoft Graph API..." -ForegroundColor Green
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All"

Write-Host "Connected to Microsoft Graph API successfully." -ForegroundColor Green

# Fetch Azure AD Group ID
Write-Host "`nFetching group information..." -ForegroundColor Cyan
$group = Get-MgGroup -Filter "DisplayName eq '$Group'" -ConsistencyLevel eventual -CountVariable count
if (-not $group) {
    Write-Host "Group '$Group' not found in Azure AD. Please check the group name." -ForegroundColor Red
    exit
}
$groupId = $group.Id
Write-Host "Group '$Group' found with ID: $groupId" -ForegroundColor Green

# Fetch devices in the group
Write-Host "`nFetching devices in the group..." -ForegroundColor Cyan
$devices = Get-MgGroupMember -GroupId $groupId -All
if (-not $devices) {
    Write-Host "No devices found in the group." -ForegroundColor Red
    exit
}

Write-Host "Found $($devices.Count) devices in the group." -ForegroundColor Green

# Initialize Report
$report = @()

# Check each device for PIN reset configuration
Write-Host "`nAuditing devices for PIN reset configuration..." -ForegroundColor Cyan
foreach ($device in $devices) {
    $deviceDetails = Get-MgDeviceManagementManagedDevice -Filter "deviceName eq '$($device.DisplayName)'" -ConsistencyLevel eventual

    if ($deviceDetails) {
        $compliancePolicy = $deviceDetails.DeviceConfigurationStates | Where-Object { $_.DisplayName -eq "Enable Pin Recovery" }
        $pinResetStatus = if ($compliancePolicy -and $compliancePolicy.State -eq "Compliant") {
            "Configured and Compliant"
        } elseif ($compliancePolicy) {
            "Configured but Non-Compliant"
        } else {
            "Not Configured"
        }

        # Add to report
        $report += [pscustomobject]@{
            DeviceName       = $device.DisplayName
            ComplianceStatus = $pinResetStatus
            LastCheckInDate  = $deviceDetails.LastContactedDateTime
        }
    } else {
        $report += [pscustomobject]@{
            DeviceName       = $device.DisplayName
            ComplianceStatus = "Not Found in Intune"
            LastCheckInDate  = "N/A"
        }
    }
}

# Save report to file
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportFilePath = Join-Path -Path $ReportPath -ChildPath "PINResetAuditReport_$timestamp.csv"

Write-Host "`nSaving report to $reportFilePath..." -ForegroundColor Green
$report | Export-Csv -Path $reportFilePath -NoTypeInformation -Encoding UTF8

Write-Host "`nAudit report generated successfully!" -ForegroundColor Green
Write-Host "Report location: $reportFilePath" -ForegroundColor Yellow
