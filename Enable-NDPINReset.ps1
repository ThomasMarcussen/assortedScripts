###################################################################################################################
# Name: Enable-NDPINReset.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: July, 2023
# Version: 1.0
###################################################################################################################
<#
	.SYNOPSIS
	Script to enable non-destructive PIN reset service for Windows Hello for Business computers.
	.DESCRIPTION
	Script to enable non-destructive PIN reset service for Windows Hello for Business computers.
	
	* Requirements:
		-- Azure Active Directory
		-- Windows Enterprise and Pro editions. There's no licensing requirement for this feature.
		-- Hybrid Windows Hello for Business deployment
		-- Azure AD registered, Azure AD joined, and Hybrid Azure AD joined
	
	* The script actions the following 
		-- Install Microsoft Graph PowerShell module
		-- Prompt the user for domain admin credentials (if it detects it is not running as domain admin)
		-- Check whether non-destructive PIN reset is configured on current Windows device.
		-- Enable the Microsoft PIN Reset Service and Client in Azure AD tenant.
		-- Configure Windows device(s) to use the Microsoft PIN Reset Service using Microsoft Intune policy.
	
	Script prerequisites:
	1. A minimum Windows PowerShell version of '7.2' is required to run this script.
	
	2. Azure Active Directory Global Administrator.

	3. Approve admin consent for the following permissions in Microsoft Graph application in Azure AD apps:
	
	DeviceManagementConfiguration.ReadWrite.All
	Policy.ReadWrite.DeviceConfiguration
	Organization.Read.All
	.PARAMETER Group
	Specifies the device group to assign the new Intune configuration policy.
	.PARAMETER LogPath
	Specifies path to save script output to.
	.EXAMPLE
	.\Enable-NDPINReset.ps1 -Group Group1 -LogPath .\

#>
#Requires -Version 7.0

param (
	[Parameter(mandatory = $true)][string] $Group,
	[Parameter(mandatory = $false)][string] $LogPath
)

if ($LogPath) {
	$ErrorActionPreference="SilentlyContinue"
	Stop-Transcript | out-null
	$ErrorActionPreference = "Continue"
	$log_file = $LogPath + "\" + (Get-Date -f yyyy-MM-dd_HH-mm-ss) + "_Enable-NDPINReset_Output.log"
	Start-Transcript -path $log_file -append
}

#Connect to MS Graph API
if (-not(Get-InstalledModule -Name Microsoft.graph -MinimumVersion 1.9.6)) {Install-Module microsoft.graph -scope CurrentUser  -Force -AllowClobber}

Write-host "`nConnecting to Microsoft Graph API. If not authenticated already in this PowerShell session, you will be prompted for your Azure AD credentials. `n`nPlease use an account with following permissions: DeviceManagementConfiguration.ReadWrite.All, Policy.ReadWrite.DeviceConfiguration, Organization.Read.All`n"

Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All","Policy.ReadWrite.DeviceConfiguration","Organization.Read.All"

Write-host "`nConnected Successfully to Microsoft Graph API."

Select-MgProfile beta

#Check whether non-destructive PIN reset is configured on current Windows device.
Write-host "`nRunning dsregcmd /status command..."
$dsregcmdResult = dsregcmd /status
if (!($dsregcmdResult)) {
	Write-host "dsregcmd /status command failed. Exiting..."
	exit
} else {
	if ($dsregcmdResult -like "*CanReset : DestructiveOnly*") {
		Write-host "Destructive PIN reset (Default) is configured on current Windows device. Proceeding to enable non-destructive PIN reset..."
	} elseif ($dsregcmdResult -like "*CanReset : DestructiveAndNonDestructive*") {
		Write-host "Non-destructive PIN reset is configured on current Windows device. Exiting..."
		exit
	} elseif ($dsregcmdResult -notlike "*CanReset*") {
		Write-host "Please ensure this device has Windows Hello for Business enabled. Exiting..."
		exit
	}
}

#Enable the Microsoft PIN Reset Service and Client in Azure AD tenant.
Write-host "Before you can remotely reset PINs, you must register two applications in your Azure Active Directory tenant:

PIN Reset Service
PIN Reset Client

*************
*  APP 1/2  *
*************

In the next PIN Reset Service application registration page that the script will open automatically for you, please sign in using a Global Administrator account you use to manage your Azure Active Directory tenant.
After you've logged in, select Accept to give consent to the PIN Reset Service to access your organization.

Once finished, please return to the script window and press Enter to continue or CTRL+C to exit" -ForegroundColor Yellow

Start-Process "https://login.windows.net/common/oauth2/authorize?response_type=code&client_id=b8456c59-1230-44c7-a4a2-99b085333e84&resource=https%3A%2F%2Fgraph.windows.net&redirect_uri=https%3A%2F%2Fcred.microsoft.com&state=e9191523-6c2f-4f1d-a4f9-c36f26f89df0&prompt=admin_consent"
Pause

Write-host "
*************
*  APP 2/2  *
*************
In the next PIN Reset Client application registration page that the script will open automatically for you, please sign in using a Global Administrator account you use to manage your Azure Active Directory tenant.
After you've logged in, select Next then Accept to give consent to the PIN Reset Client to access your organization.

Once finished, please return to the script window and press Enter to continue or CTRL+C to exit" -ForegroundColor Yellow

Start-Process "https://login.windows.net/common/oauth2/authorize?response_type=code&client_id=9115dd05-fad5-4f9c-acc7-305d08b1b04e&resource=https%3A%2F%2Fcred.microsoft.com%2F&redirect_uri=ms-appx-web%3A%2F%2FMicrosoft.AAD.BrokerPlugin%2F9115dd05-fad5-4f9c-acc7-305d08b1b04e&state=6765f8c5-f4a7-4029-b667-46a6776ad611&prompt=admin_consent"
Pause

if (Get-MgServicePrincipal -ConsistencyLevel eventual -Count spCount -Search '"DisplayName:Microsoft Pin Reset Service Production"') {
	Write-host "Microsoft Pin Reset Service Production application was found in Azure AD!"
} else {
	Write-host "Microsoft Pin Reset Service Production application was NOT found in Azure AD. Please retry registering the application using an Azure AD Global Administrator account" -ForegroundColor Red
	exit
}

if (Get-MgServicePrincipal -ConsistencyLevel eventual -Count spCount -Search '"DisplayName:Microsoft Pin Reset Client Production"') {
	Write-host "Microsoft Pin Reset Client Production application was found in Azure AD!"
} else {
	Write-host "Microsoft Pin Reset Client Production application was NOT found in Azure AD. Please retry registering the application using an Azure AD Global Administrator account" -ForegroundColor Red
	exit
}

#Configure Windows device(s) to use the Microsoft PIN Reset Service using Microsoft Intune policy.
$TenantID = (Get-MgOrganization).id
$params = @{
	Id = "00000000-0000-0000-0000-000000000000"
	DisplayName = "Enable Pin Recovery"
	RoleScopeTagIds = @(
		"0"
	)
	"@odata.type" = "#microsoft.graph.windows10CustomConfiguration"
	omaSettings = @(
		@{
			displayName = "EnablePinRecovery"
			"@odata.type" = "#microsoft.graph.omaSettingBoolean"
			value = "true"
			omaUri = "./Device/Vendor/MSFT/Policy/PassportForWork/$TenantId/Policies/EnablePinRecovery"
		}
	)
}

$paramsBody = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphDeviceConfiguration]$params

New-MgDeviceManagementDeviceConfiguration -BodyParameter $paramsBody

$deviceConfigurationId  = (Get-MgDeviceManagementDeviceConfiguration -Filter "displayname eq 'Enable Pin Recovery'").id

if ($deviceConfigurationId) {
	Write-host "`nIntune device configuration policy 'Enable Pin Recovery' was created successfully. ID:" $deviceConfigurationId
} else {
	throw "`nFailed to create Intune device configuration policy! please ensure you have required permissions and an active intune license."
}

$GroupID = (Get-MgGroup -Filter "displayname eq '$Group'").id

if ($GroupID) {
	Write-host "`nFound Azure AD Group" $Group "ID:" $GroupID

	#Assign the configuration profile
	$assignments = @{
		assignments = @()
	}
	
	$requestBody = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphDeviceConfigurationAssignment]$assignments
	$requestBody.Target.AdditionalProperties.Add("@odata.type","#microsoft.graph.groupAssignmentTarget")
	$requestBody.Target.AdditionalProperties.Add("groupId",$GroupID)
	New-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $deviceConfigurationId -BodyParameter $requestBody

} else {
	throw "`nAzure AD group ID not found! please re-check the Azure AD group name."
}

$PolicyAssignment = Get-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $deviceConfigurationId

if ($PolicyAssignment) {
	Write-host "`nPolicy has been assigned to Azure AD group successfully!"
} else {
	throw "`nPolicy assignment to Azure AD Group failed."
}

if ($LogPath) {
	Stop-transcript
}
