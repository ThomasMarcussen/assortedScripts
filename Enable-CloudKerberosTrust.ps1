###################################################################################################################
# Name: Enable-CloudKerberosTrust.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: May,2023
# Version: 1.0.0
###################################################################################################################
<#
	.SYNOPSIS
	Script to configure Azure AD Cloud Kerberos Trust.
	.DESCRIPTION
	Script to configure Azure AD Cloud Kerberos Trust.
	
	* The script actions the following 
		-- Install Azure AD Kerberos PowerShell module
		-- Prompt the user for domain admin credentials (if it detects it is not running as domain admin)
		-- Create a Kerberos Server object
		-- Verify a Kerberos Server object has been created successfully
		-- Create "CKT-Policy" Intune configuration profile 
		-- Create OMA-URI for Cloud Kerberos Trust enablement
		-- Assign the configuration profile
	
	Script prerequisites:
	1. Azure Active Directory global administrator.
	
	2. Active Directory domain administrator.

	3. Approve admin consent for the following permissions in Microsoft Graph application in Azure AD apps:
	CloudPC.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, Directory.Read.All
	.PARAMETER Domain
	Specifies the on-premises Active Directory domain. A new Azure AD Kerberos Server object will be created in this Active Directory domain.
	.PARAMETER UserName
	Specifies the UPN of an Azure Active Directory global administrator.
	.PARAMETER TenantID
	Specifies the Azure AD tenant ID for the new Intune configuration policy.
	.PARAMETER Group
	Specifies the device group to assign the new Intune configuration policy.
	.PARAMETER LogPath
	Specifies path to save script output to.
	.EXAMPLE
	.\Enable-CloudKerberosTrust.ps1 -Domain xyz.com -UserName admin@tenant.onmicrosoft.com -TenantID 0570e92c-8fb4-4775-9eb8-61f20dd2ce72 -Group Group1 -LogPath .\

#>

param (
	[Parameter(mandatory = $true)][string] $Domain,
	[Parameter(mandatory = $true)][string] $UserName,
	[Parameter(mandatory = $true)][string] $Group,
	[Parameter(mandatory = $false)][string] $TenantID,
	[Parameter(mandatory = $false)][string] $LogPath
)

if ($LogPath) {
	$ErrorActionPreference="SilentlyContinue"
	Stop-Transcript | out-null
	$ErrorActionPreference = "Continue"
	$log_file = $LogPath + "\" + (Get-Date -f yyyy-MM-dd_HH-mm-ss) + "_Enable-CloudKerberosTrust_Output.log"
	Start-Transcript -path $log_file -append
}

#Install Azure AD Kerberos PowerShell module 
Write-host 'Installing Azure AD Kerberos PowerShell module.'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
if (-not(Get-InstalledModule -Name AzureADHybridAuthenticationManagement -MinimumVersion 1.9.6)) {Install-Module AzureADHybridAuthenticationManagement -scope CurrentUser -Force -AllowClobber}

#Check whether running as admin
$p = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (!$p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script requires admin privileges to run and the current Windows PowerShell session is not running as Administrator. Start Windows PowerShell by using the Run as Administrator option, and then try running the script again.'
}

#Check whether user is a domain admin
if (![bool]((Get-ADGroupMember "Domain Admins").Where({$_.Name.Split('\')[-1] -eq $env:USERNAME}))) {
	Write-host 'This script requires AD domain admin privileges to run and the current Windows PowerShell session is not running as an AD domain admin. Upon next prompt, enter an AD Domain Admin username and password to proceed.'
	$domainCred = Get-Credential
	Write-host 'This script also requires Azure AD global administrator privileges to run. Upon next interactive sign-in prompt, login using an Azure AD global administrator to proceed.'
	Set-AzureADKerberosServer -Domain $Domain -UserPrincipalName $UserName -DomainCredential $domainCred
} else {
	Write-host 'This script requires Azure AD global administrator privileges to run. Upon next interactive sign-in prompt, login using an Azure AD global administrator to proceed.'
	Set-AzureADKerberosServer -Domain $Domain -UserPrincipalName $UserName
}

#Verify a Kerberos Server object has been created successfully
$CKT = get-AzureADKerberosServer -Domain $Domain -UserPrincipalName $userName
$CKT
if ([bool]($CKT.id)) {
	Write-host 'Cloud Kerberos Trust has been created successfully.'
} else {
	throw 'Failed to create Cloud Kerberos Trust.'
}

#Connect to MS Graph API
if (-not(Get-InstalledModule -Name Microsoft.graph -MinimumVersion 1.9.6)) {Install-Module microsoft.graph -scope CurrentUser  -Force -AllowClobber}

Write-host "`nConnecting to Microsoft Graph API. If not authenticated already in this PowerShell session, you will be prompted for your Azure AD credentials. `n`nPlease use an account with following permissions: DeviceManagementConfiguration.ReadWrite.All, Policy.ReadWrite.DeviceConfiguration`n"

Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All","Policy.ReadWrite.DeviceConfiguration","Organization.Read.All"

Write-host "`nConnected Successfully to Microsoft Graph API."

Select-MgProfile beta

Write-host "`nFetching User Drive ID"

#Get Tenant ID (if not provided as a parameter)
if (!($TenantID)) {
	Write-host "`nTenantID parameter wasn't provided. Fetching Azure AD tenant ID..."
	$TenantID = (Get-MgOrganization).id
	Write-host "`nFound Azure AD Tenant ID:" $TenantID
}

#Create "CKT-Policy" Intune configuration profile 
$params = @{
	Id = "00000000-0000-0000-0000-000000000000"
	DisplayName = "CKT-Policy"
	RoleScopeTagIds = @(
		"0"
	)
	"@odata.type" = "#microsoft.graph.windows10CustomConfiguration"
	omaSettings = @(
		@{
			displayName = "UseCloudTrustForOnPremAuth"
			"@odata.type" = "#microsoft.graph.omaSettingBoolean"
			value = "true"
			omaUri = "./Device/Vendor/MSFT/PassportForWork/$TenantID/Policies/UseCloudTrustForOnPremAuth"
		}
	)
}

$paramsBody = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphDeviceConfiguration]$params

New-MgDeviceManagementDeviceConfiguration -BodyParameter $paramsBody

$deviceConfigurationId  = (Get-MgDeviceManagementDeviceConfiguration -Filter "displayname eq 'CKT-Policy'").id

if ($deviceConfigurationId) {
	Write-host "`nIntune device configuration policy CKT-Policy was created successfully. ID:" $deviceConfigurationId
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
	$requestBody.Target.AdditionalProperties.Add("groupId","f434a0b6-daa3-48eb-a605-a0099e9ec8d8")
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

