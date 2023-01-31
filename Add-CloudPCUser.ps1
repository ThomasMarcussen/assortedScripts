###################################################################################################################
# Name: Add-CloudPCUser.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: January,2023
###################################################################################################################
<#
	.SYNOPSIS
	Script to add a Windows 365 Cloud PC User
	.DESCRIPTION
	Script to add a Windows 365 Cloud PC User
	
	Script prerequisites:
	1. A minimum Windows PowerShell version of '7.2' is required to run this script. The script automatically checks for and installs module if needed.
	
	2. Windows 365 Cloud PC Management PowerShell Module must be installed on local machine. The script automatically checks for and installs module if needed.
	
	3. Microsoft Graph PowerShell Module must be installed on local machine. The script automatically checks for and installs module if needed.

	4. An Azure AD user that has an admin consent permission, if needed, to approve the following permissions in Microsoft Graph application in Azure AD apps:
	CloudPC.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, Directory.Read.All
	.PARAMETER Username
	Username to add to Windows 365 Cloud PC
	.PARAMETER UsersListPath
	CSV file path containing a list of users to add to Windows 365 Cloud PC. Sample file contents:
	----------
	upn
	AdeleV@sampletenant.onmicrosoft.com
	AlexW@sampletenant.onmicrosoft.com
	DiegoS@sampletenant.onmicrosoft.com
	GradyA@sampletenant.onmicrosoft.com
	.PARAMETER Group
	Azure AD group name to add users to
	.EXAMPLE
	.\Add-CloudPCUser.ps1 -Username User@SampleTenant.onmicrosoft.com -Group IT -Verbose
	.EXAMPLE
	.\Add-CloudPCUser.ps1 -UsersListPath c:\temp\users.csv -Group Sales -Verbose
#>

#Requires -Version 7.2
param ([Parameter(mandatory = $false)][string] $Username,
	[Parameter(mandatory = $false)][string] $UsersListPath,
	[Parameter(mandatory = $true)][string] $Group
)

if ([string]::IsNullOrEmpty($Username) -and [string]::IsNullOrEmpty($UsersListPath)) {
	throw "`nPlease re-run the script and specify either an Azure AD user name or path to a CSV file containing a list of Azure AD user names to continue."
	}

if (![string]::IsNullOrEmpty($Username) -and ![string]::IsNullOrEmpty($UsersListPath)) {
	throw "`nPlease re-run the script and specify either an Azure AD user name or path to a CSV file containing a list of Azure AD user names to continue."
	}

if (!($PSVersionTable.PSVersion -gt 7.2)) {
	Write-host -BackgroundColor red "`nThe module 'C:\Program Files\WindowsPowerShell\Modules\PSCloudPC\1.0.4\PSCloudPC.psd1' requires a minimum Windows PowerShell version of '7.2' to run. Verify that you have the minimum required version of Windows PowerShell installed, and then try again. You are trying to run this script using Windows PowerShell version" $PSVersionTable.PSVersion; 
	}

if (-not(Get-InstalledModule -Name Microsoft.graph -MinimumVersion 1.9.6)) {
	Write-host -ForegroundColor green "`nMicrosoft Grapgh PS module was not found. Installing ..."
	Install-Module microsoft.graph -scope CurrentUser -Force -AllowClobber -verbose
	}

if (-not(Get-InstalledModule -Name PSCloudPC -MinimumVersion 1.0.3)) {
	Write-host -ForegroundColor green "`nInstalling PSCloudPC PS module"
	Install-Module -Name PSCloudPC -Verbose -scope CurrentUser -Force -AllowClobber
	}

Write-host -ForegroundColor green "Importing PSCloudPC PS module"
Import-Module PSCloudPC -Verbose -Force

Write-host -ForegroundColor green "`nConnecting to Microsoft Graph API. If not authenticated already in this PowerShell session, you will be prompted for your Azure AD credentials. `n`nPlease use an account with following permissions: Group.ReadWrite.All, GroupMember.ReadWrite.All`n"

Connect-MgGraph -Scopes "Group.ReadWrite.All", "GroupMember.ReadWrite.All"

Write-host -ForegroundColor green "`nConnected Successfully to Microsoft Graph API."

Select-MgProfile v1.0

Write-host "`nFetching $group group ID..."
$GroupId = (Get-MgGroup -Filter "displayName eq '$group'").Id
Write-host "`nFound $group group ID $GroupId"

if (![string]::IsNullOrEmpty($Username) -and [string]::IsNullOrEmpty($UsersListPath)) {
	Write-host -ForegroundColor green "`nAdding $Username to $group group..."
	New-MgGroupMember -GroupId $GroupId -DirectoryObjectId (Get-MgUser -Filter "UserPrincipalName eq '$Username'").Id
	if($?) {
		Write-host -ForegroundColor green "`nSuccessfully added $Username to $group group!"
	}
	else {
		Write-host -BackgroundColor red "`nFailed to add $Username to $group group."
	}
}

if ([string]::IsNullOrEmpty($Username) -and ![string]::IsNullOrEmpty($UsersListPath)) {
	Write-host -ForegroundColor green "`nWorking in CSV list mode`n"
	$Users = Import-Csv $UsersListPath
	ForEach ($User in $Users.upn) {
			Write-host -ForegroundColor green "`nAdding $user to $group group..."
			New-MgGroupMember -GroupId $GroupId -DirectoryObjectId (Get-MgUser -Filter "UserPrincipalName eq '$user'").Id
			if($?) {
				Write-host -ForegroundColor green "Successfully added $user to $group group!"
			}
			else {
				Write-host -BackgroundColor red "`nFailed to add $user to $group group."
			}
	}
}