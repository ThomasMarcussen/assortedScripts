###################################################################################################################
# Name: Create_SCCMApplication_1.0.1.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: December,2020
###################################################################################################################

<# 
### Notes:  
RebootBehavior set to NoAction, Accepted values: BasedOnExitCode, NoAction, ForceReboot, ProgramReboot
AutoInstall $true - indicates whether a task sequence action can install the application
Added Action to Distribute the Content to the DP Group at the end

### Checklist:
- Application Name
- With a deployment type: Same application name
- Content Location
- Installation Program
- Uninstall program
- Repair Program
- Detection method (a specific MSI Product code) - SHOULD BE SET AUTOMATICALLY BY CMDLET
- User expierence: Install for system if resource is device; otherwise install for user
- Logon requirement: weather or not a user is logged on
#>


###################################################################################################################
### Load potentially required SCCM libraries
Add-Type -Path "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\Microsoft.ConfigurationManagement.ApplicationManagement.dll"
Add-Type -Path "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\Microsoft.ConfigurationManagement.ApplicationManagement.MsiInstaller.dll"
Add-Type -Path "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\Microsoft.ConfigurationManagement.ManagementProvider.dll"
Add-Type -Path "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\Microsoft.ConfigurationManagement.ApplicationManagement.Extender.dll"
Add-Type -Path "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\DcmObjectModel.dll"
Add-Type -Path "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\AdminUI.WqlQueryEngine.dll"
Add-Type -Path "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\AdminUI.AppManFoundation.dll"

###################################################################################################################
# Define Configuration Manager Properies HERE:
###################################################################################################################

$CMSiteCode = 'PS1'
$DPGroup = "All DPs"
$CMSiteServer = 'SCCM-CM001.ThomasMarcussen.com'
$CMNameSpace = "root\SMS\site_$CMSiteCode"


###################################################################################################################
# Define Application Properies HERE:
###################################################################################################################

$ApplicationName = 'My Application ver 1.0.0'
$ApplicationVersion = '1.0.0'
$ApplicationMsiPath = '\\SCCM-CM001\Sources\Software\MyApplication\1.0.0\x64\My_Application_1.0.0_x64_EN.msi'
$DeploymentName = $ApplicationName

$MsiInstallCommand = 'msiexec /i $MSICode /qn'
$MsiUninstallCommand = 'msiexec /x $MSICode /qn'
$MsiRepairCommand = 'msiexec /fuma $MSICode /qn'


###################################################################################################################
# START
###################################################################################################################
 
### Create Application
New-CMApplication -Name $ApplicationName -LocalizedApplicationName $ApplicationName -SoftwareVersion $ApplicationVersion -AutoInstall $true
$Application = Get-CMApplication -Name $ApplicationName
 
### Create Deployment Type
Add-CMMsiDeploymentType -ApplicationName $Application.LocalizedDisplayName `
  -DeploymentTypeName $DeploymentName `
  -ContentLocation $ApplicationMsiPath `
  -InstallationBehaviorType InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser`
  -InstallCommand $MsiInstallCommand`
  -UninstallCommand $MsiUnInstallCommand`
  -RepairCommand $MsiRepairCommand`
  -LogonRequirementType WhereOrNotUserLoggedOn`
  -RebootBehavior NoAction`
  -Force 

### Distribute the Content to the DP Group
Start-CMContentDistribution -ApplicationName $ApplicationName -DistributionPointGroupName $DPGroup #-Verbose

###################################################################################################################
# END
###################################################################################################################


###REF: 
# cmdlet ref: https://docs.microsoft.com/en-us/powershell/module/configurationmanager/new-cmapplication?view=sccm-ps 
# cmdelet ref: https://docs.microsoft.com/en-us/powershell/module/configurationmanager/add-cmdeploymenttype?view=sccm-ps
# https://docs.microsoft.com/en-us/powershell/module/configurationmanager/add-cmmsideploymenttype?view=sccm-ps

### EXCLUDED PART:
<# 
Add-CMDeploymentType is deprecated and only there for compatibility reasons. It's not being updated anymore.
Used instead Add-CMMsiDeploymentType cmdlets for the most part have simplified options sets and should be much easier to use and understand.
#>

<#Add-CMDeploymentType -ApplicationName $Application.LocalizedDisplayName `
  -AutoIdentifyFromInstallationFile `
  -ForceForUnknownPublisher $true `
  -InstallationFileLocation $ApplicationMsiPath `
  -InstallationBehaviorType InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser`
  -MsiInstaller `
  -DeploymentTypeName $ApplicationName
#>

<#Checklist:
- Application Name 
- With a deployment type: Same application name
- Content Location
- Installation Program
- Uninstall program
- Repair Program
- Detection method (a specific MSI Product code) - SHOULD BE SET AUTOMATICALLY BY CMDLET
- User expierence: Install for system if resource is device; otherwise install for user
- Logon requirement: weather or not a user is logged on
#>
  