###################################################################################################################
# Name: MicrosoftStoreAppUpdater.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: February,2022
###################################################################################################################

<# 
### Notes:  
This script will inititae update for Microsoft Store Apps and applications available using winget.
By default it will delete the logfile if older then 30 days.

### Checklist:
- Should run with local administrative rights or as system
### Solves the following issues:
- When deploying new computers, there might be modern apps without processed updates.
- Can also update on regular machines in use.
###
- Script is still in development
#>

function Write-log {

    [CmdletBinding()]
    Param(
          [parameter(Mandatory=$true)]
          [String]$Path,

          [parameter(Mandatory=$true)]
          [String]$Message,

          [parameter(Mandatory=$true)]
          [String]$Component,

          [Parameter(Mandatory=$true)]
          [ValidateSet("Info", "Warning", "Error")]
          [String]$Type
    )

    switch ($Type) {
        "Info" { [int]$Type = 1 }
        "Warning" { [int]$Type = 2 }
        "Error" { [int]$Type = 3 }
    }

    # Create a log entry
    $Content = "<![LOG[$Message]LOG]!>" +`
        "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " +`
        "date=`"$(Get-Date -Format "M-d-yyyy")`" " +`
        "component=`"$Component`" " +`
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
        "type=`"$Type`" " +`
        "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
        "file=`"`">"

    # Write the line to the log file
    Add-Content -Path $Path -Value $Content
}
$namespaceName = "root\cimv2\mdm\dmmap"
$className = "MDM_EnterpriseModernAppManagement_AppManagement01"
$wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
$result = $wmiObj.UpdateScanMethod()

$LogCycle = 30
$LogFilePath = Join-Path $PSScriptRoot "$(Get-Date -Format yyyy-M-dd) $($MyInvocation.MyCommand.Name).log"

Write-Warning "Delete log files older than $LogCycle days"
Get-ChildItem -Path $PSScriptRoot | Where-Object {($Now - $_.LastWriteTime).Days -gt $LogCycle -and $_.extension -eq ".log"} | Remove-Item
Write-Host "Update process has been started"
Write-Host "Following apps have updates available"
winget upgrade #Lists all apps which have updates available

$Output= winget upgrade -h --all #Apps Which are being updated and will be listed in log after the update install finishes
Write-Host "Apps which have updates available"
Write-Host $Output
try {

    throw "Updates were Succesfully installed"
	

} 
catch {

    Write-Information ($_ | Out-String) #It will write log in information when script runs as update will be started
    Write-Log -Path $LogFilePath -Message ($_ | Out-String) -Component $MyInvocation.MyCommand.Name -Type Info
}
Write-Host "Updates were installed and log file has been created"