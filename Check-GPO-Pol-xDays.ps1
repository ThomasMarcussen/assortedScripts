###################################################################################################################
# Name: Check-GPO-Pol-xDays.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: January,2022
###################################################################################################################

<# 
### Notes:  
This script will check if the GroupPolicy pol file has been updated on Windows Client.
If the Pol file has not been modified within the configured amount of days, it will be deleted (default is 30)

### Checklist:
- Should run with local administrative rights or as system
- Log file is configured to C:\Windows\Logs

### Solves the following issues:
- Stale group policy on clint maskines
- If you set a group policy object to enabled but then delete the ADM or ADMX/L files, the registry settings persist and there is no way to disable them permanently. 
  Deleting the policy registry keys is helpful in the short term but they get re-applied each time you restart your computer or run "gpupdate /force".
#>

$LastModifiedDays = 30
$FileLocation = "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"
$LogFileLocation = "C:\Windows\Logs\Check-GPO-Pol-${LastModifiedDays}-Days.log"
$Date = Get-Date
$registryFileStatus = Test-Path -Path $FileLocation -PathType Leaf

#User define function for re-useability
function Get-RegistryFileStatus-AndLog{
	[CmdletBinding()]
	Param(
		[parameter(Mandatory=$true)]
		[String]$Message,
	
		[parameter(Mandatory=$true)]
		[String]$Component,

		[Parameter(Mandatory=$true)]
		[ValidateSet("Info","Warning","Error")]
		[String]$Type

)


	switch($Type){
		"Info"{ [int]$Type = 1}
		"Warning"{ [int]$Type = 2}
		"Error"{[int]$Type = 3}
	}

		$Time = (Get-Date -Format "HH':'mm':'ss.ffffff")
		$Date =(Get-Date -Format "MM-dd-yyyy")

	 $Content = "<![LOG[$Message]LOG]!>" +`
        "<time=`"$Time`" " +`
        "date=`"$Date`" " +`
        "component=`"$Component`" " +`
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
        "type=`"$Type`" " +`
        "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
        "file=`"$LogFileLocation`">"

    
     $Content | Out-File -Append -Encoding UTF8 -FilePath $LogFileLocation
}

if($registryFileStatus){
	$writeDateTime = (Get-Item $FileLocation).LastWriteTime
	$diff = New-TimeSpan -Start $writeDateTime -End $Date
	#Checking if lof file exists. If exists then append date to it else create new and append
	$ifLogFileExists = Test-Path -Path $LogFileLocation -PathType Leaf
	if($diff.days -gt $LastModifiedDays){
		Write-Output("Its been modified more than " + $LastModifiedDays + "days ago")
		#Delete this registry.pol file
		Remove-Item $FileLocation -Force
		$registryFileStatus = Test-Path -Path $FileLocation -PathType Leaf
		if($registryFileStatus){
				$registryFileStatus = 'exists'
		}
			else{
				$registryFileStatus = 'removed'
		}
			$txt = "Registry File Status:(" + $registryFileStatus + "("
			Get-RegistryFileStatus-AndLog -Message $txt -Component $MyInvocation.MyCommand.Name -Type "Info"
		}
		else {
		$registryFileStatus = Test-Path -Path $FileLocation -PathType Leaf
		if ($registryFileStatus) {
			$registryFileStatus = 'exists'
		} else {
			$registryFileStatus = 'removed'
		}
		$txt = "Registry File Status: (" + $registryFileStatus + ")"
		Get-RegistryFileStatus-AndLog -Message $txt -Component $MyInvocation.MyCommand.Name -Type "Info"
		Write-Output("Its been modified within " + $LastModifiedDays + " days")
	}
}
else {
	Write-Output("Please make sure this file exists at " + $FileLocation + ".")
}
