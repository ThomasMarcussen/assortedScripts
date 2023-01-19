###################################################################################################################
# Name: Download-OD4BAccount.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: January,2023
###################################################################################################################

<#
    .Example 
    .\Download-OD4BAccount.ps1 -Username User@SampleTenantName.onmicrosoft.com -Destination "D:\OD4B" -ThreadCount 3 -Verbose
	
	Script prerequisites:
	1. Microsoft Graph PowerShell Module installed on local machine. The script automatically checks for and installs module if needed.

	2. An Azure AD user that has an admin consent to approve the following permissions in Microsoft Graph application in Azure AD apps:
	Organization.Read.All, User.Read.All, Directory.Read.All
#>

param ([Parameter(Mandatory)][string] $Username,
	[Parameter(Mandatory)][string] $Destination,
	[Parameter(Mandatory)][int] $ThreadCount
)

 function ExpandOD4BFolder {
	 Param([parameter(Mandatory = $true)] $Folder,
	[parameter(Mandatory = $true)] $FilePath
    )
	 write-host Retrieved $Folder.name folder located under $Folder.weburl -ForegroundColor green
	 $filepath = ($filepath + '/' + $folder.name)
     write-host $filePath -ForegroundColor yellow
	 $MGUserDriveItemChild = Get-MgUserDriveItemChild -UserId $Username -DriveId $MGUserDriveID -DriveItemId $Folder.Id
	 ForEach ($item in $MGUserDriveItemChild) {
		if ($item.folder.childcount -ne $null) {
			write-host $item.name is a folder
			writeFoldersReport -Folder $item
			$filepath = ""
			ExpandOD4BFolder -Folder $item -FilePath $filepath
		}
		else {
			writeFilesReport -file $item -filepath $filepath
			write-host $item.name is a file
		}
 }
 }


function writeFilesReport {
    Param(
        [parameter(Mandatory = $true)]
        $File,
        [parameter(Mandatory = $true)]
        $filepath
    )

	$filepathOnDisk = $File.parentReference.path -replace '/drives/' -replace $MGUserDriveID -replace '/root:' -replace '/','\'
    $object = [PSCustomObject]@{
        FileName     = $File.name
        path         = $filepathOnDisk
		DriveItemID  = $File.id
		Job          = $Job
    }
    $object | export-csv $Username'_OD4B_Files_Report.csv' -NoClobber -NoTypeInformation -Append
}


function writeFoldersReport {
    Param(
        [parameter(Mandatory = $true)]
        $Folder
    )

	$folderpath = $Folder.parentReference.path -replace '/drives/' -replace $MGUserDriveID -replace '/root:' -replace '/','\'
    $object = [PSCustomObject]@{
        name       = $Folder.name
        webUrl     = $Folder.webUrl
		path       = $Folder.parentReference.path
		folderPath = $folderpath
    }
    $object | export-csv $Username'_OD4B_Folders_Report.csv' -NoClobber -NoTypeInformation -Append
}


function createFolders {
    Param(
        [parameter(Mandatory = $true)]
        $OD4BFoldersReport,
        [parameter(Mandatory = $true)]
        $Destination
    )

$Folders = Import-Csv $OD4BFoldersReport

	foreach ($folderEntry in $Folders) {
		$folderName = $folderEntry.Name
		$folderPath = $folderEntry.folderpath

	 if (![string]::IsNullOrWhiteSpace($folderPath)) {
		 New-Item -Path $Destination\$folderPath -ItemType Directory -ErrorAction SilentlyContinue
		 Write-Host "SubFolder $Destination\$folderPath created" -f Yellow
	 }
	 else {
	 New-Item -Path $Destination\$folderName -ItemType Directory -ErrorAction SilentlyContinue
	 Write-Host "Root Folder $Destination\$folderName created" -f Yellow
	 }
	}
}


function createBatches {
    Param(
        [parameter(Mandatory = $true)]
        $OD4BFilesReport,
        [parameter(Mandatory = $true)]
        $ThreadCount
    )
	
	Get-ChildItem -Name batch* | Remove-Item -Force
	$Files = Import-Csv $OD4BFilesReport
	$OutputFilenamePattern = 'batch_'
	$LineLimit = [math]::Floor($Files.count / $ThreadCount)
	$line = 0
	$i = 0
	$file = 0
	$start = 0
	while ($line -le $Files.Length) {
    if ($i -eq $LineLimit -Or $line -eq $Files.Length) {
        $file++
        $Filename = "$OutputFilenamePattern$file"
        $Files[$start..($line - 1)] | export-csv $Filename'_'$Username'_OD4B_Files_Report.csv' -NoTypeInformation -Force
        $start = $line;
        $i = 0
        Write-Host "Created batch file $Filename"
		}
    $i++;
    $line++
	}

}


function downloadFiles {
    Param(
        [parameter(Mandatory = $true)]
        $Username,
		[parameter(Mandatory = $true)]
        $MGUserDriveID,
		[parameter(Mandatory = $true)]
        $Destination,
        [parameter(Mandatory = $true)]
        $ThreadCount
    )

$ScriptBlock = {
    param(
        $list = $null,
		$Destination = "D:\OD4B",
		$Username = $null,
		$MGUserDriveID = $null
    )

        foreach($fileEntry in $list) {
		$FilePath = $fileEntry.path
		$DriveItemID = $fileEntry.DriveItemID
		Get-MgUserDriveItemContent -DriveId $MGUserDriveID -UserId $Username -DriveItemId $DriveItemID -outfile "$Destination$FilePath"
		}
}

$MaxRunspaces = $ThreadCount+1
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxRunspaces)
$RunspacePool.Open()
$Jobs = New-Object System.Collections.ArrayList
$Filenames = Get-ChildItem -Name batch*

foreach ($File in $Filenames) {
	$batch = Import-Csv $File
    Write-Host "Creating runspace for $File"
    $PowerShell = [powershell]::Create()
	$PowerShell.RunspacePool = $RunspacePool
    $PowerShell.AddScript($ScriptBlock).AddParameter("list",$batch).AddParameter("Destination",$Destination).AddParameter("Username",$Username).AddParameter("MGUserDriveID",$MGUserDriveID) | Out-Null
    
    $JobObj = New-Object -TypeName PSObject -Property @{
		Runspace = $PowerShell.BeginInvoke()
		PowerShell = $PowerShell  
    }

    $Jobs.Add($JobObj) | Out-Null
}

while ($Jobs.Runspace.IsCompleted -contains $false) {
    Write-Host (Get-date).Tostring() "Still running..."
	Start-Sleep 1
}

}

$stopwatchScript =  [system.diagnostics.stopwatch]::StartNew()

if (-not(Get-InstalledModule -Name Microsoft.graph -MinimumVersion 1.9.6)) {Install-Module microsoft.graph -scope CurrentUser  -Force -AllowClobber}

Write-host "`nConnecting to Microsoft Graph API. If not authenticated already in this PowerShell session, you will be prompted for your Azure AD credentials. `n`nPlease use an account with following permissions: Organization.Read.All, User.Read.All, Directory.Read.All`n"

Connect-MgGraph -Scopes "Files.Read"

Write-host "`nConnected Successfully to Microsoft Graph API."

Select-MgProfile v1.0

Write-host "`nFetching User Drive ID"

$MGUserDriveID = (Get-MgUserDrive -UserId $Username).id

Write-host "`nUser Drive ID" $MGUserDriveID

$MGUserDriveRootChild = Get-MgUserDriveRootChild -UserId $Username -DriveId $MGUserDriveID

if (!(Test-Path $Destination)) {
  New-Item -Path $Destination -ItemType Directory
}

if (Test-Path $Username'_OD4B_Folders_Report.csv') {
  Remove-Item $Username'_OD4B_Folders_Report.csv'
}

if (Test-Path $Username'_OD4B_Files_Report.csv') {
  Remove-Item $Username'_OD4B_Files_Report.csv'
}

Write-host -ForegroundColor White -BackgroundColor Red "`nFetching OneDrive content"

$stopwatch =  [system.diagnostics.stopwatch]::StartNew()

ForEach ($item in $MGUserDriveRootChild) {
	if ($item.folder.childcount -ne $null) {
		write-host $item.name is a folder
		$filepath = ""
		writeFoldersReport -Folder $item
		ExpandOD4BFolder -Folder $item -filepath $filepath
    }
	else {
		write-host $item.name is a file
		$filepath = ""
		writeFilesReport -file $item -filepath $filepath
	}
 }
 
$stopwatch.Stop()
Write-host -ForegroundColor White -BackgroundColor Red "`nFetching OneDrive content COMPLETED at" $stopwatch.Elapsed

createFolders -OD4BFoldersReport $Username'_OD4B_Folders_Report.csv' -Destination $Destination

createBatches -OD4BFilesReport $Username'_OD4B_Files_Report.csv' -ThreadCount $ThreadCount

$stopwatch =  [system.diagnostics.stopwatch]::StartNew()

downloadFiles -Username $Username -MGUserDriveID $MGUserDriveID -Destination $Destination -ThreadCount $ThreadCount

$stopwatch.Stop()
Write-host -ForegroundColor White -BackgroundColor Red "`nDownload COMPLETED at" $stopwatch.Elapsed

$stopwatchScript.Stop()
Write-host -ForegroundColor White -BackgroundColor Green "`nScript COMPLETED at" $stopwatchScript.Elapsed