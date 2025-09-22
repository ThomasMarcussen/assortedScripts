###################################################################################################################
# Name: Download-OD4BAccount.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: September, 2025
# Version: 1.0.2
# ---------------------------------------------------------------------------------------------------------------
# CHANGE LOG
# ---------------------------------------------------------------------------------------------------------------
# 2025-09-22 (Latest Update)
#   - Added "-All" parameter to:
#       • Get-MgUserDriveRootChild
#       • Get-MgUserDriveItemChild
#     to ensure all items are retrieved (fixes missing files in large folders).
#   - Fixed folder traversal:
#       • Previously $FilePath was reset inside recursion; now path is correctly accumulated.
#   - Updated Microsoft Graph connection:
#       • Changed Connect-MgGraph scopes from "Files.Read" to "Files.Read.All","User.Read.All","Directory.Read.All"
#         for proper cross-user OneDrive access.
#   - Removed undefined $Job variable from writeFilesReport to avoid runtime errors.
#   - Improved batching:
#       • Switched to [math]::Ceiling for batch calculation and added guard against division by zero.
#   - Ensured destination directories are created before downloading files.
#   - Minor code clean-up, improved comments, and standardized formatting.
#
# 2023-01-xx (Original)
#   - Initial version of the script.
# ---------------------------------------------------------------------------------------------------------------
#
# Example:
#   .\Download-OD4BAccount.ps1 -Username User@SampleTenantName.onmicrosoft.com -Destination "D:\OD4B" -ThreadCount 3 -Verbose
#
# Script prerequisites:
#   1. Microsoft Graph PowerShell Module installed on local machine. The script automatically checks for and installs module if needed.
#
#   2. An Azure AD user that has an admin consent to approve the following permissions in Microsoft Graph:
#      Organization.Read.All, User.Read.All, Directory.Read.All, Files.Read.All
###################################################################################################################

param (
    [Parameter(Mandatory)][string] $Username,
    [Parameter(Mandatory)][string] $Destination,
    [Parameter(Mandatory)][int]    $ThreadCount
)

function ExpandOD4BFolder {
    param(
        [parameter(Mandatory=$true)] $Folder,
        [parameter(Mandatory=$true)] [string] $FilePath
    )

    Write-Host "Retrieved '$($Folder.name)' folder under $($Folder.webUrl)" -ForegroundColor Green
    $currentPath = ($FilePath.TrimEnd('/')) + '/' + $Folder.name
    Write-Host $currentPath -ForegroundColor Yellow

    # Ensure we fetch ALL children (handles pagination)
    $MGUserDriveItemChild = Get-MgUserDriveItemChild -UserId $Username -DriveId $MGUserDriveID -DriveItemId $Folder.Id -All

    foreach ($item in $MGUserDriveItemChild) {
        if ($null -ne $item.folder -and $null -ne $item.folder.childcount) {
            Write-Host "'$($item.name)' is a folder"
            writeFoldersReport -Folder $item
            ExpandOD4BFolder -Folder $item -FilePath $currentPath
        }
        else {
            Write-Host "'$($item.name)' is a file"
            writeFilesReport -File $item -FilePath $currentPath
        }
    }
}

function writeFilesReport {
    param(
        [parameter(Mandatory=$true)] $File,
        [parameter(Mandatory=$true)] [string] $FilePath
    )

    $filepathOnDisk = $File.parentReference.path `
        -replace '/drives/' -replace $MGUserDriveID `
        -replace '/root:' `
        -replace '/', '\'

    $object = [PSCustomObject]@{
        FileName    = $File.name
        Path        = $filepathOnDisk
        DriveItemID = $File.id
    }

    $object | Export-Csv "$($Username)_OD4B_Files_Report.csv" -NoTypeInformation -Append
}

function writeFoldersReport {
    param(
        [parameter(Mandatory=$true)] $Folder
    )

    $folderpath = $Folder.parentReference.path `
        -replace '/drives/' -replace $MGUserDriveID `
        -replace '/root:' `
        -replace '/', '\'

    $object = [PSCustomObject]@{
        Name       = $Folder.name
        WebUrl     = $Folder.webUrl
        Path       = $Folder.parentReference.path
        FolderPath = $folderpath
    }

    $object | Export-Csv "$($Username)_OD4B_Folders_Report.csv" -NoTypeInformation -Append
}

function createFolders {
    param(
        [parameter(Mandatory=$true)] $OD4BFoldersReport,
        [parameter(Mandatory=$true)] $Destination
    )

    $Folders = Import-Csv $OD4BFoldersReport
    foreach ($folderEntry in $Folders) {
        $folderName = $folderEntry.Name
        $folderPath = $folderEntry.FolderPath

        if (![string]::IsNullOrWhiteSpace($folderPath)) {
            New-Item -Path (Join-Path $Destination $folderPath) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            Write-Host "SubFolder $(Join-Path $Destination $folderPath) created" -ForegroundColor Yellow
        }
        else {
            New-Item -Path (Join-Path $Destination $folderName) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Root Folder $(Join-Path $Destination $folderName) created" -ForegroundColor Yellow
        }
    }
}

function createBatches {
    param(
        [parameter(Mandatory=$true)] $OD4BFilesReport,
        [parameter(Mandatory=$true)] [int] $ThreadCount
    )

    Get-ChildItem -Name "batch_*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    $Files = Import-Csv $OD4BFilesReport
    if (-not $Files -or $Files.Count -eq 0) { return }

    $OutputFilenamePattern = 'batch_'
    $LineLimit = [math]::Ceiling($Files.Count / [math]::Max(1,$ThreadCount))
    $file = 0

    for ($start = 0; $start -lt $Files.Count; $start += $LineLimit) {
        $file++
        $end = [math]::Min($start + $LineLimit - 1, $Files.Count - 1)
        $Filename = "$OutputFilenamePattern$file" + "_${Username}_OD4B_Files_Report.csv"
        $Files[$start..$end] | Export-Csv $Filename -NoTypeInformation -Force
        Write-Host "Created batch file $Filename"
    }
}

function downloadFiles {
    param(
        [parameter(Mandatory=$true)] $Username,
        [parameter(Mandatory=$true)] $MGUserDriveID,
        [parameter(Mandatory=$true)] $Destination,
        [parameter(Mandatory=$true)] [int] $ThreadCount
    )

    $ScriptBlock = {
        param(
            $list = $null,
            $Destination = "D:\OD4B",
            $Username = $null,
            $MGUserDriveID = $null
        )

        foreach ($fileEntry in $list) {
            $FilePath    = $fileEntry.Path
            $DriveItemID = $fileEntry.DriveItemID
            $outFile     = "$Destination$FilePath"

            $dir = Split-Path -Path $outFile -Parent
            if (-not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }

            try {
                Get-MgUserDriveItemContent -DriveId $MGUserDriveID -UserId $Username -DriveItemId $DriveItemID -OutFile $outFile -ErrorAction Stop
            }
            catch {
                Write-Warning "Failed to download $($fileEntry.FileName) to $outFile. $_"
            }
        }
    }

    $MaxRunspaces = [math]::Max(1, $ThreadCount)
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces)
    $RunspacePool.Open()
    $Jobs = New-Object System.Collections.ArrayList
    $Filenames = Get-ChildItem -Name "batch_*_${Username}_OD4B_Files_Report.csv"

    foreach ($File in $Filenames) {
        $batch = Import-Csv $File
        Write-Host "Creating runspace for $File"
        $PowerShell = [PowerShell]::Create()
        $PowerShell.RunspacePool = $RunspacePool
        $null = $PowerShell.AddScript($ScriptBlock).AddParameter("list",$batch).AddParameter("Destination",$Destination).AddParameter("Username",$Username).AddParameter("MGUserDriveID",$MGUserDriveID)

        $JobObj = [PSCustomObject]@{
            Runspace   = $PowerShell.BeginInvoke()
            PowerShell = $PowerShell
        }
        $Jobs.Add($JobObj) | Out-Null
    }

    while ($Jobs.Runspace.IsCompleted -contains $false) {
        Write-Host (Get-Date).ToString() "Still running..."
        Start-Sleep 1
    }
}

# -------------------- Main --------------------

$stopwatchScript = [System.Diagnostics.Stopwatch]::StartNew()

if (-not (Get-InstalledModule -Name Microsoft.Graph -MinimumVersion 1.9.6 -ErrorAction SilentlyContinue)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
}

Write-Host "`nConnecting to Microsoft Graph API..."
Connect-MgGraph -Scopes "Files.Read.All","User.Read.All","Directory.Read.All"
Write-Host "Connected successfully."
Select-MgProfile v1.0

Write-Host "`nFetching User Drive ID..."
$MGUserDriveID = (Get-MgUserDrive -UserId $Username).Id
Write-Host "User Drive ID: $MGUserDriveID"

if (!(Test-Path -LiteralPath $Destination)) {
    New-Item -Path $Destination -ItemType Directory | Out-Null
}

$foldersReport = "$($Username)_OD4B_Folders_Report.csv"
$filesReport   = "$($Username)_OD4B_Files_Report.csv"
if (Test-Path $foldersReport) { Remove-Item $foldersReport -Force }
if (Test-Path $filesReport)   { Remove-Item $filesReport   -Force }

Write-Host -ForegroundColor White -BackgroundColor Red "`nFetching OneDrive content (this may take a while)..."
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

$MGUserDriveRootChild = Get-MgUserDriveRootChild -UserId $Username -DriveId $MGUserDriveID -All

foreach ($item in $MGUserDriveRootChild) {
    if ($null -ne $item.folder -and $null -ne $item.folder.childcount) {
        Write-Host "'$($item.name)' is a folder"
        writeFoldersReport -Folder $item
        ExpandOD4BFolder -Folder $item -FilePath ""
    }
    else {
        Write-Host "'$($item.name)' is a file"
        writeFilesReport -File $item -FilePath ""
    }
}

$stopwatch.Stop()
Write-Host -ForegroundColor White -BackgroundColor Red ("`nFetching OneDrive content COMPLETED in {0}" -f $stopwatch.Elapsed)

createFolders -OD4BFoldersReport $foldersReport -Destination $Destination
createBatches -OD4BFilesReport $filesReport -ThreadCount $ThreadCount

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
downloadFiles -Username $Username -MGUserDriveID $MGUserDriveID -Destination $Destination -ThreadCount $ThreadCount
$stopwatch.Stop()
Write-Host -ForegroundColor White -BackgroundColor Red ("`nDownload COMPLETED in {0}" -f $stopwatch.Elapsed)

$stopwatchScript.Stop()
Write-Host -ForegroundColor White -BackgroundColor Green ("`nScript COMPLETED in {0}" -f $stopwatchScript.Elapsed)
