###################################################################################################################
# Name: Download-OD4BAccount.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: October 28, 2025
# Version: 1.0.3
# ---------------------------------------------------------------------------------------------------------------
# CHANGE LOG
# ---------------------------------------------------------------------------------------------------------------
# 2026-07-06
#   - Restore creation and last-modified timestamps on files and update older timestamps on directories.
#
# 2025-10-28
#   - Switch downloads to /content via Invoke-MgGraphRequest -OutputFilePath (no dependency on @microsoft.graph.downloadUrl).
#   - Full support for OneDrive "shortcuts" (remoteItem): follow remote driveId/itemId for folders and files.
#   - Paths are built from the visible OneDrive hierarchy (shortcut names included).
#   - Keep original CSV reports + multithreaded download; import Graph auth module inside worker runspaces.
#
# 2025-09-22
#   - Pagination handling, recursion path, broader scopes, batching improvements.
#
# 2023-01-xx
#   - Initial version.
# ---------------------------------------------------------------------------------------------------------------
#
# Example:
#   .\Download-OD4BAccount.ps1 -Username User@Tenant.onmicrosoft.com -Destination "D:\OD4B" -ThreadCount 3 -Verbose
#
# Prerequisites:
#   1) Microsoft Graph PowerShell Authentication module (auto-installs if missing)
#   2) Admin consent for: Organization.Read.All, User.Read.All, Directory.Read.All, Files.Read.All
###################################################################################################################

[CmdletBinding()]
param (
    [Parameter(Mandatory)] [string] $Username,
    [Parameter(Mandatory)] [string] $Destination,
    [Parameter(Mandatory)] [int]    $ThreadCount,
    [Parameter()] [switch] $RestoreTimestamps,
    [Parameter()] [string] $TenantId,
    [Parameter()] [string] $ClientId,
    [Parameter()] [string] $CertificateThumbPrint
)

# Script-scoped vars used across functions
$script:Username      = $Username
$script:UserId        = $null
$script:MGUserDriveID = $null
$GraphRoot            = '/v1.0'

$runspaceShared = [hashtable]::Synchronized(@{})

# -------------------- Minimal Graph Authentication Bootstrap --------------------
function Ensure-GraphAuth {
    [CmdletBinding()]
    param()

    try {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
    } catch {}

    if (-not (Get-PSRepository -Name 'PSGallery' -ErrorAction SilentlyContinue)) {
        Register-PSRepository -Default -ErrorAction SilentlyContinue
    }

    if (-not (Get-InstalledModule -Name Microsoft.Graph.Authentication -ErrorAction SilentlyContinue)) {
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }

    if (-not (Get-Module -Name Microsoft.Graph.Authentication -ErrorAction SilentlyContinue)) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    }
}

# -------------------- Graph helpers (Invoke-MgGraphRequest) --------------------
function Invoke-GraphGet {
    param(
        [Parameter(Mandatory)] [string] $RelativeUrl
    )
    # PSObject output makes property access reliable in PS 5.1
    Invoke-MgGraphRequest -Method GET -Uri $RelativeUrl -OutputType PSObject -ErrorAction Stop
}

function Get-GraphPaged {
    param(
        [Parameter(Mandatory)] [string] $RelativeUrl
    )
    $all = New-Object System.Collections.ArrayList
    $next = $RelativeUrl
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
        if ($resp.value) { [void]$all.AddRange($resp.value) }
        $next = $resp.'@odata.nextLink'
    }
    return $all
}

# -------------------- CSV writers --------------------
function Add-FolderRow {
    param(
        [Parameter(Mandatory)] [string] $FolderPath,
        [Parameter()] [string] $Name,
        [Parameter()] [string] $WebUrl,
		[Parameter(Mandatory)] [string] $CreatedDateTime,
		[Parameter(Mandatory)] [string] $LastModifiedDateTime
    )

    if (-not $Name) { $Name = Split-Path -Path $FolderPath -Leaf }
    [PSCustomObject]@{
        Name       = $Name
        WebUrl     = $WebUrl
        FolderPath = $FolderPath
		CreatedDateTime       = $CreatedDateTime
		LastModifiedDateTime  = $LastModifiedDateTime
    } | Export-Csv ('{0}_OD4B_Folders_Report.csv' -f $script:Username) -NoTypeInformation -Append
}

function Add-FileRow {
    param(
        [Parameter(Mandatory)] [string] $DriveId,
        [Parameter(Mandatory)] [string] $ItemId,
        [Parameter(Mandatory)] [string] $RelativePath, # includes filename
        [Parameter(Mandatory)] [string] $FileName,
		[Parameter(Mandatory)] [string] $CreatedDateTime,
		[Parameter(Mandatory)] [string] $LastModifiedDateTime
    )

    [PSCustomObject]@{
        FileName     = $FileName
        Path         = $RelativePath
        DriveItemID  = $ItemId
        DriveId      = $DriveId
		CreatedDateTime       = $CreatedDateTime
		LastModifiedDateTime  = $LastModifiedDateTime
    } | Export-Csv ('{0}_OD4B_Files_Report.csv' -f $script:Username) -NoTypeInformation -Append
}

# -------------------- Traversal (handles shortcuts/remoteItem) --------------------
function Traverse-Drive {
    param(
        [Parameter(Mandatory)] [string] $DriveId,
        [Parameter()]            [string] $ItemId,      # if empty => root
        [Parameter()]            [string] $DisplayPath  # visible path in user's OneDrive view
    )

    $select = 'id,name,size,folder,file,package,remoteItem,webUrl,parentReference,fileSystemInfo'
    $uri = if ($ItemId) {
        ('{0}/drives/{1}/items/{2}/children?$select={3}' -f $GraphRoot, $DriveId, $ItemId, $select)
    } else {
        ('{0}/drives/{1}/root/children?$select={2}' -f $GraphRoot, $DriveId, $select)
    }

    $children = Get-GraphPaged -RelativeUrl $uri
    $filesTotal = 0

    foreach ($item in $children) {
        # If this is a shortcut to a remote folder
        if ($item.folder -and $item.remoteItem -and $item.remoteItem.folder) {
            $newPath = if ($DisplayPath) { ('{0}\{1}' -f $DisplayPath, $item.name) } else { $item.name }
            Add-FolderRow -FolderPath $newPath -Name $item.name -WebUrl $item.webUrl `
				-CreatedDateTime $item.fileSystemInfo.CreatedDateTime.ToFileTimeUtc() `
				-LastModifiedDateTime $item.fileSystemInfo.LastModifiedDateTime.ToFileTimeUtc()
            $filesTotal += 1

            $remoteDriveId = $item.remoteItem.parentReference.driveId
            $remoteItemId  = $item.remoteItem.id
            if ($remoteDriveId -and $remoteItemId) {
                Traverse-Drive -DriveId $remoteDriveId -ItemId $remoteItemId -DisplayPath $newPath
            } else {
                Write-Warning ('Shortcut folder missing remote drive info: {0}' -f $item.name)
            }
            continue
        }

        # Shortcut to a remote FILE
        if ($item.file -and $item.remoteItem -and $item.remoteItem.file) {
            $relPath = if ($DisplayPath) { ('{0}\{1}' -f $DisplayPath, $item.name) } else { $item.name }
            $remoteDriveId = $item.remoteItem.parentReference.driveId
            $remoteItemId  = $item.remoteItem.id
            if ($remoteDriveId -and $remoteItemId) {
                Add-FileRow -DriveId $remoteDriveId -ItemId $remoteItemId -RelativePath $relPath -FileName $item.name `
					-CreatedDateTime $item.fileSystemInfo.CreatedDateTime.ToFileTimeUtc() `
					-LastModifiedDateTime $item.fileSystemInfo.LastModifiedDateTime.ToFileTimeUtc()
                $filesTotal += 1
            } else {
                Write-Warning ('Shortcut file missing remote drive info: {0}' -f $item.name)
            }
            continue
        }

        # Regular folder in this drive
        if ($item.folder -and -not $item.remoteItem) {
            $newPath = if ($DisplayPath) { ('{0}\{1}' -f $DisplayPath, $item.name) } else { $item.name }
            Add-FolderRow -FolderPath $newPath -Name $item.name -WebUrl $item.webUrl `
				-CreatedDateTime $item.fileSystemInfo.CreatedDateTime.ToFileTimeUtc() `
				-LastModifiedDateTime $item.fileSystemInfo.LastModifiedDateTime.ToFileTimeUtc()
            $filesTotal += 1
            Traverse-Drive -DriveId $DriveId -ItemId $item.id -DisplayPath $newPath
            continue
        }

        # Regular file in this drive
        if ($item.file -and -not $item.remoteItem) {
            $relPath = if ($DisplayPath) { ('{0}\{1}' -f $DisplayPath, $item.name) } else { $item.name }
            Add-FileRow -DriveId $DriveId -ItemId $item.id -RelativePath $relPath -FileName $item.name `
				-CreatedDateTime $item.fileSystemInfo.CreatedDateTime.ToFileTimeUtc() `
				-LastModifiedDateTime $item.fileSystemInfo.LastModifiedDateTime.ToFileTimeUtc()
            $filesTotal += 1
            continue
        }

        # Non-file things (packages, etc.)
        Write-Warning ('Skipping non-file item: {0} (id: {1})' -f $item.name, $item.id)
    }

    $runspaceShared.filesTotal += $filesTotal

}

# -------------------- Local folder & batch creation --------------------
function createFolders {
    param(
        [Parameter(Mandatory)] $OD4BFoldersReport,
        [Parameter(Mandatory)] $Destination
    )

    $Folders = Import-Csv $OD4BFoldersReport
	$UnixEpochFilesystemTime = 116444736000000000
    foreach ($folderEntry in $Folders) {
        if ([string]::IsNullOrWhiteSpace($folderEntry.FolderPath)) { continue }
        $folderInfo = [System.IO.DirectoryInfo](Join-Path $Destination $folderEntry.FolderPath)
		if (-not $folderInfo.Exists) {
			$folderItem = New-Item -Path $folderInfo.FullName -ItemType Directory
            if ($script:RestoreTimestamps) {
			    $folderItem.CreationTime  = [System.DateTime]::FromFileTimeUtc($UnixEpochFilesystemTime)
			    $folderItem.LastWriteTime = [System.DateTime]::FromFileTimeUtc($UnixEpochFilesystemTime)
            }
			Write-Host ('Folder ensured: {0}' -f $folderInfo.FullName) -ForegroundColor Cyan
		} else {
			Write-Host ('Folder pre-existed: {0}' -f $folderInfo.FullName) -ForegroundColor DarkCyan
		}
    }
}

function setFolderTime {
    param(
        [Parameter(Mandatory)] $OD4BFoldersReport,
        [Parameter(Mandatory)] $Destination
    )

    if (-not $script:RestoreTimestamps) {
        return
    }

    $Folders = Import-Csv $OD4BFoldersReport
    $UnixEpochFilesystemTime = 116444736000000000
    foreach ($folderEntry in $Folders) {
        $folderPath = $folderEntry.FolderPath
        if ([string]::IsNullOrWhiteSpace($folderPath)) { continue }
        $folderInfo = [System.IO.DirectoryInfo](Join-Path $Destination $folderPath)
		$folderItem = Get-Item -Path $folderInfo.FullName
		$creationTime = [System.DateTime]::FromFileTimeUtc($folderEntry.CreatedDateTime)
		$modifiedTime = [System.DateTime]::FromFileTimeUtc($folderEntry.LastModifiedDateTime)
        if ($folderItem.CreationTime -le $UnixEpochFilesystemTime -or $creationTime -gt $folderItem.CreationTime) {
            $folderItem.CreationTime = $creationTime
            Write-Host ('Folder creation time changed: {0}' -f $folderInfo.FullName) -ForegroundColor DarkCyan
        }
	    if ($folderItem.LastWriteTime -le $UnixEpochFilesystemTime -or $modifiedTime -gt $folderItem.LastWriteTime) {
            $folderItem.LastWriteTime = $modifiedTime
            Write-Host ('Folder modification time changed: {0}' -f $folderInfo.FullName) -ForegroundColor DarkCyan
        }
    }
}

function createBatches {
    param(
        [Parameter(Mandatory)] $OD4BFilesReport,
        [Parameter(Mandatory)] [int] $ThreadCount
    )

    Get-ChildItem -Name 'batch_*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    $Files = Import-Csv $OD4BFilesReport
    if (-not $Files -or $Files.Count -eq 0) { return }

    $OutputFilenamePattern = 'batch_'
    $LineLimit = [math]::Ceiling($Files.Count / [math]::Max(1, $ThreadCount))
    $file = 0

    for ($start = 0; $start -lt $Files.Count; $start += $LineLimit) {
        $file++
        $end = [math]::Min($start + $LineLimit - 1, $Files.Count - 1)
        $Filename = ('{0}{1}_{2}_OD4B_Files_Report.csv' -f $OutputFilenamePattern, $file, $script:Username)
        $Files[$start..$end] | Export-Csv $Filename -NoTypeInformation -Force
        Write-Host ('Created batch file {0}' -f $Filename)
    }
}

# -------------------- Downloads (multi-threaded via /content) --------------------
function downloadFiles {
    param(
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter(Mandatory)] [int]    $ThreadCount,
        [Parameter(Mandatory)] [string] $GraphRootParam
    )

    $ScriptBlock = {
        param(
            $list = $null,
            [string] $Destination,
            [string] $GraphRootParam,
            [object] $RunspaceJobState
        )

        # Ensure the auth cmdlet exists in the worker and use the existing session
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

        foreach ($fileEntry in $list) {
            $fileName    = $fileEntry.FileName
            $relative    = $fileEntry.Path
            $driveId     = $fileEntry.DriveId
            $itemId      = $fileEntry.DriveItemID

            if (-not $driveId -or -not $itemId) {
                Write-Warning ('Missing drive/item id for {0} - skipped.' -f $fileName)
                continue
            }

            $localPath = Join-Path -Path $Destination -ChildPath $relative
            $dir = Split-Path -Path $localPath -Parent
            if (-not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }

            $uri = ('{0}/drives/{1}/items/{2}/content' -f $GraphRootParam, $driveId, $itemId)
            try {
                # Streams the content to disk using your current Graph session
                Invoke-MgGraphRequest -Method GET -Uri $uri -OutputFilePath $localPath -ErrorAction Stop | Out-Null
                $fileItem = Get-Item $localPath
                if ($script:RestoreTimestamps) {
				    $fileItem.CreationTime  = [System.DateTime]::FromFileTimeUtc($fileEntry.CreatedDateTime)
				    $fileItem.LastWriteTime = [System.DateTime]::FromFileTimeUtc($fileEntry.LastModifiedDateTime)
                }
                $RunspaceJobState.filesProcessed += 1
            }
            catch {
                Write-Warning ('Failed to download {0} to {1}. {2}' -f $fileName, $localPath, $_.Exception.Message)
            }
        }
    }

    $MaxRunspaces = [math]::Max(1, $ThreadCount)
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces)
    $RunspacePool.Open()
    $Jobs = New-Object System.Collections.ArrayList
    $Filenames = Get-ChildItem -Name ('batch_*_{0}_OD4B_Files_Report.csv' -f $script:Username)

    foreach ($File in $Filenames) {
        $batch = Import-Csv $File
        Write-Host ('Creating runspace for {0}' -f $File)
        $PowerShell = [PowerShell]::Create()
        $PowerShell.RunspacePool = $RunspacePool
        $null = $PowerShell.AddScript($ScriptBlock).
            AddParameter('list', $batch).
            AddParameter('Destination', $Destination).
            AddParameter('GraphRootParam', $GraphRootParam).
            AddParameter('RunspaceJobState', $runspaceShared)

        $JobObj = [PSCustomObject]@{
            Runspace   = $PowerShell.BeginInvoke()
            PowerShell = $PowerShell
        }
        $Jobs.Add($JobObj) | Out-Null
    }

    while ($Jobs.Runspace.IsCompleted -contains $false) {
        Write-Progress -Activity "Processing OD4B Account" `
		    -Status "Restoring files" -CurrentOperation ("Downloading {0} of {1} files" -f ($runspaceShared.filesProcessed+1),$runspaceShared.filesTotal)  `
			-PercentComplete ([math]::Min($runspaceShared.filesProcessed, $runspaceShared.filesTotal)/$runspaceShared.filesTotal*100)
        Start-Sleep 1
    }

    foreach ($job in $Jobs) {
        try { $job.PowerShell.EndInvoke($job.Runspace) } catch {}
        finally { $job.PowerShell.Dispose() }
    }
    $RunspacePool.Close()
    $RunspacePool.Dispose()
}

# -------------------- Main --------------------

$stopwatchScript = [System.Diagnostics.Stopwatch]::StartNew()

Ensure-GraphAuth

Write-Host "`nConnecting to Microsoft Graph API..."
$requiredScopes = @('Files.Read.All', 'User.Read.All', 'Directory.Read.All')
if (-not [string]::IsNullOrWhiteSpace($script:CertificateThumbPrint)) {
    Connect-MgGraph -NoWelcome `
			-TenantId $script:TenantId -ClientId $script:ClientId `
			-CertificateThumbPrint $script:CertificateThumbPrint
} else {
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
}
Write-Host -ForegroundColor Green 'Connected successfully.'


# Optional: warn if scopes missing
try {
    $ctx = Get-MgContext
    $missing = $requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
    if ($missing) { Write-Warning ('Missing scopes: {0}. Admin consent may be required.' -f ($missing -join ', ')) }
} catch {
    Write-Verbose 'Get-MgContext unavailable; continuing.' -Verbose
}

# Resolve user and drive
Write-Host "`nResolving user and drive via Graph..."
try {
    $user = Invoke-GraphGet -RelativeUrl ('{0}/users/{1}?$select=id,userPrincipalName' -f $GraphRoot, $Username)
    $script:UserId = $user.id
} catch {
    throw ('Failed to resolve user {0}. {1}' -f $Username, $_.Exception.Message)
}

try {
    $drive = Invoke-GraphGet -RelativeUrl ('{0}/users/{1}/drive?$select=id' -f $GraphRoot, $script:UserId)
    $script:MGUserDriveID = $drive.id
} catch {
    throw ('Failed to resolve OneDrive for user {0}. If the user never opened OneDrive, it may not be provisioned.' -f $Username)
}

Write-Host ('User ID: {0}' -f $script:UserId)
Write-Host ('Drive ID: {0}' -f $script:MGUserDriveID)

$runspaceShared.filesProcessed = 0
$runspaceShared.filesTotal = 0

# Prepare destination and reports
if (-not (Test-Path -LiteralPath $Destination)) {
    New-Item -Path $Destination -ItemType Directory | Out-Null
}

$foldersReport = ('{0}_OD4B_Folders_Report.csv' -f $Username)
$filesReport   = ('{0}_OD4B_Files_Report.csv'   -f $Username)
foreach ($rep in @($foldersReport, $filesReport)) {
    if (Test-Path $rep) { Remove-Item $rep -Force }
}

# Enumerate OneDrive content (root -> recurse); handles remoteItem
Write-Host -ForegroundColor Green "`nFetching OneDrive content (this may take a while)..."
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Traverse-Drive -DriveId $script:MGUserDriveID -ItemId $null -DisplayPath ''

$stopwatch.Stop()
Write-Host -ForegroundColor Green ("`nFetching OneDrive content COMPLETED in {0}" -f $stopwatch.Elapsed)

# Recreate folder tree locally and split into batches for parallel downloads
createFolders -OD4BFoldersReport $foldersReport -Destination $Destination
createBatches -OD4BFilesReport   $filesReport   -ThreadCount $ThreadCount

# Download phase (parallel via /content)
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
downloadFiles -Destination $Destination -ThreadCount $ThreadCount -GraphRootParam $GraphRoot
$stopwatch.Stop()
Write-Host -ForegroundColor Green ("`nDownload COMPLETED in {0}" -f $stopwatch.Elapsed)

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
setFolderTime -OD4BFoldersReport $foldersReport -Destination $Destination
$stopwatch.Stop()
Write-Host -ForegroundColor Green ("`nFolders UPDATED in {0}" -f $stopwatch.Elapsed)

$stopwatchScript.Stop()
Write-Host -ForegroundColor Blue ("`nScript COMPLETED in {0}" -f $stopwatchScript.Elapsed)
