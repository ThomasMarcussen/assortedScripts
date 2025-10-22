<#
.SYNOPSIS
    Repairs and triggers Microsoft Intune MDM auto-enrollment on Windows devices.

.DESCRIPTION
    Automates troubleshooting and remediation of Windows auto-enrollment issues for Microsoft Intune.
    The script detects and fixes common blockers such as:
      - Time synchronization and TLS configuration issues
      - Conditional Access or MFA enrollment restrictions
      - Stale Workspace ONE or third-party MDM enrollment artifacts
      - Hybrid Azure AD Join drift (DomainJoined but not AzureADJoined)
    It then triggers MDM enrollment using user credentials first, falling back to device credentials if needed.
    All actions and results are logged to: 
        C:\Windows\Logs\MDM-Enrollment-<COMPUTERNAME>.log

.AUTHOR
    Written by: Thomas Marcussen, Thomas@ThomasMarcussen.com
    Maintainer: Thomas Marcussen
    Date: 2025-10-22
    Contact: info@circleofbytes.com
    Company: Circle of Bytes - Modern Endpoint Management & Microsoft 365 Consultancy
    Website: https://www.circleofbytes.com

.VERSION
    1.0.2

.CHANGE LOG
    [1.0.2] - 2025-10-22
        • Added full author metadata
        • Replaced all non-ASCII characters and removed smart punctuation (PS5 parser safe)
        • Cleaned up string formatting (-f usage); removed parentheses inside format strings
        • Improved resilience of logging to handle locked or read-only files
        • Clarified execution flow for User and Device credential enrollment modes
        • Added clearer console and log messages for each major step
        • Simplified task creation fallback to schtasks.exe for better legacy OS support
        • Verified compatibility with PowerShell 5.1 on Windows 10 / Windows 11
        • Added consistent line spacing and section headers for readability

    [1.0.1] - 2025-10
        • Introduced unified logging function (Write-Log) with retry and encoding protection
        • Added central logging directory under C:\Windows\Logs
        • Improved error resilience in Add-Content (auto-retry 3x)
        • Refined event polling to correctly capture IDs 75, 76, and 77 from DM-EDP\Admin
        • Introduced simplified logic for mode retry loops (User, then Device)
        • Enhanced service validation for dmwappushservice and tiledatamodelsvc
        • Added robust network endpoint testing with Test-NetConnection
        • Updated endpoint list to use current Microsoft Intune / Entra URLs only
          (Removed deprecated deviceenrollment.microsoft.com)

    [1.0.0] - 2025-10
        • Initial stable release of Intune Auto-Enrollment Repair utility
        • Created functions to repair policy keys and force Auto MDM Enrollment
        • Implemented detection for missing MDM scheduled task
        • Added Workspace ONE / VMware enrollment cleanup logic
        • Implemented AAD re-registration via dsregcmd /leave and /join
        • Added TLS 1.2 enforcement for secure communication with Microsoft endpoints
        • Introduced event log monitoring for enrollment progress and result codes
        • Implemented heuristic for 0x8018002A Conditional Access / MFA block detection
        • Added time synchronization logic with NTP validation and logging
        • Designed for use in hybrid-joined, enterprise-managed environments

.NOTES
    Requirements:
      - Run as Administrator
      - Internet connectivity to Microsoft Intune and Entra ID endpoints
      - PowerShell 5.1 or later (Windows 10 / 11)
      - Device must be Hybrid Azure AD Joined or Azure AD Joined
      - Not compatible with non-domain joined / workgroup devices

    Tested Environments:
      - Windows 10 22H2 (Hybrid Joined)
      - Windows 11 23H2 (Hybrid Joined)
      - Devices previously enrolled in VMware Workspace ONE, then enterprise wiped

    Output:
      - Log file created in: C:\Windows\Logs\MDM-Enrollment-<COMPUTERNAME>.log
      - Enrollment diagnostics: Event Viewer → Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider\Admin
#>

param(
  [int]$WaitEventsSec = 60,
  [int]$MaxRetries    = 1,
  [string]$NtpPeers   = "pool.ntp.org"
)

# ---------------- Logging setup ----------------
$LogRoot = 'C:\Windows\Logs'
if (-not (Test-Path $LogRoot)) {
    try {
        New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
    } catch {
        Write-Host ("WARNING: Failed to create {0} - falling back to script directory." -f $LogRoot)
        $LogRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
    }
}

$LogFile = Join-Path $LogRoot ("MDM-Enrollment-{0}.log" -f $env:COMPUTERNAME)
New-Item -Path $LogFile -ItemType File -Force | Out-Null

function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToString('u')
    $line = "[{0}] {1}" -f $ts, $Message
    Write-Host $line
    for ($i=0; $i -lt 3; $i++) {
        try {
            Add-Content -Path $LogFile -Value $line -Encoding UTF8
            break
        } catch {
            Start-Sleep -Milliseconds 150
            if ($i -eq 2) {
                Write-Host ("WARN: failed to write to {0}: {1}" -f $LogFile, $_.Exception.Message)
            }
        }
    }
}
Write-Log "===== Intune Auto-Enrollment - Hardened - Extended Forensics and Cleanup ====="

# ---------------- Constants ----------------
$RegPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM'
$TaskPath = '\Microsoft\Windows\EnterpriseMgmt\'
$TaskName = 'Auto MDM Enrollment with AAD Token'
$TaskFull = "$TaskPath$TaskName"
$Exe      = Join-Path $env:WINDIR 'System32\deviceenroller.exe'
$EnrollArgs = '/c /AutoEnrollMDM'

# Current enrollment/auth endpoints to probe (TCP 443)
$Endpoints = @(
  'EnterpriseEnrollment.manage.microsoft.com',
  'EnterpriseEnrollment-s.manage.microsoft.com',
  'manage.microsoft.com',
  'enterpriseregistration.windows.net',
  'login.microsoftonline.com',
  'device.login.microsoftonline.com'
)

# --- Utility: create policy keys ---
function Ensure-PolicyKeys([ValidateSet('User','Device')]$Mode){
  if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
  New-ItemProperty -Path $RegPath -Name 'AutoEnrollMDM' -Value 1 -PropertyType DWord -Force | Out-Null
  $val = if ($Mode -eq 'User') { 1 } else { 0 }
  New-ItemProperty -Path $RegPath -Name 'UseAADCredentialType' -Value $val -PropertyType DWord -Force | Out-Null
  Write-Log ("Policy keys set. AutoEnrollMDM={0} UseAADCredentialType={1} Mode: {2}" -f 1, $val, $Mode)
}

# --- Task management ---
function Test-EnrollmentTask {
  try { Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null; return $true }
  catch { return $false }
}

function New-EnrollmentTask {
  Write-Log ("Creating scheduled task {0} ..." -f $TaskFull)
  try {
    $action    = New-ScheduledTaskAction -Execute $Exe -Argument $EnrollArgs
    $triggers  = @( New-ScheduledTaskTrigger -AtStartup ; New-ScheduledTaskTrigger -AtLogOn )
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
    return $true
  } catch {
    Write-Log ("Register-ScheduledTask failed: {0}. Falling back to schtasks." -f $_.Exception.Message)
    schtasks /Delete /TN $TaskFull /F 2>$null | Out-Null
    $cmd = @('/Create','/TN',$TaskFull,'/SC','ONLOGON','/TR',('"' + $Exe + '" ' + $EnrollArgs),'/RL','HIGHEST','/RU','SYSTEM','/F')
    $p = Start-Process -FilePath schtasks.exe -ArgumentList $cmd -Wait -PassThru -NoNewWindow
    return ($p.ExitCode -eq 0)
  }
}

function Start-EnrollmentTaskAndDirect {
  if (Test-EnrollmentTask) {
    Write-Log ("Starting scheduled task: {0}" -f $TaskFull)
    schtasks /run /tn $TaskFull | Out-Null
  } elseif (New-EnrollmentTask) {
    Write-Log "Task created; starting now."
    schtasks /run /tn $TaskFull | Out-Null
  } else {
    Write-Log "WARNING: Could not create or start the scheduled task."
  }
  if (Test-Path $Exe) {
    Write-Log "Starting deviceenroller.exe directly."
    Start-Process -FilePath $Exe -ArgumentList $EnrollArgs -WindowStyle Hidden | Out-Null
  }
}

# --- Enrollment wait / feedback ---
function Wait-ForEnrollmentResult([int]$Seconds){
  $start = Get-Date
  $deadline = $start.AddSeconds($Seconds)
  Write-Log ("Waiting up to {0} seconds for DM-EDP\Admin events (75,76,77)..." -f $Seconds)
  do {
    $events = Get-WinEvent -FilterHashtable @{
      LogName='Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
      StartTime=$start } -MaxEvents 400 -ErrorAction SilentlyContinue |
      Where-Object { $_.Id -in 75,76,77 } |
      Sort-Object TimeCreated -Descending
    if ($events) {
      $succ = $events | Where-Object { $_.Id -eq 76 } | Select-Object -First 1
      if ($succ) {
        Write-Log ("Enrollment SUCCESS: {0}" -f $succ.Message)
        return @{Status='Success'}
      }
      $fail = $events | Where-Object { $_.Id -eq 77 } | Select-Object -First 1
      if ($fail) {
        $code = $null
        if ($fail.Message -match '(0x[0-9A-Fa-f]{6,})'){ $code=$matches[1] }
        $codeOut = if ($code) { $code } else { '-' }
        Write-Log ("Enrollment FAILURE code {0}. Detail: {1}" -f $codeOut, $fail.Message)
        return @{Status='Failure'; Code=$code}
      }
    }
    Start-Sleep -Seconds 2
  } while ((Get-Date) -lt $deadline)
  Write-Log "No enrollment events found in allotted time."
  return @{Status='NoEvents'}
}

function Show-TaskState {
  try {
    $ti = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    $hex = ('0x{0:X8}' -f $ti.LastTaskResult)
    Write-Log ("Task LastResult {0} Hex {1}" -f $ti.LastTaskResult, $hex)
  } catch { Write-Log "Task info unavailable." }
}

function Retry-Mode([string]$Mode){
  $attempt=0
  $lastCode=$null
  do {
    $attempt++
    Write-Log ("--- Attempt {0} Mode {1} ---" -f $attempt, $Mode)
    Ensure-PolicyKeys -Mode $Mode
    gpupdate /force | Out-Null
    Start-EnrollmentTaskAndDirect
    $res = Wait-ForEnrollmentResult -Seconds $WaitEventsSec
    Show-TaskState
    if ($res.Status -eq 'Success'){ return @{Success=$true} }
    if ($res.Code){ $lastCode=$res.Code }
    if ($attempt -le $MaxRetries){ Write-Log "Retrying after short delay..."; Start-Sleep -Seconds 5 }
  } while ($attempt -le $MaxRetries)
  return @{Success=$false; Code=$lastCode}
}

# --- Environment repair helpers ---
function Ensure-Services {
  foreach ($s in @('dmwappushservice','tiledatamodelsvc')){
    try {
      $svc = Get-Service $s -ErrorAction Stop
      if ($svc.StartType -eq 'Disabled'){ Set-Service $s -StartupType Automatic }
      if ($svc.Status -ne 'Running'){ Start-Service $s }
      Write-Log ("Service {0} OK" -f $s)
    } catch { Write-Log ("Service {0} not present - OK" -f $s) }
  }
}

function Ensure-TLS12-Enabled {
  $base='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2'
  New-Item "$base\Client" -Force | Out-Null
  New-Item "$base\Server" -Force | Out-Null
  New-ItemProperty "$base\Client" Enabled -Value 1 -Type DWord -Force | Out-Null
  New-ItemProperty "$base\Client" DisabledByDefault -Value 0 -Type DWord -Force | Out-Null
  New-ItemProperty "$base\Server" Enabled -Value 1 -Type DWord -Force | Out-Null
  New-ItemProperty "$base\Server" DisabledByDefault -Value 0 -Type DWord -Force | Out-Null
  Write-Log "TLS 1.2 ensured enabled."
}

function Check-TimeSync {
  try {
    Write-Log ("Checking and syncing system time via NTP: {0}" -f $NtpPeers)
    w32tm /config /manualpeerlist:$NtpPeers /syncfromflags:manual /update | Out-Null
    net stop w32time | Out-Null
    net start w32time | Out-Null
    w32tm /resync /force | Out-Null
    $s=(w32tm /query /status) -join ' '
    Write-Log ("Time status: {0}" -f $s)
  } catch { Write-Log ("Time sync error: {0}" -f $_.Exception.Message) }
}

function Test-Network {
  Write-Log "Probing network endpoints on TCP 443..."
  foreach ($h in $Endpoints){
    try {
      $r=Test-NetConnection -ComputerName $h -Port 443 -WarningAction SilentlyContinue
      Write-Log (" - {0,-45} : {1}" -f $h,[bool]$r.TcpTestSucceeded)
    } catch { Write-Log (" - {0} : ERROR {1}" -f $h,$_.Exception.Message) }
  }
}

function Should-ReRegisterAAD {
  $out=(dsregcmd /status) -join "`r`n"
  $dj=($out -match 'DomainJoined\s*:\s*YES')
  $aad=($out -match 'AzureAdJoined\s*:\s*YES')
  return ($dj -and -not $aad)
}
function AAD-ReRegister {
  Write-Log "Performing dsregcmd leave then join."
  try { dsregcmd /leave | Out-Null; Start-Sleep 3; dsregcmd /join | Out-Null; Write-Log "AAD re-registration complete." }
  catch { Write-Log ("dsregcmd error: {0}" -f $_.Exception.Message) }
}

# --- Cleanup WS1 / stale enrollments ---
function Cleanup-WorkspaceOne {
  Write-Log "Cleaning stale enrollment artifacts."
  $BackupDir=Join-Path $LogRoot ("MDM-Backup-{0:yyyyMMddHHmmss}" -f (Get-Date))
  New-Item $BackupDir -ItemType Directory -Force | Out-Null
  foreach ($root in @(
    'HKLM:\SOFTWARE\Microsoft\Enrollments',
    'HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked',
    'HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement'
  )){
    if (Test-Path $root){
      reg export ($root -replace 'HKEY_LOCAL_MACHINE','HKLM') (Join-Path $BackupDir ((Split-Path $root -Leaf)+'.reg')) /y | Out-Null
      Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
      Write-Log ("Removed {0}. Backup at {1}" -f $root,$BackupDir)
    }
  }
  try {
    $store=New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
    $store.Open('ReadWrite')
    $store.Certificates | Where-Object { $_.Subject -like "*MS-Organization*" } | ForEach-Object {
      Write-Log ("Removing cert: {0}" -f $_.Subject); $store.Remove($_)
    }
    $store.Close()
  } catch { Write-Log ("Cert cleanup error: {0}" -f $_.Exception.Message) }
  Write-Log "Cleanup complete."
}

# --- CA/MFA heuristic ---
function Heuristic-Flag-CA($userCode,$devCode,[bool]$eventsPresent){
  if ((-not $eventsPresent) -and (($userCode -eq '0x8018002a') -or ($devCode -eq '0x8018002a'))){
    Write-Log "LIKELY BLOCKER: Conditional Access or MFA requiring interaction (0x8018002A)."
    Write-Log "ACTION: Exclude Microsoft Intune and Microsoft Intune Enrollment apps from MFA during enrollment."
  }
}

# ------------------- EXECUTION -------------------
Ensure-Services
Ensure-TLS12-Enabled
Check-TimeSync
if (Should-ReRegisterAAD){ AAD-ReRegister }
Test-Network
Cleanup-WorkspaceOne

Write-Log "Starting enrollment attempts..."
$u=Retry-Mode -Mode 'User'
if ($u.Success){
  Write-Log "Enrollment succeeded using USER credentials."
  Write-Host ("`nLog saved to {0}" -f $LogFile)
  exit 0
}

$d=Retry-Mode -Mode 'Device'
if ($d.Success){
  Write-Log "Enrollment succeeded using DEVICE credentials."
  Write-Host ("`nLog saved to {0}" -f $LogFile)
  exit 0
}

Write-Log "Enrollment failed in both modes."
$eventsPresent = ((Get-WinEvent -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0)
Heuristic-Flag-CA $u.Code $d.Code $eventsPresent

Write-Host ("`nLog saved to {0}" -f $LogFile)
exit 1

# SIG # Begin signature block
# MIIpmgYJKoZIhvcNAQcCoIIpizCCKYcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBUIrR5WVrFkpqZ
# FfFayT1vqIz4d+dOfxmhQQUmQxfPwqCCDk8wggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggeXMIIFf6ADAgECAhAJk/+MOgtz03ufnBveMqHYMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjUwNjE4MDAwMDAwWhcNMjYwNDAx
# MjM1OTU5WjCBnzETMBEGCysGAQQBgjc8AgEDEwJESzEdMBsGA1UEDwwUUHJpdmF0
# ZSBPcmdhbml6YXRpb24xETAPBgNVBAUTCDQwNTYwNDgzMQswCQYDVQQGEwJESzER
# MA8GA1UEBxMISG9ybnNsZXQxGjAYBgNVBAoTEUxvZ2ljIFVua25vd24gQXBzMRow
# GAYDVQQDExFMb2dpYyBVbmtub3duIEFwczCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAJXN+BSQmjmLlxTQ74DyYHlAl0MDMJIcU6mVe6h6vK2bNxZ7heWL
# 62tiCewzqMlbseS0ZJZGVFMItstdQ9ZhFWnglJdqMfjnkPEifnYXcvKtzjtOafSv
# qE/34EokWO7JvMalVi6DIeu1WBnrEJqrEr84pNwPJdU95SaGxLvlLhVoneSF2J4T
# pgA8WokgaC0PC6pzY7VPRyOD9zoh16IiLYyZtXKtqEtMrgrguUFHtIhF8WyG89MH
# Sc6NWmiJPvVXLeABAaIY6xdUBM8EiS0TU8pSQTJDl5rQSCaC6yjArsXiZH9bKCiL
# NaIy8yhgD93TmKp8lBGwnUM0HNtMUBY4ZemAC64BJyS4lnKYM9TQJbGA280b7AUJ
# EZQ5d8TnmgPkbpqVkAQGy5rnJQvkRVSucLVZwQSgF8WQ/uj1QdHTcWitHbeCvbI5
# yl5pty738CY1It6fi3nldmHvh/IhXDIa5i8gfqwesIALzPDXPMgyg4ZcgcnrcQ8x
# /e6k5r93o1R+qyqt+IeOhdNvmMq2qYHseGVg5Gassbhi7WGQTilRP79TMdjFw6e0
# A89V6pOG7S1u1jhC2xupaO/7CJoZhaElj3Kz1vSkf5wAOvexo0zbro4S/LHtnkAn
# 4+QK81aC8m7keSm78ziQDO4Wd+459hAkawSsI1XZuK09nuAiN31S5MbDAgMBAAGj
# ggICMIIB/jAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4E
# FgQULntXOUwO4tkeKuuNV2CUfoe4WNwwPQYDVR0gBDYwNDAyBgVngQwBAzApMCcG
# CCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+G
# TWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVT
# aWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3Js
# NC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQw
# OTZTSEEzODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25p
# bmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0B
# AQsFAAOCAgEASdBIpE6bDz3nYTZFyulKnq3DdhamesErbojdL5Q8hmyvqMZzMv+H
# 9yhL38WzxWFjN1UM50i0a24FASE9CmWuqnBWYWdJUWrlTbFMkOgXGGtgAzATn2oD
# /5M7ThWg7Th9ve4Z7CZ+IDHrhQQc20ImMOOlqYQT0sNQcC0bnhRrWoY9j7rQ17pk
# cbB6/3Om/Ku4qYT+h2cHbbyqeUOoBOb1THbbGKB/9Kx2pBbcR8Hcj+gq4KphNBrj
# onemMSgWgYXnHUz5mrgPCW/HzQxGSUYf4yzMMuiqJXASWh/sdh9PEmdb7UAPHoWK
# MJow536rch2vHU+md9h/Xm40oAVrcGs/Ye1eo5BnjFmtUMrjGx6R55leF8Q5m54C
# 06GjYJrkrbZkLIzzlMm7pALA7uUTJQtnmXixqxP+Sa5walPEy2dcyreZsZ/ERSej
# Fobyneuwj6Lso+uDpM+JXvG+29D+aXeoAVmMN7CcPHFjx7Tvk9yIXOGAGZZRCHgQ
# UKvHSfg+RGjKDjKbOOorrT3zJdMa2jW/VjpW5hwUICORu5XI8XCiA5i7Qalw4hqe
# DKEgHUDfi1jEOw/aUpri/XsR4wC2hd88yJkl7/08N6j6v93WAodZJZocTJbeNjdK
# v5EjOgbAsphWDbtO0Wayv/4jfKYVcokZnO8ViOA1us9MmXLMOTO213kxghqhMIIa
# nQIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFB
# MD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5
# NiBTSEEzODQgMjAyMSBDQTECEAmT/4w6C3PTe5+cG94yodgwDQYJYIZIAWUDBAIB
# BQCgfDAQBgorBgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg
# 4pkCEFBkmForWAOwsp2qOdTTKqhz2rgxFhBbxZH7ZncwDQYJKoZIhvcNAQEBBQAE
# ggIAQEwSbGn43jYwCh0m3zr27nhHenBTRjQ30EYqVBBCGA3X9O+b+fw4TXZ80pOI
# 4qqlvtE2knxdAFiYMc2KNjTCr2DPZJbJeSJUbzjuWqGCm/WIYB3/FQnjd3zdU10X
# V0g1BiuChv6k3Tc4LDRaBLrCoJ4cEBP3t0Z7w3SA3Y2vPb5MyYAwIL1YPA06g3KS
# hMmLC5RZ5OUOdRPwlB31TX/Yr8cHo7Kiy5CFCm8gwheye0ebKodxS8xK0Zdy/X16
# zfr5TWLYf+IliSNkfC1YBEsbEprQbe7HUSXbL97wEopR5DqbFSigvxGYzJuQG8lc
# 955hvox+/tlPZsxFEm4HudY68/SOWyp1LKOWq1NXZ+1x8/j3VLDM0kF/Ki7Jo9/B
# Tbq/ov6KNRNXiv9Jl10ezMuqpn0aDiRWesgi5YNEIyHPcHkZ56YZR8e2U4dfhSIE
# 108VsKTnFsWzQagoZI7/vA74Dl0hQz4MdXDVtm+7qlXKDBBOASP8lsjk+owVn7F+
# h0C3IMR2aFR6UFwsPfCK7+Zrx1gpQx/30fGyBmgkK4NPmXbZJeqcAq2TOLijL8Go
# rxrdaoak4vSI86tK9/+AdaEGwMtmBk+/8tluKow5seh04dkKblClms/R1F7Ka7kx
# ABYA/N28BhDjRcWdPaPBZXg5m3OUR5ovanIoZdp8b2+mugmhghd3MIIXcwYKKwYB
# BAGCNwMDATGCF2MwghdfBgkqhkiG9w0BBwKgghdQMIIXTAIBAzEPMA0GCWCGSAFl
# AwQCAQUAMHgGCyqGSIb3DQEJEAEEoGkEZzBlAgEBBglghkgBhv1sBwEwMTANBglg
# hkgBZQMEAgEFAAQgD6jTjeSy8l7PXscsenK/T2ceVVH8WXc8Xa0vkrm3PoQCEQCc
# 7qeUgYuOa6tnEJhZ0lJgGA8yMDI1MTAyMjA2MzkxNlqgghM6MIIG7TCCBNWgAwIB
# AgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4X
# DTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYg
# UlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlC
# MGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA
# 2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYO
# zDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0
# ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5
# KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLo
# ZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdo
# RORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUo
# HLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7r
# lRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V
# 1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8
# +3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39
# /dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUF
# BwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# XQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmww
# IAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUA
# A4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gB
# q9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9l
# Ffim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUq
# W4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMn
# xYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZp
# qyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AW
# cIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJg
# ddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV
# 1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVcc
# AvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8a
# tufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzCCBrQwggScoAMC
# AQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUw
# NzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRp
# bWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2U
# tZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWC
# WgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+
# gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DP
# fNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVV
# gtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifi
# nT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x
# 5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HH
# fIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQ
# yogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70Ew
# gWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7Zr
# IGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTv
# b1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYB
# BQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# QQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877
# FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI
# 9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3ess
# BS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qK
# tntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I
# +ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q1
# 7r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+Mt
# ucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9J
# GYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlH
# qhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7G
# ELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlar
# Evf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggWNMIIEdaADAgECAhAOmxiO
# +dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAi
# BgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAw
# MDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERp
# Z2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsb
# hA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iT
# cMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGb
# NOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclP
# XuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCr
# VYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFP
# ObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTv
# kpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWM
# cCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls
# 5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBR
# a2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6
# MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8E
# BAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDig
# NoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCg
# v0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQT
# SnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh
# 65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSw
# uKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAO
# QGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjD
# TZ9ztwGpn1eqXijiuZQxggN8MIIDeAIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNTEwMjIwNjM5MTZaMCsGCyqGSIb3DQEJ
# EAIMMRwwGjAYMBYEFN1iMKyGCi0wa9o4sWh5UjAH+0F+MC8GCSqGSIb3DQEJBDEi
# BCD2I5w5HiqvgHTNCT7q/lRICBli4H0LFSM47UJrLyR3jjA3BgsqhkiG9w0BCRAC
# LzEoMCYwJDAiBCBKoD+iLNdchMVck4+CjmdrnK7Ksz/jbSaaozTxRhEKMzANBgkq
# hkiG9w0BAQEFAASCAgCnxsxoNdwG5V0OYtkpNm0aFwvDuqqj/iMhSzEpQ9J8eDqW
# YCfKcmoSzuIVLxucvt01WD9kQKqItUsf/MXBgOZakOUcSHfY9RaNOZrTK04w8BXM
# 7jPSuHLWZwO5jkzljxs4IUTlgm6CEXnF2K6OMZuDBqUMUU1hNxw8abh+KYRgmr3O
# IXdrte7TwOqpR44gVeZ8kpqz7dz93tiXFiDvnBMeeN3JfQdNNxquCOL+ndpEjECZ
# jWDOeAHhnNz3n246eMTJ4iZVXE1J/I+v3vU9t5Fm8yOXhANbndpgFTue29WkKyU0
# 2khtmGxpPYUVxT3uTVc9kb8EDJrSDO1OY4n97VurWUoReyORWlSwfis965vt5wXj
# CZeHZl76hFtq3/NCN3EDSnJxTO1tJ85VthwQsoRF0WOImygXUi8nHYh4LA3EO3zT
# jxRrPEXuSnKvSQCXiFIq4EcJXC9USFDuwtkBEtNmEv+HrLW/LUKE/VzBiFt1sbd2
# EBlPsBNp+fso7tpvtzoL1Xmd7KqF9A4CXJLWvU3XYVtrwf2YybjY8TlNXART2KI3
# DPVcw8+9x5KTlKL7RUB2+O/JeDFxT5mpg1IReBp6Rk0yvP/q+eq1RThIUpVgD1OS
# Rw1DM6OCP5KY0SUgcPMN2t2KzpBy0ZFc0reE2GTpXCWy8H2r7g85TdaT4GKUjw==
# SIG # End signature block
