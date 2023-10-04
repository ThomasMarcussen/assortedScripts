###################################################################################################################
# Name: Uninstall-iTunes.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: October, 2023
###################################################################################################################
<#
    .SYNOPSIS
    Script to uninstall iTunes, addressing both MSI-installed and Store-installed instances.

    .DESCRIPTION
    The script is engineered to uninstall iTunes across the two primary installation methodologies: traditional MSI installations and Microsoft Store installations. It executes an uninstallation procedure for each type independently, ensuring a comprehensive purge of iTunes across the board.

    Script prerequisites:
    1. A minimum Windows PowerShell version of '5.1' is required to run this script. Ensure the device has PowerShell installed and configured.

    2. Administrative privileges: The script should be executed with administrative privileges to allow the removal of software and to access the Windows registry.

    3. Execution Policy: Ensure that your PowerShell execution policy allows for the execution of scripts. You may configure this via Set-ExecutionPolicy.

    4. Test Environment: It is pivotal that the script is tested in a secure, sandboxed environment prior to production deployment, mitigating the risk of unintended system alterations.

    .PARAMETER None
    The script takes no parameters.

    .EXAMPLE
    .\Uninstall-iTunes.ps1 -Verbose

    .NOTES
    The script will check and attempt to uninstall iTunes, regardless of the installation methodology (MSI or Store). Status updates, such as confirmation of uninstallation or failure thereof, will be displayed in the console output.
    Ensure thorough validation of the script in a safe environment before deploying in a live scenario.
    Undertake this operation with caution, ensuring accurate and safe execution to prevent inadvertent system disruptions.
#>

function Uninstall-MSIiTunes {
    $UninstallString = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
                        Where-Object {$_.DisplayName -match "iTunes"}).UninstallString

    if ($null -ne $UninstallString) {
        Start-Process cmd -ArgumentList "/c $UninstallString /quiet" -Wait

        if ($null -eq (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                       Where-Object {$_.DisplayName -match "iTunes"}).UninstallString) {
            Write-Output "MSI-based iTunes has been uninstalled successfully."
        } else {
            Write-Output "Failed to uninstall MSI-based iTunes."
        }
    } else {
        Write-Output "MSI-based iTunes is not installed."
    }
}

function Uninstall-StoreiTunes {
    $App = Get-AppxPackage -AllUsers | Where-Object { $_.Name -match "iTunes" }

    if ($App -ne $null) {
        Get-AppxPackage -Name $App.Name | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

        if ((Get-AppxPackage -Name $App.Name -AllUsers) -eq $null) {
            Write-Output "Store-based iTunes has been uninstalled successfully."
        } else {
            Write-Output "Failed to uninstall Store-based iTunes."
        }
    } else {
        Write-Output "Store-based iTunes is not installed."
    }
}

# Uninstall both versions of iTunes
Uninstall-MSIiTunes
Uninstall-StoreiTunes
