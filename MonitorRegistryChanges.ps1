###################################################################################################################
# Name: MonitorRegistryChanges.ps1
# Author: Thomas Marcussen, Thomas@ThomasMarcussen.com
# Date: December,2022
###################################################################################################################
# Monitor the registry for changes

# Define the registry key to monitor
$regKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

# Create a new RegistryWatcher object
$watcher = New-Object -TypeName System.Management.ManagementEventWatcher `
    -ArgumentList "SELECT * FROM RegistryKeyChangeEvent WHERE Hive='$regKey'"

# Define a callback function to handle registry change events
function OnRegistryChange {
    param($source, $eventArgs)

    # Print the registry key that was changed
    Write-Host "Registry key changed: $($eventArgs.NewEvent.KeyPath)"
}

# Register the callback function to handle registry change events
$watcher.EventArrived += { OnRegistryChange $watcher $_ }

# Start monitoring the registry for changes
$watcher.Start()

# Wait indefinitely
while ($true) {
    Start-Sleep -Seconds 1
}