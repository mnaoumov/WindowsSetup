#Requires -Version 3

[CmdletBinding()]
param
(
)

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
Set-StrictMode -Version Latest
trap { throw $Error[0] }

$message = "$(Get-Date) Before Reboot`n"
$message
$message | Out-File -FilePath "$env:USERPROFILE\test.txt" -Append
Start-Sleep -Seconds 60
Invoke-Reboot
$message = "$(Get-Date) After Reboot`n"
$message
$message | Out-File -FilePath "$env:USERPROFILE\test.txt" -Append
Start-Sleep -Seconds 60
