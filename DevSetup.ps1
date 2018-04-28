#Requires -Version 3

[CmdletBinding()]
param
(
)

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
Set-StrictMode -Version Latest
trap { throw $Error[0] }

function Main {
    EnsureRunningAsAdmin
    $settings = InitSetupSettings
    ConfigurePowerShellPolicy
    Install-BoxStarter
}

function EnsureRunningAsAdmin {
    if (-not (Test-Administrator)) {
        Start-Process -FilePath powershell.exe -ArgumentsList "-NoExit -NoProfile -ExecutionPolicy Bypass -Command `"[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri https://bit.ly/2w0WQVQ -UseBasicParsing | Invoke-Expression`"" -Verb RunAs
        exit
    }
}

function Test-Administrator {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConfigurePowerShellPolicy {
    if ((Get-ExecutionPolicy -Scope LocalMachine) -eq [Microsoft.PowerShell.ExecutionPolicy]::RemoteSigned) {
        return
    }

    $currentProcessPolicy = Get-ExecutionPolicy -Scope Process
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Scope Process
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
    Set-ExecutionPolicy -ExecutionPolicy $currentProcessPolicy -Force -Scope Process
}

function Install-BoxStarter {
    if (Test-Path -Path Variable:Boxstarter) {
        return
    }
    Invoke-WebRequest -UseBasicParsing -Uri http://boxstarter.org/bootstrapper.ps1 | Invoke-Expression
    Get-BoxStarter -Force
}

function InitSetupSettings {
    $settingsFile = "$env:USERPROFILE\DevSetupSettings.json"

    if (-not (Test-Path -Path $settingsFile)) {
        $settings = @{
            FullName = Read-Host -Prompt 'Enter Your Name'
            Email = Read-Host -Prompt 'Enter Your Email'
            GitLabPassword = Read-Host -Prompt 'Enter Your GitLab Password'
            WindowsPassword = Read-Host -Prompt 'Enter Your Windows Password'
        }

        $settings | ConvertTo-Json | Out-File -FilePath $settingsFile
    }

    Get-Content -Path $settingsFile -Raw | ConvertFrom-Json
}

Main