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

    switch ($settings.BuildStep) {
        0 { 
            ConfigurePowerShellPolicy
            Install-BoxStarter
        
            $securePassword = ConvertTo-SecureString -String $settings.WindowsPassword -AsPlainText -Force
            $credential = New-Object -TypeName PSCredential -ArgumentList @($env:USERNAME, $securePassword)
            IncreaseBuildStep
            Install-BoxStarterPackage -PackageName https://bit.ly/2w0WQVQ -Credential $credential
        }
        1 {
            $message = "$(Get-Date) Before Reboot`n"
            $message
            $message | Out-File -FilePath "$env:USERPROFILE\test.txt" -Append
            Start-Sleep -Seconds 60
            IncreaseBuildStep
            Invoke-Reboot
        }
        2 {
            $message = "$(Get-Date) After Reboot`n"
            $message
            $message | Out-File -FilePath "$env:USERPROFILE\test.txt" -Append
            Start-Sleep -Seconds 60
            IncreaseBuildStep
            Invoke-Reboot
        }
        Default {
            "We are done"
        }
    }
}

function EnsureRunningAsAdmin {
    if (-not (Test-Administrator)) {
        Start-Process -FilePath powershell.exe -ArgumentsList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
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
            BuildStep = 0
        }

        $settings | ConvertTo-Json | Out-File -FilePath $settingsFile
    }

    Get-Content -Path $settingsFile -Raw | ConvertFrom-Json
}

function IncreaseBuildStep {
    $settingsFile = "$env:USERPROFILE\DevSetupSettings.json"
    $settings = Get-Content -Path $settingsFile -Raw | ConvertFrom-Json
    $settings.BuildStep++
    $settings | ConvertTo-Json | Out-File -FilePath $settingsFile
}

Main