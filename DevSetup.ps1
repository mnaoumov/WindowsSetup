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

    if (-not (Test-InsideBoxstarterInstall)) {
        ConfigurePowerShellPolicy
        Install-BoxStarter

        $securePassword = ConvertTo-SecureString -String $settings.WindowsPassword -AsPlainText -Force
        $credential = New-Object -TypeName PSCredential -ArgumentList @($env:USERNAME, $securePassword)
        Install-BoxStarterPackage -PackageName $PSCommandPath -Credential $credential
    }
    else {
        choco install powershell -y
        choco install visualstudiocode -y
        choco install git -y
        choco install gitextensions -y
        choco install kdiff3 -y
        choco install cmder -y

        if (Test-PendingReboot) {
            Invoke-Reboot
        }

        choco install sql-server-2017 -y
        choco install sql-server-management-studio -y

        if (Test-PendingReboot) {
            Invoke-Reboot
        }

        choco install visualstudio2017community -y

        if (Test-PendingReboot) {
            Invoke-Reboot
        }

        choco install resharper -y
        choco install GoogleChrome -y
        choco install Firefox -y


        Install-WindowsFeature -Name Web-Server, Web-Mgmt-Console, Web-Scripting-Tools, Web-Asp-Net45

        if (Test-PendingReboot) {
            Invoke-Reboot
        }

        if (-not (Test-Path -Path C:\Dev)) {
            New-Item -Path C:\Dev -ItemType Directory | Out-Null
        }

        if (-not (Test-Path -Path C:\Dev\RISC)) {
            Set-Location -Path C:\Dev
            cmdkey /generic:git:https://git.voliasoftware.com "/user:$($settings.Email)" "/pass:$($settings.GitLabPassword)"
            cmdkey "/generic:git:https://$($settings.Email)@git.voliasoftware.com" "/user:$($settings.Email)" "/pass:$($settings.GitLabPassword)"
    
            git clone https://git.voliasoftware.com/risc/riscvta.git RISC
            Set-Location -Path RISC
            git config user.email $settings.Email
            git config user.name $settings.FullName
        }

        $credential = New-Object -TypeName PScredential -ArgumentList @('Vince', (ConvertTo-SecureString -String $settings.DBBackupPassword -AsPlainText -Force))
        Invoke-WebRequest -Credential $credential -UseBasicParsing -Uri http://148.251.185.130:9080/DBBackup/VTA70.bak -OutFile C:\Dev\VTA70.bak
    }
}

function EnsureRunningAsAdmin {
    if (-not (Test-Administrator)) {
        Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
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
            DBBackupPassword = Read-Host -Prompt 'Enter Password for DBBackup download (ask your team lead)'
        }

        $settings | ConvertTo-Json | Out-File -FilePath $settingsFile
    }

    Get-Content -Path $settingsFile -Raw | ConvertFrom-Json
}

function Test-InsideBoxstarterInstall {
    (Test-Path -Path Variable:Boxstarter) -and $Boxstarter.ContainsKey('SourcePID')
}

function Install-ChocolateyPackage {
    param
    (
        [Parameter(Mandatory)]
        [string] $Name
    )

    $cacheFolder = "$env:UserProfile\AppData\Local\ChocoCache"
    if (-not (Test-Path -Path $cacheFolder)) {
        New-Item -Path $cacheFolder -ItemType Directory | Out-Null
    }

    if (Test-PendingReboot) {
        Invoke-Reboot
    }

    choco install $Name -y --cacheLocation $cacheFolder

    if (Test-PendingReboot) {
        Invoke-Reboot
    }
}

Main