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
    ConfigurePowerShellPolicy
    DoNotOpenServerManagerAtLogon
    ShowFileExtensionsInExplorer
    ShowHiddenFilesInExplorer
    ShowSystemFilesInExplorer
    DisableInternetExplorerEnhancedSecurity
    Rename-Computer -NewName 'Dev-VM'
    Set-TimeZone -Name 'FLE Standard Time'
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
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
}

function DoNotOpenServerManagerAtLogon {
    New-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value 1 -Force
}

function ShowFileExtensionsInExplorer {
    New-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWORD -Value 0 -Force
}

function ShowHiddenFilesInExplorer {
    New-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWORD -Value 1 -Force
}

function ShowSystemFilesInExplorer {
    New-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSuperHidden -PropertyType DWORD -Value 1 -Force
}

function DisableInternetExplorerEnhancedSecurity {
    New-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -Value 0 -PropertyType DWORD -Force
    rundll32 iesetup.dll, IEHardenLMSettings,1,True
    rundll32 iesetup.dll, IEHardenUser,1,True
    rundll32 iesetup.dll, IEHardenAdmin,1,True
}

function Set-TimeZone {
    param
    (
        [Parameter(Mandatory)]
        [string] $Name
    )

    tzutil.exe /s $Name
}

Main