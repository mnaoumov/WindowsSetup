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
        Install-BoxStarterPackage -PackageName $PSCommandPath -Credential $credential -Verbose
    }
    else {
        Install-ChocolateyPackage -Name powershell
        Install-ChocolateyPackage -Name visualstudiocode
        Install-ChocolateyPackage -Name git
        Install-ChocolateyPackage -Name gitextensions
        Install-ChocolateyPackage -Name kdiff3
        Install-ChocolateyPackage -Name cmder
        Install-ChocolateyPackage -Name sql-server-2017 -AdditionalArguments ('/SAPWD=Password13579!', '/SECURITYMODE=SQL')
        Install-ChocolateyPackage -Name sql-server-management-studio
        Install-ChocolateyPackage -Name visualstudio2017community
        Install-ChocolateyPackage -Name visualstudio2017-workload-netweb
        Install-ChocolateyPackage -Name resharper
        Install-ChocolateyPackage -Name GoogleChrome
        Install-ChocolateyPackage -Name Firefox

        Install-WindowsFeature -Name Web-Server, Web-Mgmt-Console, Web-Scripting-Tools, Web-Asp-Net45

        Install-PackageProvider -Name NuGet -Force
        Install-Module -Name posh-git -Force -AllowClobber
        Install-Module -Name SqlServer -Force -AllowClobber

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
    
            InvokeAndIgnoreStdErr -ScriptBlock { git clone https://git.voliasoftware.com/risc/riscvta.git RISC --progress }
            Set-Location -Path C:\Dev\RISC
            git config user.email $settings.Email
            git config user.name $settings.FullName
        }

        PinToTaskBar -ApplicationPath 'C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe'
        PinToTaskBar -ApplicationPath 'C:\Program Files\Microsoft VS Code\Code.exe'
        PinToTaskBar -ApplicationPath 'c:\tools\cmder\Cmder.exe'
        PinToTaskBar -ApplicationPath 'C:\Program Files (x86)\Microsoft SQL Server\140\Tools\Binn\ManagementStudio\Ssms.exe'
        PinToTaskBar -ApplicationPath 'C:\Program Files\Internet Explorer\iexplore.exe'
        PinToTaskBar -ApplicationPath 'C:\Program Files (x86)\GitExtensions\GitExtensions.exe'
        UnpinFromTaskBar -ApplicationPath '%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe'
        UnpinFromTaskBar -ApplicationPath '%SystemRoot%\system32\ServerManager.exe'

        ConfigureCmder

        ConfigureIis

        RestoreDatabase
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
            FullName         = Read-Host -Prompt 'Enter Your Name'
            Email            = Read-Host -Prompt 'Enter Your Email'
            GitLabPassword   = Read-Host -Prompt 'Enter Your GitLab Password'
            WindowsPassword  = Read-Host -Prompt 'Enter Your Windows Password'
            DevSetupPassword = Read-Host -Prompt 'Enter Password for DevSetup download (ask your team lead)'
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
        [string] $Name,

        [string[]] $AdditionalArguments
    )

    $cacheFolder = "$env:UserProfile\AppData\Local\ChocoCache"
    if (-not (Test-Path -Path $cacheFolder)) {
        New-Item -Path $cacheFolder -ItemType Directory | Out-Null
    }

    if (Test-PendingReboot) {
        Invoke-Reboot
    }

    choco install $Name -y --cacheLocation $cacheFolder $AdditionalArguments

    if (Test-PendingReboot) {
        Invoke-Reboot
    }
}

function PinToTaskBar {
    param
    (
        [Parameter(Mandatory)]
        [string] $ApplicationPath
    )

    $syspinPath = "$Env:USERPROFILE\syspin.exe"
    if (-not (Test-Path -Path $syspinPath)) {
        Invoke-WebRequest -UseBasicParsing -Uri http://www.technosys.net/download.aspx?file=syspin.exe -OutFile $syspinPath
    }
    
    & $syspinPath $ApplicationPath 'c:"Pin to taskbar"'
}

function UnpinFromTaskBar {
    param
    (
        [Parameter(Mandatory)]
        [string] $ApplicationPath
    )

    $syspinPath = "$Env:USERPROFILE\syspin.exe"
    if (-not (Test-Path -Path $syspinPath)) {
        Invoke-WebRequest -UseBasicParsing -Uri http://www.technosys.net/download.aspx?file=syspin.exe -OutFile $syspinPath
    }
    
    & $syspinPath $ApplicationPath 'c:"Unpin from taskbar"'
}

function ConfigureCmder {
    $settingsPath = 'C:\tools\cmder\vendor\conemu-maximus5\ConEmu.xml'
    Copy-Item -Path C:\tools\cmder\config\ConEmu.xml -Destination $settingsPath -Force
    $settingsXml = [xml] (Get-Content -Path $settingsPath)
    $settingsXml.SelectSingleNode("/key[@name='Software']/key[@name='ConEmu']/key[@name='.Vanilla']/value[@name='StartTasksName']").data = '{Powershell::PowerShell as Admin}'
    $settingsXml.SelectSingleNode("/key[@name='Software']/key[@name='ConEmu']/key[@name='.Vanilla']/key[@name='Tasks']/key[value/@data='{Powershell::PowerShell as Admin}']/value[@name='Cmd1']").data = @'
-new_console:d:C:\Dev\RISC PowerShell -ExecutionPolicy Bypass -NoLogo -NoProfile -NoExit -Command "Invoke-Expression '. ''%ConEmuDir%\..\profile.ps1'''"
'@

    $settingsXml.Save($settingsPath)
}

function InvokeAndIgnoreStdErr {
    param
    (
        [Parameter(Mandatory)]
        [ScriptBlock] $ScriptBlock
    )

    $backupErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue
    try {
        & $ScriptBlock 2>&1 | ForEach-Object -Process {
            "$_"
        }
    }
    finally {
        $ErrorActionPreference = $backupErrorActionPreference
    }
}

function RestoreDatabase {
    $dbBackupPath = 'C:\Dev\VTA70.bak'
    if (Test-Path -Path $dbBackupPath) {
        return
    }

    $credential = New-Object -TypeName PScredential -ArgumentList @('DevSetup', (ConvertTo-SecureString -String $settings.DevSetupPassword -AsPlainText -Force))
    Invoke-WebRequest -Credential $credential -UseBasicParsing -Uri http://148.251.185.130:9080/DevSetup/VTA70.bak -OutFile C:\Dev\VTA70.bak

    Import-Module -Name SqlServer

    New-Item -Path C:\Dev\DB\VTA70 -ItemType Directory | Out-Null

    $backupParts = @(
        "BPGLOBAL.mdf"
        "BPGLOBAL1.mdf"
        "ftrow_Corsefulltext.mdf"
        "ftrow_BlogFullText.mdf"
        "ftrow_EmpFullText.mdf"
        "BPGLOBALLOG.ldf"
    )

    $relocateFiles = $backupParts | ForEach-Object -Process {
        $name = $_.Split(".")[0]
        New-Object -TypeName Microsoft.SqlServer.Management.Smo.RelocateFile -ArgumentList ($name, "c:\Dev\DB\VTA70\$_")
    }

    Restore-SqlDatabase -ServerInstance . -Database VTA70 -BackupFile C:\dev\VTA70.bak -RelocateFile $relocateFiles

    Invoke-Sqlcmd -ServerInstance . -Database master -Query "CREATE LOGIN [otis] WITH PASSWORD=N'real203', DEFAULT_DATABASE=[VTA70], CHECK_EXPIRATION=OFF, CHECK_POLICY=OFF"
    Invoke-Sqlcmd -ServerInstance . -Database VTA70 -Query 'ALTER USER [otis] WITH LOGIN = otis'
    Invoke-Sqlcmd -ServerInstance . -Database VTA70 -Query 'ALTER USER [otis] WITH DEFAULT_SCHEMA=[otis]'
    Invoke-Sqlcmd -ServerInstance . -Database VTA70 -Query 'ALTER ROLE [db_owner] ADD MEMBER [IIS APPPOOL\RISC]'

    Invoke-Sqlcmd -ServerInstance . -Database master -Query 'CREATE LOGIN [IIS APPPOOL\RISC] FROM WINDOWS WITH DEFAULT_DATABASE=[master]'
    Invoke-Sqlcmd -ServerInstance . -Database VTA70 -Query 'CREATE USER [IIS APPPOOL\RISC] FOR LOGIN [IIS APPPOOL\RISC]'
    Invoke-Sqlcmd -ServerInstance . -Database VTA70 -Query 'ALTER USER [IIS APPPOOL\RISC] WITH DEFAULT_SCHEMA=[otis]'
    Invoke-Sqlcmd -ServerInstance . -Database VTA70 -Query 'ALTER ROLE [db_owner] ADD MEMBER [IIS APPPOOL\RISC]'
}

function ConfigureIis {
    New-WebAppPool -Name RISC
    Set-ItemProperty -Path IIS:\AppPools\RISC -Name enable32BitAppOnWin64 -Value true
    New-WebApplication -Site 'Default Web Site' -Name RISC -PhysicalPath C:\Dev\RISC\Risc.VTA.BackOffice.WebSite -ApplicationPool RISC
}

Main