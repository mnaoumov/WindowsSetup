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
    EnsureRunningInBoxstarter

    Install-ChocolateyPackageWithChecks -Name powershell
    Install-ChocolateyPackageWithChecks -Name visualstudiocode
    Install-ChocolateyPackageWithChecks -Name git
    Install-ChocolateyPackageWithChecks -Name gitextensions
    Install-ChocolateyPackageWithChecks -Name kdiff3
    Install-ChocolateyPackageWithChecks -Name cmder
    Install-ChocolateyPackageWithChecks -Name sql-server-2017 -CustomParams '/SAPWD=Password13579! /SECURITYMODE=SQL'
    Install-ChocolateyPackageWithChecks -Name sql-server-management-studio
    Install-ChocolateyPackageWithChecks -Name visualstudio2017community
    Install-ChocolateyPackageWithChecks -Name visualstudio2017-workload-netweb
    Install-ChocolateyPackageWithChecks -Name resharper
    Install-ChocolateyPackageWithChecks -Name GoogleChrome
    Install-ChocolateyPackageWithChecks -Name Firefox

    Install-WindowsFeature -Name Web-Server, Web-Mgmt-Console, Web-Scripting-Tools, Web-Asp-Net45

    Install-PackageProvider -Name NuGet -Force

    if (-not (Get-Module -Name posh-git -ListAvailable)) {
        Install-Module -Name posh-git -Force -AllowClobber
    }

    if (-not (Get-Module -Name SqlServer -ListAvailable)) {
        Install-Module -Name SqlServer -Force -AllowClobber
    }

    if (Test-PendingReboot) {
        Invoke-Reboot
    }

    if (-not (Test-Path -Path C:\Dev)) {
        New-Item -Path C:\Dev -ItemType Directory | Out-Null
    }

    git config --global user.email $settings.Email
    git config --global user.name $settings.FullName

    if (-not (Test-Path -Path C:\Dev\RISC)) {
        Set-Location -Path C:\Dev
        cmdkey /generic:git:https://git.voliasoftware.com "/user:$($settings.Email)" "/pass:$($settings.GitLabPassword)"
        cmdkey "/generic:git:https://$($settings.Email)@git.voliasoftware.com" "/user:$($settings.Email)" "/pass:$($settings.GitLabPassword)"

        InvokeAndIgnoreStdErr -ScriptBlock { git clone https://git.voliasoftware.com/risc/riscvta.git RISC --progress }
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

    Install-FoxProOleDb
    Install-FoxProOdbc
    Install-VisualFoxPro
    ConfigureFoxProOdbc

    Install-AceCrypt
    Install-CrystalReportsRuntime
    Install-CrystalReports

    C:\Dev\RISC\tools\Update-Database.ps1
    C:\Dev\RISC\tools\Build.ps1
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

function Install-ChocolateyPackageWithChecks {
    param
    (
        [Parameter(Mandatory)]
        [string] $Name,

        [string] $CustomParams
    )

    $cacheFolder = "$env:UserProfile\AppData\Local\ChocoCache"
    if (-not (Test-Path -Path $cacheFolder)) {
        New-Item -Path $cacheFolder -ItemType Directory | Out-Null
    }

    if (Test-PendingReboot) {
        Invoke-Reboot
    }

    choco install $Name -y --cacheLocation $cacheFolder --params="'$CustomParams'"

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
    if (Test-Path -Path $settingsPath) {
        return
    }

    Copy-Item -Path C:\tools\cmder\config\ConEmu.xml -Destination $settingsPath
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

    $filePath = DownloadDevSetupFile -FileName VTA70.bak
    Move-Item -Path $filePath -Destination $dbBackupPath

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
    Import-Module -Name WebAdministration

    if (Test-Path -Path IIS:\AppPools\RISC) {
        return
    }

    New-WebAppPool -Name RISC
    Set-ItemProperty -Path IIS:\AppPools\RISC -Name enable32BitAppOnWin64 -Value true
    New-WebApplication -Site 'Default Web Site' -Name RISC -PhysicalPath C:\Dev\RISC\Risc.VTA.BackOffice.WebSite -ApplicationPool RISC

    Invoke-Reboot
}

function Install-FoxProOleDb {
    if (Test-Path -Path 'C:\Program Files (x86)\Microsoft Visual FoxPro OLE DB Provider') {
        return
    }

    $filePath = DownloadDevSetupFile -FileName VFPOLEDBSetup.msi
    Install-Msi -InstallerPath $filePath -AdditionalArguments 'FolderForm_AllUsers=ALL'
}

function Install-FoxProOdbc {
    if (Test-Path -Path 'C:\Windows\SysWOW64\vfpodbc.dll') {
        return
    }
    $filePath = DownloadDevSetupFile -FileName VFPODBC.msi
    Install-Msi -InstallerPath $filePath
}

function Install-VisualFoxPro {
    if (Test-Path -Path 'C:\Program Files (x86)\Microsoft Visual FoxPro 9') {
        return
    }

    $tempDir = "$Env:TEMP\$([Guid]::NewGuid())"
    New-Item -Path $tempDir -ItemType Directory | Out-Null
    $filePath = DownloadDevSetupFile -FileName VisualFoxPro.zip
    & 'C:\ProgramData\chocolatey\tools\7z.exe' x $filePath "-o$tempDir"

    Start-Process -FilePath "$tempDir\WCU\bootstrap.msi" -Wait
    Start-Process -FilePath msiexec.exe -ArgumentList ('/i', "$tempDir\WCU\soap3\soapsdk.msi", "/qn") -Wait
    Start-Process -FilePath "$tempDir\setup\setup.exe" -ArgumentList ('/UnattendFile', "$tempDir\setup\Unattended.ini") -Wait
}

function Install-AceCrypt {
    if (Test-Path -Path 'Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{F783E66E-761E-11D4-8CE2-AF310264C746}') {
        return
    }

    $filePath = DownloadDevSetupFile -FileName AceCrypt.dll
    regsvr32.exe $filePath /s
}

function Install-CrystalReportsRuntime {
    if (Test-Path -Path 'C:\Program Files (x86)\Business Objects\Common\2.8\bin') {
        return
    }

    $filePath = DownloadDevSetupFile -FileName CRRedist2008_x86.msi
    Install-Msi -InstallerPath $filePath
}

function EnsureRunningInBoxstarter {
    if (Test-InsideBoxstarterInstall) {
        return
    }

    ConfigurePowerShellPolicy
    Install-BoxStarter

    $securePassword = ConvertTo-SecureString -String $settings.WindowsPassword -AsPlainText -Force
    $credential = New-Object -TypeName PSCredential -ArgumentList @($env:USERNAME, $securePassword)
    Install-BoxStarterPackage -PackageName $PSCommandPath -Credential $credential -Verbose
    exit
}

function DownloadDevSetupFile {
    param
    (
        [Parameter(Mandatory)]
        [string] $FileName
    )

    $resultFile = "$Env:TEMP\$FileName"
    $credential = New-Object -TypeName PScredential -ArgumentList @('DevSetup', (ConvertTo-SecureString -String $settings.DevSetupPassword -AsPlainText -Force))
    Invoke-WebRequest -Credential $credential -UseBasicParsing -Uri "http://148.251.185.130:9080/DevSetup/$FileName" -OutFile $resultFile
    $resultFile
}

function Install-Msi {
    param
    (
        [Parameter(Mandatory)]
        [string] $InstallerPath,

        [string[]] $AdditionalArguments
    )

    $arguments = @('/i', $InstallerPath, '/qn')
    if ($AdditionalArguments -ne $null) {
        $arguments += $AdditionalArguments
    }

    Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait
}

function Install-CrystalReports {
    if (Test-Path -Path 'C:\Program Files (x86)\Business Objects\Crystal Reports 11.5') {
        return
    }

    $tempDir = "$Env:TEMP\$([Guid]::NewGuid())"
    New-Item -Path $tempDir -ItemType Directory | Out-Null
    $filePath = DownloadDevSetupFile -FileName CrystalReports.zip
    & 'C:\ProgramData\chocolatey\tools\7z.exe' x $filePath "-o$tempDir"

    Start-Process -FilePath "$tempDir\setup.exe" -ArgumentList ('/qn', 'REBOOT=ReallySuppress', 'CLIENTLANGUAGE=EN', 'ADDLOCAL=ALL', 'PIDKEY="B5W60-01C0200-00GPAJ0-0M80"') -Wait
}

function ConfigureFoxProOdbc {
    if (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\otisreports') {
        return
    }

    New-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\ODBC Data Sources' -Name otisreports -Value 'Microsoft Visual FoxPro Driver' -Force
    New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\otisreports' -Force
    New-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\otisreports' -Name Driver -Value 'C:\Windows\SysWOW64\vfpodbc.dll' -Force
    New-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\otisreports' -Name SourceDB -Value 'C:\Dev\FoxProOdbc' -Force
    New-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\otisreports' -Name SourceType -Value DBF -Force
}

Main