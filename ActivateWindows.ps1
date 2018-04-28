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

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $tempDir = [System.IO.Path]::GetTempPath() + [Guid]::NewGuid()
    New-Item -Path $tempDir -ItemType Directory | Out-Null
    $kmsAutoNetExe = "$tempDir\KMSAuto Net.exe"
    Invoke-WebRequest -UseBasicParsing -Uri https://github.com/mnaoumov/WindowsSetup/raw/master/KMSAuto%20Net.exe -OutFile $kmsAutoNetExe
    & $kmsAutoNetExe /win=act /kmsset=yes

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $retrySeconds = 1
    $timeoutSeconds = 60
    while (Get-Process -Name 'KMSAuto Net' -ErrorAction SilentlyContinue) {
        if ($stopwatch.Elapsed.TotalSeconds -gt $timeoutSeconds) {
            throw "KMSAuto Net timed out"
        }
        Start-Sleep -Seconds $retrySeconds
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

Main