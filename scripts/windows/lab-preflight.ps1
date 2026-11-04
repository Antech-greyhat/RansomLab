#requires -Version 5.1
<#
.SYNOPSIS
Read-only RansomLab prerequisite observations for a Windows lab guest.
.DESCRIPTION
Does not create snapshots, verify network isolation, change security settings,
install packages, create fixtures, or arm a simulation. Exit 2 means the Python
version command is unavailable. Exit 0 is not approval to execute file impact.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pythonAvailable = $false
$pythonVersion = $null
$pythonCommand = Get-Command -Name python -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -ne $pythonCommand) {
    try {
        $versionOutput = & $pythonCommand.Source --version 2>$null
        if ($LASTEXITCODE -eq 0 -and ($versionOutput -join '') -match '^Python \d+\.\d+\.\d+$') {
            $pythonAvailable = $true
            $pythonVersion = ($versionOutput -join '').Trim()
        }
    } catch {
        $pythonAvailable = $false
    }
}

$vmwareDetected = $false
$manufacturerCheck = 'unavailable'
try {
    $bios = Get-ItemProperty -LiteralPath 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS' `
        -Name SystemManufacturer,SystemProductName -ErrorAction Stop
    $vmwareDetected = (($bios.SystemManufacturer + ' ' + $bios.SystemProductName) -match 'VMware')
    $manufacturerCheck = 'observed'
} catch {
    $manufacturerCheck = 'unavailable'
}

$elevated = $null
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally {
        $identity.Dispose()
    }
} catch {
    $elevated = $null
}

[ordered]@{
    tool = 'RansomLab read-only preflight'
    python_available = $pythonAvailable
    python_version = $pythonVersion
    manufacturer_check = $manufacturerCheck
    vmware_indicator = $vmwareDetected
    elevated = $elevated
    snapshot_verified = $false
    network_isolation_verified = $false
    file_impact_ready = $false
    manual_checks = @(
        'Use a dedicated non-administrative account in an approved disposable Windows 11 guest.'
        'Verify the VMware network has no bridge, NAT, host-share or unintended route.'
        'Disable shared folders, clipboard and drag-and-drop integrations for the exercise.'
        'Create and record a clean guest snapshot and verify the rollback procedure.'
        'Confirm the local NTFS directory boundary and required platform tests succeed.'
        'Run python -m ransomlab doctor; resolve failures without disabling safeguards.'
    )
} | ConvertTo-Json -Depth 3

if (-not $pythonAvailable) { exit 2 }
exit 0
