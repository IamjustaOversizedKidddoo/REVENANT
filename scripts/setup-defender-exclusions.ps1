#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Add (or remove) scoped Microsoft Defender exclusions so REVENANT's offensive
    security tooling can run on a Windows lab host.

.DESCRIPTION
    REVENANT bundles real penetration-testing binaries (nmap, ncat, nuclei, ffuf,
    subfinder, katana, httpx, trufflehog, gitleaks, semgrep). Microsoft Defender
    correctly flags these as HackTool / riskware and quarantines them, which breaks
    the adapters that shell out to them.

    The *preferred* fix is isolation: run REVENANT in its Docker/WSL2 appliance
    (set REVENANT_RUNNER=docker, or use deployments/docker-compose.yml) so Defender
    is never in the loop. Use THIS script only when you must run tools on the bare
    Windows host, and only on a dedicated, authorized lab machine.

    Exclusions are scoped to the REVENANT bin/ folder and the specific tool
    executables - never a blanket "disable Defender". Re-run with -Remove to undo.

.PARAMETER RepoRoot
    REVENANT repository root. Defaults to the parent of this script's folder.

.PARAMETER Remove
    Remove the exclusions this script adds, instead of adding them.

.EXAMPLE
    # From an ELEVATED PowerShell:
    .\scripts\setup-defender-exclusions.ps1

.EXAMPLE
    .\scripts\setup-defender-exclusions.ps1 -Remove
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

$binDir = Join-Path $RepoRoot 'bin'
$tools = @(
    'nmap.exe', 'ncat.exe', 'nping.exe', 'nuclei.exe', 'ffuf.exe',
    'subfinder.exe', 'katana.exe', 'httpx.exe', 'trufflehog.exe',
    'gitleaks.exe', 'semgrep.exe', 'pysemgrep.exe'
)

Write-Host '============================================================'
Write-Host '  REVENANT - Microsoft Defender exclusion setup'
Write-Host '============================================================'
Write-Host ("  Repo root : {0}" -f $RepoRoot)
Write-Host ("  Tools dir : {0}" -f $binDir)
Write-Host ("  Mode      : {0}" -f ($(if ($Remove) { 'REMOVE' } else { 'ADD' })))
Write-Host ''

if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
    Write-Error 'Defender cmdlets not available. Is this Windows with Defender present?'
    exit 1
}

if ($Remove) {
    Remove-MpPreference -ExclusionPath $binDir -ErrorAction SilentlyContinue
    foreach ($t in $tools) { Remove-MpPreference -ExclusionProcess $t -ErrorAction SilentlyContinue }
    Write-Host '[+] Removed REVENANT Defender exclusions.' -ForegroundColor Green
    Write-Host '    Defender will again scan/quarantine the bundled tools.'
    exit 0
}

Add-MpPreference -ExclusionPath $binDir
Write-Host ("[+] Excluded folder: {0}" -f $binDir) -ForegroundColor Green

foreach ($t in $tools) {
    Add-MpPreference -ExclusionProcess $t
    Write-Host ("[+] Excluded process: {0}" -f $t) -ForegroundColor Green
}

Write-Host ''
Write-Host '[i] Note: the hypothesis._native DLL / unsigned EXE blocks (WinError 4551)'
Write-Host '    come from Smart App Control / WDAC, NOT antivirus. Defender exclusions'
Write-Host '    do not lift those - turn Smart App Control OFF on this lab host:'
Write-Host '    Settings > Privacy & security > Windows Security > App & browser control'
Write-Host '    > Smart App Control > Off   (one-way; requires a reinstall to re-enable).'
Write-Host ''
Write-Host '[i] Preferred alternative: skip host exclusions entirely and run tools in'
Write-Host '    containers:  $env:REVENANT_RUNNER = "docker"   (see docs/WINDOWS-SECURITY.md)'
Write-Host '============================================================'
