# Hosted CI verifies package install/startup/uninstall, not an interactive desktop.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = Join-Path $env:LOCALAPPDATA 'Programs\LocalGPTMCP-CI'
$installer = Join-Path $PSScriptRoot 'install.ps1'
$uninstaller = Join-Path $PSScriptRoot 'uninstall.ps1'
if (Test-Path -LiteralPath $target) {
    throw 'Refusing to overwrite an existing CI test target.'
}
try {
    & $installer -InstallRoot $target
    $launcher = Join-Path $target 'Start-LocalGPTMCP.ps1'
    if (-not (Test-Path -LiteralPath $launcher)) { throw 'Launcher not installed.' }
    $safe = & $launcher
    if ($safe -notmatch 'unpaired') { throw 'Default launch was not deny-first.' }
    $version = & $launcher --version
    if ($version -notmatch '^0\.1\.0$') { throw 'Installed package version mismatch.' }
    $marker = Get-Content -LiteralPath (Join-Path $target '.local-gpt-mcp-install.json') -Raw
    if ($marker -match 'token|secret|password') { throw 'Installer marker contains a secret.' }
} finally {
    if (Test-Path -LiteralPath $target) {
        & $uninstaller -InstallRoot $target -Confirm:$false
    }
}
if (Test-Path -LiteralPath $target) { throw 'Uninstaller left installed files.' }
Write-Output 'PASS: verified per-user install, deny-first startup, and clean uninstall.'
