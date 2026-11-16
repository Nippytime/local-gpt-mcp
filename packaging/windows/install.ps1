# Per-user installer. No elevation, services, scheduled tasks, or auto-start.
# Example: pwsh -NoProfile -File packaging/windows/install.ps1
[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\LocalGPTMCP')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$application = 'local-gpt-mcp'
$base = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\')
$destination = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
if (-not $destination.StartsWith("$base\", [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Installation must remain inside the current user LocalAppData directory.'
}
if (-not (Test-Path -LiteralPath $base -PathType Container)) {
    throw 'LocalAppData is unavailable.'
}
$marker = Join-Path $destination '.local-gpt-mcp-install.json'
$existed = Test-Path -LiteralPath $destination
if ($existed) {
    $item = Get-Item -LiteralPath $destination -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Refusing installation to a reparse-point directory.'
    }
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw 'Existing directory is not an owned Local GPT MCP installation.'
    }
    $previous = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    if ($previous.application -ne $application) {
        throw 'Installation ownership marker is invalid.'
    }
    if (((Get-Item -LiteralPath $marker -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Refusing installation with a linked ownership marker.'
    }
}
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if (-not (Test-Path -LiteralPath (Join-Path $repository 'pyproject.toml') -PathType Leaf)) {
    throw 'Run installer from a checked-out project distribution.'
}
$python = (Get-Command python -ErrorAction Stop).Source
& $python -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ required"'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 or newer is required.' }
try {
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $venv = Join-Path $destination 'venv'
    if (-not (Test-Path -LiteralPath (Join-Path $venv 'Scripts\python.exe'))) {
        & $python -m venv $venv
        if ($LASTEXITCODE -ne 0) { throw 'Unable to create Python environment.' }
    }
    $binary = Join-Path $venv 'Scripts\python.exe'
    & $binary -m pip install --disable-pip-version-check $repository
    if ($LASTEXITCODE -ne 0) { throw 'Package installation failed.' }
    $launcher = @'
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Arguments
)
& (Join-Path $PSScriptRoot 'venv\Scripts\python.exe') -m local_gpt_mcp @Arguments
exit $LASTEXITCODE
'@
    Set-Content -LiteralPath (Join-Path $destination 'Start-LocalGPTMCP.ps1') -Value $launcher -Encoding utf8
    @{
        application = $application
        version = 1
        auto_start = $false
        installed_for = 'current-user'
    } | ConvertTo-Json | Set-Content -LiteralPath $marker -Encoding utf8
} catch {
    if (-not $existed -and (Test-Path -LiteralPath $destination)) {
        Remove-Item -LiteralPath $destination -Recurse -Force
    }
    throw
}
Write-Output "Installed (user only, opt-in): $destination"
Write-Output 'No startup tasks or services were registered.'
