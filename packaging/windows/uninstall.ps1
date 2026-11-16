# Remove only a verified per-user installation. Never alter user profiles or browser data.
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\LocalGPTMCP')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$base = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\')
$destination = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
if (-not $destination.StartsWith("$base\", [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to uninstall outside the current user LocalAppData.'
}
if (-not (Test-Path -LiteralPath $destination)) {
    Write-Output 'Local GPT MCP is not installed at the selected location.'
    exit 0
}
$item = Get-Item -LiteralPath $destination -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Refusing to remove a reparse-point installation.'
}
$marker = Join-Path $destination '.local-gpt-mcp-install.json'
if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
    throw 'Refusing to remove an unmarked directory.'
}
if (((Get-Item -LiteralPath $marker -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Refusing a linked ownership marker.'
}
$owner = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
if ($owner.application -ne 'local-gpt-mcp' -or $owner.version -ne 1) {
    throw 'Ownership marker is invalid.'
}
if ($PSCmdlet.ShouldProcess($destination, 'Remove verified per-user installation')) {
    Remove-Item -LiteralPath $destination -Recurse -Force
    Write-Output 'Removed verified Local GPT MCP installation.'
}
