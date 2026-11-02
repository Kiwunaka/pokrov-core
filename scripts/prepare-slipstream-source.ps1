[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceDirectory)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$release = [IO.File]::ReadAllText((Join-Path $root 'config/release.json')) | ConvertFrom-Json
$SourceDirectory = [IO.Path]::GetFullPath($SourceDirectory)
$revision = (& git -C $SourceDirectory rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $revision -ne $release.engine.slipstream.revision) {
  throw 'Slipstream source must match config/release.json; initialize its pinned submodules first.'
}
$patch = Join-Path $root 'third_party/slipstream/pokrov-local-io.patch'
& git -C $SourceDirectory apply --reverse --check $patch *> $null
if ($LASTEXITCODE -eq 0) { return }
& git -C $SourceDirectory apply --check $patch
if ($LASTEXITCODE -ne 0) { throw 'Slipstream local I/O patch does not apply to this source checkout.' }
& git -C $SourceDirectory apply $patch
if ($LASTEXITCODE -ne 0) { throw 'Could not apply the Slipstream local I/O patch.' }
