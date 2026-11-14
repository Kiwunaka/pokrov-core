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
foreach ($name in @('pokrov-local-io.patch', 'pokrov-active-poll.patch')) {
  $patch = Join-Path $root "third_party/slipstream/$name"
  & git -C $SourceDirectory apply --reverse --check $patch *> $null
  if ($LASTEXITCODE -eq 0) { continue }
  & git -C $SourceDirectory apply --check $patch
  if ($LASTEXITCODE -ne 0) { throw "Slipstream patch does not apply: $name" }
  & git -C $SourceDirectory apply $patch
  if ($LASTEXITCODE -ne 0) { throw "Could not apply Slipstream patch: $name" }
}
