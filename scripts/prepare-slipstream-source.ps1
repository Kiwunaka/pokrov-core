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
$patches = @('pokrov-local-io.patch', 'pokrov-active-poll.patch', 'pokrov-multipath.patch')
# The multipath patch changes the file introduced by the local I/O patch.
$lastPatch = Join-Path $root "third_party/slipstream/$($patches[-1])"
& git -C $SourceDirectory apply --reverse --check $lastPatch *> $null
if ($LASTEXITCODE -eq 0) { $patches = @() }
$patches += 'pokrov-dns-reorder.patch'
foreach ($name in $patches) {
  $patch = Join-Path $root "third_party/slipstream/$name"
  & git -C $SourceDirectory apply --reverse --check $patch *> $null
  if ($LASTEXITCODE -eq 0) { continue }
  & git -C $SourceDirectory apply --check $patch
  if ($LASTEXITCODE -ne 0) { throw "Slipstream patch does not apply: $name" }
  & git -C $SourceDirectory apply $patch
  if ($LASTEXITCODE -ne 0) { throw "Could not apply Slipstream patch: $name" }
}
