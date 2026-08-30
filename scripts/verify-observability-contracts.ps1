[CmdletBinding()]
param(
  [string]$SnapshotPath,
  [string]$PlatformRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot

function Get-CanonicalTextSha256 {
  param([Parameter(Mandatory = $true)][string]$Path)

  $canonical = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n").Replace("`r", "`n")
  $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
  return [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($bytes)
  ).ToLowerInvariant()
}
if ([string]::IsNullOrWhiteSpace($SnapshotPath)) {
  $SnapshotPath = Join-Path $root "config\observability-contracts.json"
}

function Read-JsonFile {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Required observability contract is missing: $Path"
  }
  return [IO.File]::ReadAllText($Path) | ConvertFrom-Json
}

function Assert-ExactProperties {
  param(
    [Parameter(Mandatory = $true)]$Value,
    [Parameter(Mandatory = $true)][string[]]$Expected,
    [Parameter(Mandatory = $true)][string]$Path
  )

  $actual = @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)
  $wanted = @($Expected | Sort-Object -CaseSensitive)
  if (@(Compare-Object -ReferenceObject $wanted -DifferenceObject $actual -CaseSensitive).Count -ne 0) {
    throw "$Path has unsupported or missing properties."
  }
}

$snapshot = Read-JsonFile $SnapshotPath
Assert-ExactProperties -Value $snapshot `
  -Expected @("schema_version", "canonical_repository", "contracts") `
  -Path "observability snapshot"
if ([int]$snapshot.schema_version -ne 1 -or
    [string]$snapshot.canonical_repository -ne "Kiwunaka/portal") {
  throw "Unsupported observability snapshot identity."
}

$expectedVersions = @{
  "error-catalog" = "1.2.0"
  "observability-event" = "1.0.0"
}
$contracts = @($snapshot.contracts)
if ($contracts.Count -ne $expectedVersions.Count) {
  throw "Observability snapshot must contain exactly two canonical contracts."
}
$seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($contract in $contracts) {
  Assert-ExactProperties -Value $contract `
    -Expected @("id", "version", "sha256") -Path "observability snapshot contract"
  $id = [string]$contract.id
  if (-not $expectedVersions.ContainsKey($id) -or -not $seen.Add($id)) {
    throw "Observability snapshot contains an unknown or duplicate contract."
  }
  if ([string]$contract.version -ne $expectedVersions[$id] -or
      [string]$contract.sha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw "Observability snapshot contract identity is invalid."
  }
}

if (-not [string]::IsNullOrWhiteSpace($PlatformRoot)) {
  $platformPath = (Resolve-Path -LiteralPath $PlatformRoot).Path
  $canonicalPaths = @{
    "error-catalog" = Join-Path $platformPath "shared\contracts\observability\error-catalog.json"
    "observability-event" = Join-Path $platformPath "shared\contracts\observability\observability-event.schema.json"
  }
  foreach ($contract in $contracts) {
    $canonicalPath = $canonicalPaths[[string]$contract.id]
    if (-not (Test-Path -LiteralPath $canonicalPath -PathType Leaf)) {
      throw "Canonical platform observability contract is missing."
    }
    $actualHash = Get-CanonicalTextSha256 -Path $canonicalPath
    if ($actualHash -ne [string]$contract.sha256) {
      throw "Core observability snapshot disagrees with the canonical platform contract."
    }
  }
}

$legacyLogSources = @{
  (Join-Path $root "v2\hcore\grpc_server.go") = @(
    'Log(LogLevel_DEBUG, LogType_CORE, "PokrovSettingsJson", val, err)',
    'Log(LogLevel_DEBUG, LogType_CORE, table)'
  )
  (Join-Path $root "platform\desktop\custom.go") = @(
    'log.Error(err.Error())'
  )
}
foreach ($entry in $legacyLogSources.GetEnumerator()) {
  $source = [IO.File]::ReadAllText($entry.Key)
  foreach ($forbidden in $entry.Value) {
    if ($source.Contains($forbidden)) {
      throw "Legacy Core logging must not emit stored settings, database tables, or raw FFI errors."
    }
  }
}

Write-Host "POKROV Core observability contracts OK: schema=1 contracts=2" -ForegroundColor Green
