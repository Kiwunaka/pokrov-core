[CmdletBinding()]
param(
  [string]$ContractPath,
  [string]$ReleasePath,
  [string]$DesktopSourceDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ContractPath)) {
  $ContractPath = Join-Path $root "config\abi-contract.json"
}
if ([string]::IsNullOrWhiteSpace($ReleasePath)) {
  $ReleasePath = Join-Path $root "config\release.json"
}
if ([string]::IsNullOrWhiteSpace($DesktopSourceDirectory)) {
  $DesktopSourceDirectory = Join-Path $root "platform\desktop"
}

function Read-JsonContract {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Required ABI contract is missing: $Path"
  }
  return [IO.File]::ReadAllText($Path) | ConvertFrom-Json
}

function Assert-SameSet {
  param(
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][object[]]$Actual,
    [Parameter(Mandatory = $true)][object[]]$Expected
  )

  $actualValues = @($Actual | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive -Unique)
  $expectedValues = @($Expected | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive -Unique)
  $difference = @(Compare-Object -ReferenceObject $expectedValues -DifferenceObject $actualValues -CaseSensitive)
  if ($difference.Count -ne 0 -or $actualValues.Count -ne $expectedValues.Count) {
    throw "$Label disagrees with config\abi-contract.json."
  }
}

$contract = Read-JsonContract $ContractPath
$release = Read-JsonContract $ReleasePath

if ([int]$contract.schema_version -ne 1) {
  throw "Unsupported ABI contract schema version."
}
if ([int]$release.desktop_abi -ne [int]$contract.desktop_abi.version) {
  throw "config\release.json desktop_abi disagrees with config\abi-contract.json."
}
if ($release.abi_contract -ne "config/abi-contract.json") {
  throw "config\release.json must name the canonical ABI contract."
}
if ($release.core_event_abi_contract -ne "config/core-event-abi.json") {
  throw "config\release.json must name the canonical Core event ABI contract."
}
if ($contract.desktop_abi.marker_symbol -ne "pokrovCoreAbiVersion" -or
    $contract.desktop_abi.capabilities_symbol -ne "pokrovCoreCapabilities" -or
    $contract.desktop_abi.string_release_symbol -ne "freeString") {
  throw "Desktop ABI marker, capability, or string ownership symbol changed without a schema decision."
}
if (@($contract.desktop_abi.legacy_compatible_without_capabilities_symbol).Count -ne 1 -or
    [int]$contract.desktop_abi.legacy_compatible_without_capabilities_symbol[0] -ne 2) {
  throw "Only legacy desktop ABI 2 may omit the additive capabilities symbol."
}

$desktopSources = @(
  Get-ChildItem -LiteralPath $DesktopSourceDirectory -Filter "*.go" -File |
    Sort-Object FullName
)
if ($desktopSources.Count -eq 0) {
  throw "Desktop ABI sources are missing: $DesktopSourceDirectory"
}
$sourceText = ($desktopSources | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n"
$exportMatches = [regex]::Matches($sourceText, '(?m)^//export\s+([A-Za-z][A-Za-z0-9_]*)\s*$')
$actualExports = @($exportMatches | ForEach-Object { $_.Groups[1].Value })
if (@($actualExports | Group-Object | Where-Object Count -gt 1).Count -ne 0) {
  throw "Desktop ABI contains duplicate //export declarations."
}
Assert-SameSet -Label "Desktop exported symbols" -Actual $actualExports -Expected @($contract.desktop_abi.exports)

$requiredExports = @($contract.desktop_abi.client_required_exports)
foreach ($symbol in $requiredExports) {
  if (@($contract.desktop_abi.exports) -notcontains [string]$symbol) {
    throw "Client-required symbol '$symbol' is absent from the exported symbol contract."
  }
}

$abiConstant = [regex]::Match($sourceText, '(?m)^const pokrovDesktopABIVersion = ([0-9]+)\s*$')
if (-not $abiConstant.Success -or
    [int]$abiConstant.Groups[1].Value -ne [int]$contract.desktop_abi.version) {
  throw "pokrovDesktopABIVersion disagrees with the canonical ABI contract."
}

$descriptorConstant = [regex]::Match(
  $sourceText,
  '(?m)^const pokrovCoreCapabilitiesJSON = `([^`]+)`\s*$'
)
if (-not $descriptorConstant.Success) {
  throw "pokrovCoreCapabilitiesJSON is missing from the desktop ABI source."
}
$expectedDescriptor = $contract.descriptor | ConvertTo-Json -Depth 10 -Compress
if ($descriptorConstant.Groups[1].Value -ne $expectedDescriptor) {
  throw "pokrovCoreCapabilitiesJSON disagrees with config\abi-contract.json."
}
if ([int]$contract.descriptor.desktop_abi -ne [int]$contract.desktop_abi.version -or
    [int]$contract.descriptor.schema_version -ne 1 -or
    [int]$contract.descriptor.event_abi -ne 1) {
  throw "Capability descriptor version fields disagree with the ABI contract."
}

Assert-SameSet -Label "Capability identifiers" -Actual @($contract.descriptor.capabilities) -Expected @(
  "bounded_stop_reason",
  "core_start_stop",
  "materialized_profile",
  "secure_profile_file",
  "structured_operational_events",
  "typed_lifecycle_events"
)
Assert-SameSet -Label "Lifecycle event identifiers" -Actual @($contract.descriptor.lifecycle_events) -Expected @(
  "initialization",
  "profile",
  "core_start",
  "tun",
  "routes",
  "dns",
  "egress",
  "recovery",
  "stop"
)

$eventContractPath = Join-Path $root ([string]$contract.descriptor.operational_events.contract)
$eventContract = Read-JsonContract $eventContractPath
if ([int]$eventContract.schema_version -ne 1 -or
    [int]$eventContract.event_abi -ne [int]$contract.descriptor.event_abi -or
    [int]$eventContract.desktop_abi -ne [int]$contract.desktop_abi.version -or
    $eventContract.callback_symbol -ne $contract.descriptor.operational_events.callback_symbol -or
    $eventContract.context_symbol -ne $contract.descriptor.operational_events.context_symbol -or
    [int]$eventContract.maximum_pending_events -ne
      [int]$contract.descriptor.operational_events.maximum_pending_events) {
  throw "Core event ABI contract disagrees with the capability descriptor."
}
foreach ($symbol in @($eventContract.callback_symbol, $eventContract.context_symbol)) {
  if (@($contract.desktop_abi.exports) -notcontains [string]$symbol) {
    throw "Core event ABI symbol '$symbol' is absent from the desktop export contract."
  }
}
Assert-SameSet -Label "Core event ABI fields" -Actual @($eventContract.fields) -Expected @(
  "schema_version",
  "event_abi",
  "occurred_at_utc",
  "run_id",
  "attempt_id",
  "generation",
  "sequence",
  "name",
  "subsystem",
  "stage",
  "severity",
  "outcome",
  "error_code",
  "phase"
)
Assert-SameSet -Label "Core event ABI error codes" -Actual @($eventContract.error_codes) -Expected @(
  "CORE-003",
  "CORE-005",
  "CORE-006",
  "CORE-008",
  "EGRESS-001",
  "TRANSPORT-001",
  "TRANSPORT-002",
  "TRANSPORT-003",
  "TRANSPORT-004"
)
if (@($eventContract.events).Count -ne 4 -or
    (@($eventContract.events.name) -join ',') -ne
      'core.runtime.initialize,core.runtime.start,core.runtime.stop,core.egress.probe') {
  throw "Core event ABI event definitions changed without a contract decision."
}

Write-Host "POKROV Core ABI contract OK: desktop=2 descriptor=1 events=1 exports=$($actualExports.Count)" -ForegroundColor Green
