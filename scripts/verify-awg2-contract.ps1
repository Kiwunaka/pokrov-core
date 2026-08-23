param(
  [string]$ContractPath
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $ContractPath) {
  $ContractPath = Join-Path $root "config\awg2-capability.json"
}
$ContractPath = [System.IO.Path]::GetFullPath($ContractPath)
if (-not $ContractPath.StartsWith([System.IO.Path]::GetFullPath($root), [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "AWG2 contract must stay inside the Core repository."
}
if (-not (Test-Path -LiteralPath $ContractPath -PathType Leaf)) {
  throw "AWG2 contract is missing."
}

$contract = Get-Content -Raw -LiteralPath $ContractPath | ConvertFrom-Json -Depth 32
if (
  $contract.schema_version -ne 1 -or
  $contract.contract_id -ne "pokrov.awg2.endpoint.v1" -or
  $contract.status -ne "prototype_disabled_by_default" -or
  $contract.public_runtime_advertised -ne $false -or
  $contract.engine.type -ne "awg" -or
  $contract.engine.build_tag -ne "with_awg" -or
  $contract.engine.android_release_build -ne $true -or
  $contract.engine.windows_release_build -ne $true
) {
  throw "AWG2 contract identity or prototype state is invalid."
}
if ((@($contract.supported_platforms) -join ',') -ne 'android,windows') {
  throw "AWG2 contract may target only Android and Windows in this slice."
}
if (
  $contract.typed_endpoint.type -ne "awg" -or
  $contract.typed_endpoint.use_integrated_tun -ne $false -or
  $contract.typed_endpoint.peer_count -ne 1 -or
  $contract.typed_endpoint.key_encoding -ne "base64" -or
  $contract.typed_endpoint.key_bytes -ne 32 -or
  (@($contract.typed_endpoint.allowed_mtu) -join ',') -ne '1280,1400,1408' -or
  (@($contract.typed_endpoint.unsupported_fields) -join ',') -ne 'i1,i2,i3,i4,i5'
) {
  throw "AWG2 typed endpoint subset is invalid."
}

$module = "$($contract.dependency.module) $($contract.dependency.version)"
$sum = "$module $($contract.dependency.module_sum)"
foreach ($path in @("go.mod", "engine\sing-box\go.mod")) {
  $content = Get-Content -Raw -LiteralPath (Join-Path $root $path)
  if (-not $content.Contains($module)) {
    throw "$path does not pin $module."
  }
}
foreach ($path in @("go.sum", "engine\sing-box\go.sum")) {
  $content = Get-Content -Raw -LiteralPath (Join-Path $root $path)
  if (-not $content.Contains($sum)) {
    throw "$path does not pin the AWG2 module sum."
  }
}
foreach ($path in @("scripts\build-android.ps1", "scripts\build-windows.ps1")) {
  $content = Get-Content -Raw -LiteralPath (Join-Path $root $path)
  if (-not $content.Contains('"with_awg"') -or -not $content.Contains('verify-awg2-contract.ps1')) {
    throw "$path does not bind the AWG2 contract and build tag."
  }
}
$noticePath = Join-Path $root ([string]$contract.dependency.notice)
if (-not (Test-Path -LiteralPath $noticePath -PathType Leaf)) {
  throw "AWG2 dependency license notice is missing."
}
$converter = Get-Content -Raw -LiteralPath (Join-Path $root "ray2sing\ray2sing\convert.go")
if (
  -not $converter.Contains('"awg://":       rejectLegacyAWGConfig') -or
  -not $converter.Contains('"[Interface]":  rejectLegacyAWGTextConfig')
) {
  throw "Legacy raw AWG converter is not fail-closed."
}
$awgConverter = Get-Content -Raw -LiteralPath (Join-Path $root "ray2sing\ray2sing\awg.go")
if ($awgConverter.Contains('if true ||')) {
  throw "Legacy AWG converter still contains an unconditional transport branch."
}

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ContractPath).Hash.ToLowerInvariant()
Write-Host "POKROV AWG2 contract OK: $($contract.contract_id) sha256=$hash" -ForegroundColor Green
