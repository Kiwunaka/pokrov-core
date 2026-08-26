param(
  [string]$ContractPath
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $ContractPath) {
  $ContractPath = Join-Path $root "config\awg31-capability.json"
}
$ContractPath = [System.IO.Path]::GetFullPath($ContractPath)
if (-not $ContractPath.StartsWith([System.IO.Path]::GetFullPath($root), [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "AWG 3.1 contract must stay inside the Core repository."
}
if (-not (Test-Path -LiteralPath $ContractPath -PathType Leaf)) {
  throw "AWG 3.1 contract is missing."
}

$contract = Get-Content -Raw -LiteralPath $ContractPath | ConvertFrom-Json -Depth 32
if (
  $contract.schema_version -ne 1 -or
  $contract.contract_id -ne "pokrov.awg31.endpoint.v1" -or
  $contract.status -ne "lab_disabled_by_default" -or
  $contract.public_runtime_advertised -ne $false -or
  $contract.engine.type -ne "awg" -or
  $contract.engine.build_tag -ne "with_awg" -or
  $contract.engine.android_release_build -ne $true -or
  $contract.engine.windows_release_build -ne $true
) {
  throw "AWG 3.1 contract identity or lab state is invalid."
}
if ((@($contract.supported_platforms) -join ',') -ne 'android,windows') {
  throw "AWG 3.1 lab may target only Android and Windows."
}
if (
  $contract.compatibility.awg2_contract_id -ne "pokrov.awg2.endpoint.v1" -or
  $contract.compatibility.wire_compatible_with_awg2 -ne $false -or
  $contract.compatibility.separate_managed_profile_required -ne $true
) {
  throw "AWG 3.1 must remain a separate, incompatible managed profile."
}
if (
  $contract.typed_endpoint.type -ne "awg" -or
  $contract.typed_endpoint.explicit_contract_id_required -ne $true -or
  $contract.typed_endpoint.use_integrated_tun -ne $false -or
  $contract.typed_endpoint.peer_count -ne 1 -or
  $contract.typed_endpoint.key_encoding -ne "base64" -or
  $contract.typed_endpoint.key_bytes -ne 32 -or
  (@($contract.typed_endpoint.allowed_mtu) -join ',') -ne '1280,1400,1408' -or
  $contract.typed_endpoint.maximum_junk_packet_count -ne 128 -or
  $contract.typed_endpoint.maximum_junk_packet_size -ne 1279 -or
  $contract.typed_endpoint.maximum_padding_size -ne 65535 -or
  $contract.typed_endpoint.minimum_header_protection_padding -ne 12 -or
  $contract.typed_endpoint.maximum_instruction_packet_bytes -ne 512 -or
  $contract.typed_endpoint.maximum_content_padding_addition -ne 512 -or
  $contract.typed_endpoint.maximum_persistent_keepalive_seconds -ne 600
) {
  throw "AWG 3.1 typed endpoint bounds are invalid."
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
    throw "$path does not pin the AWG 3.1 module sum."
  }
}
foreach ($path in @("scripts\build-android.ps1", "scripts\build-windows.ps1")) {
  $content = Get-Content -Raw -LiteralPath (Join-Path $root $path)
  if (-not $content.Contains('"with_awg"') -or -not $content.Contains('verify-awg31-contract.ps1')) {
    throw "$path does not bind the AWG 3.1 contract and build tag."
  }
}

$noticePath = Join-Path $root ([string]$contract.dependency.notice)
if (-not (Test-Path -LiteralPath $noticePath -PathType Leaf)) {
  throw "AWG 3.1 dependency license notice is missing."
}
$optionSource = Get-Content -Raw -LiteralPath (Join-Path $root "engine\sing-box\option\awg.go")
$endpointSource = Get-Content -Raw -LiteralPath (Join-Path $root "engine\sing-box\protocol\awg\endpoint.go")
$contractSource = Get-Content -Raw -LiteralPath (Join-Path $root "engine\sing-box\protocol\awg\contract.go")
foreach ($field in @(
  'header_protection_key',
  'content_padding_addition',
  'rekey_after_time',
  'rekey_timeout',
  'reject_after_time',
  'keepalive_timeout',
  'max_handshake_attempts',
  'random_trailers'
)) {
  if (-not $optionSource.Contains($field) -or -not $endpointSource.Contains($field)) {
    throw "AWG 3.1 option or IPC mapping is missing $field."
  }
}
if (
  -not $optionSource.Contains('persistent_keepalive_interval_range') -or
  -not $endpointSource.Contains('PersistentKeepaliveIntervalRange') -or
  -not $endpointSource.Contains('persistent_keepalive_interval=')
) {
  throw "AWG 3.1 persistent keepalive range mapping is missing."
}
if (
  -not $contractSource.Contains('pokrov.awg31.endpoint.v1') -or
  -not $contractSource.Contains('header protection requires s1-s4 >= 12')
) {
  throw "AWG 3.1 fail-closed validator is missing."
}
$fixture = Get-Content -Raw -LiteralPath (Join-Path $root "engine\sing-box\protocol\awg\testdata\awg31-v1-dual-stack.json") | ConvertFrom-Json -Depth 32
if ($fixture.synthetic -ne $true -or $fixture.contract_id -ne $contract.contract_id) {
  throw "AWG 3.1 fixture must remain synthetic and contract-bound."
}

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ContractPath).Hash.ToLowerInvariant()
Write-Host "POKROV AWG 3.1 contract OK: $($contract.contract_id) sha256=$hash" -ForegroundColor Green
