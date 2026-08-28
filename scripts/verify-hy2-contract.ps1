param(
  [string]$ContractPath
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $ContractPath) {
  $ContractPath = Join-Path $root "config\hy2-capability.json"
}
$ContractPath = [System.IO.Path]::GetFullPath($ContractPath)
if (-not $ContractPath.StartsWith([System.IO.Path]::GetFullPath($root), [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "Hysteria2 contract must stay inside the Core repository."
}
if (-not (Test-Path -LiteralPath $ContractPath -PathType Leaf)) {
  throw "Hysteria2 contract is missing."
}

$contract = Get-Content -Raw -LiteralPath $ContractPath | ConvertFrom-Json -Depth 32
if (
  $contract.schema_version -ne 1 -or
  $contract.contract_id -ne "pokrov.hy2.outbound.v1" -or
  $contract.status -ne "lab_disabled_by_default" -or
  $contract.public_runtime_advertised -ne $false -or
  $contract.engine.type -ne "hysteria2" -or
  $contract.engine.build_tag -ne "with_quic" -or
  $contract.engine.android_release_build -ne $true -or
  $contract.engine.windows_release_build -ne $true
) {
  throw "Hysteria2 contract identity or lab state is invalid."
}
if ((@($contract.supported_platforms) -join ',') -ne 'android,windows') {
  throw "Hysteria2 lab may target only Android and Windows."
}
$typed = $contract.typed_outbound
if (
  $typed.type -ne "hysteria2" -or
  $typed.managed_profile_required -ne $true -or
  $typed.raw_uri_conversion_allowed -ne $false -or
  $typed.single_server_port_required -ne $true -or
  $typed.port_hopping_allowed -ne $false -or
  $typed.tls_required -ne $true -or
  $typed.tls_insecure_allowed -ne $false -or
  $typed.tls_server_name_required -ne $true -or
  (@($typed.allowed_obfs_types) -join ',') -ne 'none,salamander' -or
  $typed.minimum_password_bytes -ne 16 -or
  $typed.maximum_password_bytes -ne 128 -or
  $typed.minimum_bandwidth_mbps -ne 1 -or
  $typed.maximum_bandwidth_mbps -ne 1000
) {
  throw "Hysteria2 typed outbound bounds are invalid."
}
if (
  $contract.dependency.module -ne "github.com/sagernet/sing-box" -or
  $contract.dependency.version -ne "v1.13.0" -or
  $contract.dependency.license -ne "GPL-3.0-or-later"
) {
  throw "Hysteria2 dependency identity is invalid."
}
$noticePath = Join-Path $root ([string]$contract.dependency.notice)
if (-not (Test-Path -LiteralPath $noticePath -PathType Leaf)) {
  throw "Hysteria2 dependency license notice is missing."
}
$rootMod = Get-Content -Raw -LiteralPath (Join-Path $root "go.mod")
if (-not $rootMod.Contains("github.com/sagernet/sing-box v1.13.0")) {
  throw "Root go.mod does not pin sing-box v1.13.0."
}
foreach ($path in @("scripts\build-android.ps1", "scripts\build-windows.ps1")) {
  $content = Get-Content -Raw -LiteralPath (Join-Path $root $path)
  if (-not $content.Contains('"with_quic"') -or -not $content.Contains('verify-hy2-contract.ps1')) {
    throw "$path does not bind the Hysteria2 contract and QUIC build tag."
  }
}
$optionSource = Get-Content -Raw -LiteralPath (Join-Path $root "engine\sing-box\option\hysteria2.go")
$outboundSource = Get-Content -Raw -LiteralPath (Join-Path $root "engine\sing-box\protocol\hysteria2\outbound.go")
$converterSource = Get-Content -Raw -LiteralPath (Join-Path $root "ray2sing\ray2sing\hysteria2.go")
foreach ($field in @('server_ports', 'hop_interval', 'up_mbps', 'down_mbps', 'password')) {
  if (-not $optionSource.Contains($field)) {
    throw "Embedded Hysteria2 option mapping is missing $field."
  }
}
if (
  -not $optionSource.Contains('OutboundTLSOptionsContainer') -or
  -not $outboundSource.Contains('TypeHysteria2') -or
  -not $converterSource.Contains('raw Hysteria2 URI conversion is disabled')
) {
  throw "Hysteria2 runtime registration or raw-URI rejection is missing."
}

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ContractPath).Hash.ToLowerInvariant()
Write-Host "POKROV Hysteria2 contract OK: $($contract.contract_id) sha256=$hash" -ForegroundColor Green
