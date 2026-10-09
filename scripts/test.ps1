param(
  [string]$GoExecutable = "go"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$release = Get-Content -Raw -LiteralPath (Join-Path $root "config\release.json") | ConvertFrom-Json
$version = (Get-Content -Raw -LiteralPath (Join-Path $root "VERSION")).Trim()
if ($version -ne $release.version) {
  throw "VERSION and config/release.json must identify the same Core version."
}
$goCommand = Get-Command $GoExecutable -ErrorAction SilentlyContinue
if (-not $goCommand) {
  throw "$($release.go_toolchain) is required."
}
$goVersion = (& $goCommand.Source env GOVERSION).Trim()
if ($LASTEXITCODE -ne 0 -or $goVersion -ne $release.go_toolchain) {
  throw "Expected $($release.go_toolchain), got '$goVersion'."
}

& (Join-Path $PSScriptRoot "verify-abi-contract.ps1")

$previousToolchain = $env:GOTOOLCHAIN
$clientTags = @(
  "pokrov_client", "with_gvisor", "with_quic", "with_wireguard", "with_utls",
  "with_clash_api", "with_grpc", "with_awg", "tfogo_checklinkname0",
  "with_naive_outbound", "with_conntrack", "with_purego"
) -join ","
try {
  $env:GOTOOLCHAIN = "local"

  $goFiles = @(
    Get-ChildItem -LiteralPath (Join-Path $root "platform"), (Join-Path $root "v2"), (Join-Path $root "ray2sing"), (Join-Path $root "internal") -Recurse -Filter "*.go" |
      Select-Object -ExpandProperty FullName
  )
  $gofmtName = if ($IsWindows) { "gofmt.exe" } else { "gofmt" }
  $gofmtPath = Join-Path (Split-Path -Parent $goCommand.Source) $gofmtName
  if (-not (Test-Path -LiteralPath $gofmtPath -PathType Leaf)) {
    throw "gofmt is required."
  }
  $unformatted = @(& $gofmtPath -l $goFiles)
  if ($LASTEXITCODE -ne 0) {
    throw "gofmt check failed."
  }
  if ($unformatted.Count -gt 0) {
    $unformatted | Write-Error
    throw "Go files are not formatted."
  }

  Push-Location $root
  try {
    & $goCommand.Source test -count=1 -ldflags=-checklinkname=0 -tags $clientTags ./...
    if ($LASTEXITCODE -ne 0) {
      throw "POKROV Core module tests failed."
    }
    if ($IsWindows) {
      & $goCommand.Source test -count=1 -tags pokrov_wintun_test -run '^TestPokrov(FinalizerPassesAdapterHandle|FailedSessionClosesAdapterImmediately)$' github.com/sagernet/sing-tun/internal/wintun github.com/sagernet/sing-tun
      if ($LASTEXITCODE -ne 0) {
        throw "Windows adapter ownership tests failed."
      }
    }
  } finally {
    Pop-Location
  }

  Push-Location (Join-Path $root "engine\sing-box")
  try {
    & $goCommand.Source test -count=1 -tags with_awg,with_utls,with_quic . ./protocol/awg ./common/tls ./common/urltest ./daemon ./experimental/libbox ./dns ./protocol/group ./transport/v2rayxhttp
    if ($LASTEXITCODE -ne 0) {
      throw "Engine tests failed."
    }
  } finally {
    Pop-Location
  }
} finally {
  $env:GOTOOLCHAIN = $previousToolchain
}

Write-Host "POKROV Core tests OK." -ForegroundColor Green
