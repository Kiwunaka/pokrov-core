param(
  [string]$GoExecutable = "go"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$release = Get-Content -Raw -LiteralPath (Join-Path $root "config\release.json") | ConvertFrom-Json
$version = (Get-Content -Raw -LiteralPath (Join-Path $root "VERSION")).Trim()
if ($version -ne $release.version -or
    $release.version -ne "1.1.0" -or
    $release.state -ne "PRE_CANDIDATE_LOCAL" -or
    $release.candidate_created -ne $false) {
  throw "VERSION and config/release.json must identify the honest Core 1.1.0 pre-candidate target."
}
$retained = $release.retained_public_release
if ($retained.version -ne "1.0.3" -or
    $retained.release_tag -ne "v1.0.3" -or
    $retained.source_commit -ne "69a74545101708e56183c92e31f2b4c7b2509884" -or
    $retained.local_build_evidence.android.sha256 -ne
      "6e6f3b688fe415c9392e19aa4f8660885316897cfc369cf8c3ff3d01100ee14f" -or
    $retained.local_build_evidence.windows.sha256 -ne
      "7cc83854fc4022b759e9de3d0942b90a24c859cfd51e3231d04e7c7a6b7d5054") {
  throw "The retained public Core 1.0.3 release evidence changed."
}
$goCommand = Get-Command $GoExecutable -ErrorAction SilentlyContinue
if (-not $goCommand) {
  throw "$($release.go_toolchain) is required."
}
$goVersion = (& $goCommand.Source env GOVERSION).Trim()
if ($LASTEXITCODE -ne 0 -or $goVersion -ne $release.go_toolchain) {
  throw "Expected $($release.go_toolchain), got '$goVersion'."
}

& (Join-Path $PSScriptRoot "verify-brand.ps1")
& (Join-Path $PSScriptRoot "verify-abi-contract.ps1")
& (Join-Path $PSScriptRoot "verify-observability-contracts.ps1")
& (Join-Path $PSScriptRoot "verify-awg2-contract.ps1")
& (Join-Path $PSScriptRoot "verify-release-ci-contract.ps1")

$previousToolchain = $env:GOTOOLCHAIN
try {
  $env:GOTOOLCHAIN = "local"

  $goFiles = @(
    Get-ChildItem -LiteralPath (Join-Path $root "platform"), (Join-Path $root "v2"), (Join-Path $root "ray2sing"), (Join-Path $root "internal") -Recurse -Filter "*.go" |
      Select-Object -ExpandProperty FullName
  )
  $goFiles += @(
    "engine\sing-box\daemon\platform.go",
    "engine\sing-box\daemon\started_service.go",
    "engine\sing-box\experimental\libbox\command_server.go",
    "engine\sing-box\experimental\libbox\operational_events.go",
    "engine\sing-box\experimental\libbox\operational_events_test.go",
    "engine\sing-box\experimental\libbox\service.go"
  ) | ForEach-Object { Join-Path $root $_ }
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
    & $goCommand.Source test -count=1 ./...
    if ($LASTEXITCODE -ne 0) {
      throw "POKROV Core full module tests failed."
    }
  } finally {
    Pop-Location
  }

  Push-Location (Join-Path $root "engine\sing-box")
  try {
    & $goCommand.Source test -count=1 -tags with_awg ./protocol/awg
    if ($LASTEXITCODE -ne 0) {
      throw "AWG2 contract tests failed."
    }
    & $goCommand.Source test -count=1 ./daemon ./experimental/libbox
    if ($LASTEXITCODE -ne 0) {
      throw "Core event bridge tests failed."
    }
    & $goCommand.Source test -count=1 ./common/tls
    if ($LASTEXITCODE -ne 0) {
      throw "TLS tests failed."
    }
    & $goCommand.Source test -count=1 -tags with_utls ./common/tls
    if ($LASTEXITCODE -ne 0) {
      throw "uTLS tests failed."
    }
  } finally {
    Pop-Location
  }
} finally {
  $env:GOTOOLCHAIN = $previousToolchain
}

Write-Host "POKROV Core tests OK." -ForegroundColor Green
