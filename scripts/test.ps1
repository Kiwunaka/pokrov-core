param(
  [string]$GoExecutable = "go"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$goCommand = Get-Command $GoExecutable -ErrorAction SilentlyContinue
if (-not $goCommand) {
  throw "Go 1.25.12 is required."
}
$goVersion = (& $goCommand.Source env GOVERSION).Trim()
if ($LASTEXITCODE -ne 0 -or $goVersion -ne "go1.25.12") {
  throw "Expected Go 1.25.12, got '$goVersion'."
}

& (Join-Path $PSScriptRoot "verify-brand.ps1")

$previousToolchain = $env:GOTOOLCHAIN
try {
  $env:GOTOOLCHAIN = "local"

  $goFiles = @(
    Get-ChildItem -LiteralPath (Join-Path $root "platform"), (Join-Path $root "v2"), (Join-Path $root "ray2sing") -Recurse -Filter "*.go" |
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
    & $goCommand.Source test ./v2/config ./v2/hcore ./v2/hutils ./ray2sing/ray2sing
    if ($LASTEXITCODE -ne 0) {
      throw "POKROV Core package tests failed."
    }
  } finally {
    Pop-Location
  }

  Push-Location (Join-Path $root "engine\sing-box")
  try {
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
