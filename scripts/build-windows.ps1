param(
  [string]$GoExecutable = "go",
  [string]$CCompiler = "x86_64-w64-mingw32-gcc",
  [string]$OutputDirectory,
  [string]$CronetLibrary
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$release = Get-Content -Raw -LiteralPath (Join-Path $root "config\release.json") | ConvertFrom-Json
if (-not $OutputDirectory) {
  $OutputDirectory = Join-Path $root "dist\windows"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$goCommand = Get-Command $GoExecutable -ErrorAction SilentlyContinue
if (-not $goCommand) {
  throw "Go 1.25.12 is required."
}
$goVersion = (& $goCommand.Source env GOVERSION).Trim()
if ($LASTEXITCODE -ne 0 -or $goVersion -ne $release.go_toolchain) {
  throw "Expected $($release.go_toolchain), got '$goVersion'."
}
$compilerCommand = Get-Command $CCompiler -ErrorAction SilentlyContinue
if (-not $compilerCommand) {
  throw "MinGW-w64 compiler '$CCompiler' was not found."
}

$outputPath = Join-Path $OutputDirectory $release.artifacts.windows
$tags = @(
  "with_gvisor",
  "with_quic",
  "with_wireguard",
  "with_utls",
  "with_clash_api",
  "with_grpc",
  "with_awg",
  "tfogo_checklinkname0",
  "with_naive_outbound",
  "with_conntrack",
  "with_purego"
) -join ","

$previousGoos = $env:GOOS
$previousGoarch = $env:GOARCH
$previousCgo = $env:CGO_ENABLED
$previousCc = $env:CC
$previousToolchain = $env:GOTOOLCHAIN
try {
  $env:GOOS = "windows"
  $env:GOARCH = "amd64"
  $env:CGO_ENABLED = "1"
  $env:CC = $compilerCommand.Source
  $env:GOTOOLCHAIN = "local"

  Push-Location $root
  try {
    & $goCommand.Source build `
      -trimpath `
      -tags $tags `
      -ldflags "-w -s -checklinkname=0 -buildid= -X github.com/Kiwunaka/POKROV-core/v2/hcommon/constants.Version=$($release.version)" `
      -buildmode=c-shared `
      -o $outputPath `
      ./platform/desktop
    if ($LASTEXITCODE -ne 0) {
      throw "Windows runtime build failed."
    }
  } finally {
    Pop-Location
  }
} finally {
  $env:GOOS = $previousGoos
  $env:GOARCH = $previousGoarch
  $env:CGO_ENABLED = $previousCgo
  $env:CC = $previousCc
  $env:GOTOOLCHAIN = $previousToolchain
}

$cronetOutput = Join-Path $OutputDirectory "libcronet.dll"
$expectedCronetSize = [int64]$release.local_build_evidence.windows.libcronet.size
$expectedCronetSha256 = [string]$release.local_build_evidence.windows.libcronet.sha256

function Test-CronetIdentity {
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return $false
  }
  $file = Get-Item -LiteralPath $Path
  if ($file.Length -ne $expectedCronetSize) {
    return $false
  }
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
  return $hash -eq $expectedCronetSha256
}

if ($CronetLibrary) {
  $CronetLibrary = [System.IO.Path]::GetFullPath($CronetLibrary)
  if (-not (Test-CronetIdentity -Path $CronetLibrary)) {
    throw "Cronet library does not match the pinned size and SHA-256: $CronetLibrary"
  }
  if ($CronetLibrary -ne $cronetOutput) {
    Copy-Item -Force -LiteralPath $CronetLibrary -Destination $cronetOutput
  }
} elseif (-not (Test-CronetIdentity -Path $cronetOutput)) {
  throw "Pinned libcronet.dll is unavailable. Pass -CronetLibrary with the exact dependency recorded in config/release.json."
}

if (-not (Test-CronetIdentity -Path $cronetOutput)) {
  throw "Windows Cronet dependency failed its final identity check."
}

Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath, $cronetOutput |
  Select-Object Path, Hash
