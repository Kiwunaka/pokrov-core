param(
  [string]$GoExecutable = "go",
  [string]$AndroidSdk,
  [string]$GomobileBinDirectory,
  [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$release = Get-Content -Raw -LiteralPath (Join-Path $root "config\release.json") | ConvertFrom-Json
if (-not $OutputDirectory) {
  $OutputDirectory = Join-Path $root "dist\android"
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

if (-not $AndroidSdk) {
  $AndroidSdk = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { $env:ANDROID_HOME }
}
if (-not $AndroidSdk -or -not (Test-Path -LiteralPath $AndroidSdk -PathType Container)) {
  throw "Pass -AndroidSdk or set ANDROID_SDK_ROOT."
}
$AndroidSdk = [System.IO.Path]::GetFullPath($AndroidSdk)

if (-not $GomobileBinDirectory) {
  $GomobileBinDirectory = Join-Path $root "tmp\gomobile-go1.25.12"
}
$GomobileBinDirectory = [System.IO.Path]::GetFullPath($GomobileBinDirectory)
New-Item -ItemType Directory -Force -Path $GomobileBinDirectory | Out-Null
$gomobile = Join-Path $GomobileBinDirectory "gomobile.exe"
$gobind = Join-Path $GomobileBinDirectory "gobind.exe"
$outputPath = Join-Path $OutputDirectory $release.artifacts.android

$previousPath = $env:PATH
$previousGobin = $env:GOBIN
$previousToolchain = $env:GOTOOLCHAIN
$previousAndroidHome = $env:ANDROID_HOME
$previousAndroidSdkRoot = $env:ANDROID_SDK_ROOT
$previousCgoLdflags = $env:CGO_LDFLAGS
$previousNativeArgumentPassing = $PSNativeCommandArgumentPassing
try {
  $goBinDirectory = Split-Path -Parent $goCommand.Source
  $env:PATH = "$goBinDirectory;$GomobileBinDirectory;$previousPath"
  $env:GOBIN = $GomobileBinDirectory
  $env:GOTOOLCHAIN = "local"
  $env:ANDROID_HOME = $AndroidSdk
  $env:ANDROID_SDK_ROOT = $AndroidSdk
  $env:CGO_LDFLAGS = "-O2 -g -s -w -Wl,-z,max-page-size=16384"
  $PSNativeCommandArgumentPassing = "Standard"

  if (-not (Test-Path -LiteralPath $gomobile)) {
    & $goCommand.Source install "github.com/sagernet/gomobile/cmd/gomobile@v$($release.engine.gomobile)"
    if ($LASTEXITCODE -ne 0) { throw "Could not install gomobile." }
  }
  if (-not (Test-Path -LiteralPath $gobind)) {
    & $goCommand.Source install "github.com/sagernet/gomobile/cmd/gobind@v$($release.engine.gomobile)"
    if ($LASTEXITCODE -ne 0) { throw "Could not install gobind." }
  }

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
    "with_conntrack"
  ) -join ","

  Push-Location $root
  try {
    & $gomobile bind `
      -androidapi 21 `
      -javapkg $release.android_package `
      -libname "pokrov-core" `
      -tags $tags `
      -trimpath `
      -ldflags "-w -s -checklinkname=0 -buildid= -X github.com/Kiwunaka/POKROV-core/v2/hcommon/constants.Version=$($release.version)" `
      -target android `
      -gcflags "all=-N -l" `
      -o $outputPath `
      "github.com/sagernet/sing-box/experimental/libbox" `
      "./platform/mobile"
    if ($LASTEXITCODE -ne 0) {
      throw "Android runtime build failed."
    }
  } finally {
    Pop-Location
  }
} finally {
  $env:PATH = $previousPath
  $env:GOBIN = $previousGobin
  $env:GOTOOLCHAIN = $previousToolchain
  $env:ANDROID_HOME = $previousAndroidHome
  $env:ANDROID_SDK_ROOT = $previousAndroidSdkRoot
  $env:CGO_LDFLAGS = $previousCgoLdflags
  $PSNativeCommandArgumentPassing = $previousNativeArgumentPassing
}

$aarEntries = @(& tar.exe -tf $outputPath)
if ($LASTEXITCODE -ne 0) {
  throw "Could not inspect Android artifact."
}
foreach ($abi in @("armeabi-v7a", "arm64-v8a", "x86", "x86_64")) {
  if ($aarEntries -notcontains "jni/$abi/libpokrov-core.so") {
    throw "Android artifact is missing $abi/libpokrov-core.so."
  }
}

Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath |
  Select-Object Path, Hash
