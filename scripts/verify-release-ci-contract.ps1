[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$workflow = Get-Content -Raw -LiteralPath (Join-Path $root ".github\workflows\ci.yml")
$androidBuild = Get-Content -Raw -LiteralPath (Join-Path $root "scripts\build-android.ps1")
$appleBuild = Get-Content -Raw -LiteralPath (Join-Path $root "scripts\build-apple.sh")

$required = @(
  "android-artifact-reproducibility:",
  "windows-artifact-reproducibility:",
  "apple-source-build:",
  "honnef.co/go/tools/cmd/staticcheck@v0.7.0",
  "-checks='SA2*,SA5*,SA6*'",
  "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0",
  "govulncheck@v1.7.0",
  "FuzzParseConfigDoesNotPanic",
  "new-release-artifact-evidence.ps1",
  "test-windows-core-proxy-only.ps1",
  "actions/upload-artifact@v4",
  "RequireCleanSource"
)
foreach ($needle in $required) {
  if (-not $workflow.Contains($needle)) {
    throw "Core CI is missing required release contract token: $needle"
  }
}
foreach ($build in @(
  @{ Token = "build-android.ps1"; Count = 2 },
  @{ Token = "build-windows.ps1"; Count = 2 },
  @{ Token = "build-apple.sh"; Count = 2 }
)) {
  $actual = ([regex]::Matches($workflow, [regex]::Escape($build.Token))).Count
  if ($actual -lt $build.Count) {
    throw "Core CI must invoke $($build.Token) at least $($build.Count) times; found $actual."
  }
}
foreach ($forbidden in @(
  "contents: write",
  "id-token: write",
  "attest-build-provenance",
  "gh release",
  "upload-release-asset",
  "create-release"
)) {
  if ($workflow.Contains($forbidden)) {
    throw "Pre-candidate Core CI must not contain '$forbidden'."
  }
}
if (-not $androidBuild.Contains('if ($IsWindows) { ".exe" } else { "" }')) {
  throw "Android release build must resolve gomobile names on Windows and Unix runners."
}
if (-not $androidBuild.Contains('[System.IO.Path]::PathSeparator')) {
  throw "Android release build must use the runner-native PATH separator."
}
if (-not $appleBuild.Contains('OUTPUT_DIRECTORY="${1:-$ROOT/dist/apple}"')) {
  throw "Apple release build must accept isolated output roots for two-build comparison."
}
if (-not (Test-Path -LiteralPath (Join-Path $root "v2\config\parser_fuzz_test.go") -PathType Leaf)) {
  throw "The config/profile parser fuzz target is missing."
}

Write-Host "Core release CI contract OK: Linux tests/security, Android/Windows/Apple builds, two-build comparison, SBOM, bounded provenance, app backtest." -ForegroundColor Green
