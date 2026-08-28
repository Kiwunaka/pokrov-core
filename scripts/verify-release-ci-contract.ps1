[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$workflow = Get-Content -Raw -LiteralPath (Join-Path $root ".github\workflows\ci.yml")
$androidBuild = Get-Content -Raw -LiteralPath (Join-Path $root "scripts\build-android.ps1")
$appleBuild = Get-Content -Raw -LiteralPath (Join-Path $root "scripts\build-apple.sh")
$appleDiagnostic = Get-Content -Raw -LiteralPath (Join-Path $root "scripts\diagnose-apple-reproducibility.sh")
$release = Get-Content -Raw -LiteralPath (Join-Path $root "config\release.json") | ConvertFrom-Json

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
  "diagnose-apple-reproducibility.sh",
  "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
  "POKROV_MINGW_GCC",
  "C:\ProgramData\mingw64",
  "actions/upload-artifact@v4",
  "POKROV_SOURCE_COMMIT",
  "ExpectedSourceCommit",
  "RequireCleanSource"
)
foreach ($needle in $required) {
  if (-not $workflow.Contains($needle)) {
    throw "Core CI is missing required release contract token: $needle"
  }
}
$sourceCheckoutToken = 'ref: ${{ env.POKROV_SOURCE_COMMIT }}'
$sourceCheckoutCount = ([regex]::Matches($workflow, [regex]::Escape($sourceCheckoutToken))).Count
if ($sourceCheckoutCount -ne 5) {
  throw "Every Core checkout must use the exact source authority; expected 5 explicit refs, found $sourceCheckoutCount."
}
$expectedCommitBinding = '-ExpectedSourceCommit "$env:POKROV_SOURCE_COMMIT"'
$expectedCommitBindingCount = ([regex]::Matches($workflow, [regex]::Escape($expectedCommitBinding))).Count
if ($expectedCommitBindingCount -ne 3) {
  throw "Every artifact evidence lane must verify the exact source authority; expected 3 bindings, found $expectedCommitBindingCount."
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
if ($androidBuild.Contains("tar.exe") -or $androidBuild.Contains("Get-Command tar") -or -not $androidBuild.Contains("[System.IO.Compression.ZipFile]::OpenRead")) {
  throw "Android release build must inspect the AAR through the cross-platform ZIP API."
}
if ($release.engine.android_ndk -ne "29.0.14206865" -or -not $androidBuild.Contains('ANDROID_NDK_HOME')) {
  throw "Android release build must pin and select NDK 29.0.14206865."
}
if (-not $appleBuild.Contains('OUTPUT_DIRECTORY="${1:-$ROOT/dist/apple}"')) {
  throw "Apple release build must accept isolated output roots for two-build comparison."
}
if (-not $appleBuild.Contains('-extldflags=-Wl,-no_uuid') -or
    -not $appleBuild.Contains('ZERO_AR_DATE=1') -or
    -not $appleBuild.Contains('AvailableLibraries') -or
    -not $appleBuild.Contains('LibraryIdentifier')) {
  throw "Apple release build must suppress random binary metadata and canonicalize the XCFramework library order."
}
if (-not $appleDiagnostic.Contains("diff -u") -or -not $appleDiagnostic.Contains("dwarfdump --uuid")) {
  throw "Apple release CI must retain plist and Mach-O UUID diagnostics before comparison."
}
if (-not (Test-Path -LiteralPath (Join-Path $root "v2\config\parser_fuzz_test.go") -PathType Leaf)) {
  throw "The config/profile parser fuzz target is missing."
}

$evidenceScript = Join-Path $root "scripts\new-release-artifact-evidence.ps1"
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("pokrov-core-evidence-contract-" + [guid]::NewGuid().ToString("N"))
$firstBuild = Join-Path $fixtureRoot "first"
$secondBuild = Join-Path $fixtureRoot "second"
$fixtureOutput = Join-Path $fixtureRoot "evidence.json"
try {
  New-Item -ItemType Directory -Force -Path $firstBuild,$secondBuild | Out-Null
  [System.IO.File]::WriteAllText((Join-Path $firstBuild "artifact.bin"), "same", [System.Text.UTF8Encoding]::new($false))
  [System.IO.File]::WriteAllText((Join-Path $secondBuild "artifact.bin"), "same", [System.Text.UTF8Encoding]::new($false))
  try {
    & $evidenceScript -Lane android -FirstBuildRoot $firstBuild -SecondBuildRoot $secondBuild -Output $fixtureOutput -ExpectedSourceCommit ("0" * 40)
    throw "Artifact evidence accepted a checkout that did not match the expected source commit."
  } catch {
    if ($_.Exception.Message -notmatch '^Expected source commit [0-9a-f]{40}, but the checkout is [0-9a-f]{40}\.$') {
      throw
    }
  }
} finally {
  if (Test-Path -LiteralPath $fixtureRoot) {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
  }
}

Write-Host "Core release CI contract OK: Linux tests/security, Android/Windows/Apple builds, two-build comparison, SBOM, bounded provenance, app backtest." -ForegroundColor Green
