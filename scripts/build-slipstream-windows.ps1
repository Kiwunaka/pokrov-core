[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$SourceDirectory,
  [Parameter(Mandatory)][string]$OutputDirectory,
  [Parameter(Mandatory)][string[]]$ToolDirectories
)

# Run in the Visual Studio 2022 x64 developer environment. ToolDirectories adds
# Cargo, CMake, full Windows Perl and pkgconf; the helper installs no tools.
$ErrorActionPreference = 'Stop'
$SourceDirectory = [IO.Path]::GetFullPath($SourceDirectory)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
& (Join-Path $PSScriptRoot 'prepare-slipstream-source.ps1') -SourceDirectory $SourceDirectory
$buildRoot = Join-Path $OutputDirectory '.build'
New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
$savedEnvironment = @{}

function Set-BuildEnvironment([string]$Name, [string]$Value) {
  if (-not $savedEnvironment.ContainsKey($Name)) {
    $savedEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name)
  }
  [Environment]::SetEnvironmentVariable($Name, $Value)
}

function Invoke-Build([string]$Program, [string[]]$Arguments, [string]$Log) {
  & $Program @Arguments *> $Log
  if ($LASTEXITCODE -ne 0) { throw "Native dependency build failed; see $Log" }
}

try {
  Set-BuildEnvironment PATH ((@($ToolDirectories) + $env:PATH) -join [IO.Path]::PathSeparator)
  $cargo = (Get-Command cargo -ErrorAction Stop).Source
  $perl = (Get-Command perl -ErrorAction Stop).Source
  $nmake = (Get-Command nmake -ErrorAction Stop).Source
  Get-Command cl, lib, cmake -ErrorAction Stop | Out-Null
  Set-BuildEnvironment CARGO_TARGET_DIR (Join-Path $buildRoot 'cargo')
  Set-BuildEnvironment OPENSSL_NO_VENDOR '1'
  Set-BuildEnvironment OPENSSL_STATIC '1'
  Set-BuildEnvironment OPENSSL_USE_STATIC_LIBS 'TRUE'
  Set-BuildEnvironment PICOQUIC_AUTO_BUILD '0'
  Push-Location $SourceDirectory
  try {
    $metadataText = & $cargo metadata --locked --format-version 1 --features openssl-vendored
    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the pinned Cargo dependency sources.' }
    $metadata = $metadataText | ConvertFrom-Json -Depth 100
    $opensslPackage = $metadata.packages | Where-Object name -EQ 'openssl-src'
    $opensslSource = Join-Path (Split-Path -Parent $opensslPackage.manifest_path) 'openssl'
    $opensslBuild = Join-Path $buildRoot 'openssl-build'
    $opensslInstall = Join-Path $buildRoot 'openssl-install'
    New-Item -ItemType Directory -Force -Path $opensslBuild | Out-Null
    Push-Location $opensslBuild
    try {
      Invoke-Build $perl @((Join-Path $opensslSource 'Configure'), 'VC-WIN64A',
        "--prefix=$opensslInstall", '--libdir=lib', 'no-shared', 'no-module', 'no-tests', 'no-asm') `
        (Join-Path $buildRoot 'openssl-configure.log')
      Invoke-Build $nmake @('build_libs') (Join-Path $buildRoot 'openssl-build.log')
      Invoke-Build $nmake @('install_dev') (Join-Path $buildRoot 'openssl-install.log')
    } finally { Pop-Location }
    foreach ($entry in @{
      OPENSSL_DIR = $opensslInstall; OPENSSL_ROOT_DIR = $opensslInstall; OPENSSL64DIR = $opensslInstall
      OPENSSL_INCLUDE_DIR = "$opensslInstall/include"; OPENSSL_LIB_DIR = "$opensslInstall/lib"
      OPENSSL_SSL_LIBRARY = "$opensslInstall/lib/libssl.lib"; OPENSSL_CRYPTO_LIBRARY = "$opensslInstall/lib/libcrypto.lib"
      OPENSSL_LIBS = 'libssl:libcrypto'; PICOQUIC_INCLUDE_DIR = "$SourceDirectory/vendor/picoquic/picoquic"
      PICOQUIC_LIB_DIR = "$buildRoot/picoquic/lib"; PICOTLS_INCLUDE_DIR = "$buildRoot/picoquic/cmake/_deps/picotls-src/include"
    }.GetEnumerator()) { Set-BuildEnvironment $entry.Key $entry.Value }
    # Use the pinned upstream's existing Windows compatibility overlay and build.
    & (Join-Path $SourceDirectory 'scripts/build_picoquic_windows.ps1') -RepoRoot $SourceDirectory `
      -StageDir "$buildRoot/picoquic/lib" -OpenSslStageDir "$buildRoot/openssl-stage" `
      *> (Join-Path $buildRoot 'picoquic-build.log')
    Invoke-Build $cargo @('build', '--locked', '--release', '-p', 'slipstream-client',
      '--bin', 'slipstream-client', '--features', 'openssl-static,picoquic-minimal-build') `
      (Join-Path $buildRoot 'cargo-build.log')
    Copy-Item -Force -LiteralPath (Join-Path $env:CARGO_TARGET_DIR 'release/slipstream-client.exe') `
      -Destination (Join-Path $OutputDirectory 'slipstream-client.exe')
  } finally { Pop-Location }
} finally {
  foreach ($entry in $savedEnvironment.GetEnumerator()) {
    [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value)
  }
}
