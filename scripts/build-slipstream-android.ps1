[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$SourceDirectory,
  [Parameter(Mandatory)][string]$OutputDirectory,
  [Parameter(Mandatory)][string]$AndroidNdk,
  [Parameter(Mandatory)][string[]]$ToolDirectories,
  [ValidateSet('armeabi-v7a', 'arm64-v8a', 'x86_64')]
  [string[]]$Abis = @('armeabi-v7a', 'arm64-v8a', 'x86_64')
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$release = [IO.File]::ReadAllText((Join-Path $root 'config/release.json')) | ConvertFrom-Json
$pin = $release.engine.slipstream
$SourceDirectory = [IO.Path]::GetFullPath($SourceDirectory)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$AndroidNdk = [IO.Path]::GetFullPath($AndroidNdk)
$revision = (& git -C $SourceDirectory rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $revision -ne $pin.revision) {
  throw 'Slipstream source must match config/release.json; initialize its pinned submodules first.'
}
$ndkProperties = [IO.File]::ReadAllText((Join-Path $AndroidNdk 'source.properties'))
if ($ndkProperties -notmatch ('(?m)^Pkg\.Revision\s*=\s*' + [regex]::Escape($release.engine.android_ndk) + '\s*$')) {
  throw 'Android NDK must match config/release.json.'
}
$ndkBin = Join-Path $AndroidNdk 'toolchains/llvm/prebuilt/windows-x86_64/bin'
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
  Set-BuildEnvironment PATH ((@($ToolDirectories) + $ndkBin + $env:PATH) -join [IO.Path]::PathSeparator)
  $cargo = (Get-Command cargo -ErrorAction Stop).Source
  $perl = (Get-Command perl -ErrorAction Stop).Source
  $make = (Get-Command make -ErrorAction Stop).Source
  $cmake = (Get-Command cmake -ErrorAction Stop).Source
  $ninja = (Get-Command ninja -ErrorAction Stop).Source
  $pkgconf = (Get-Command pkgconf -ErrorAction Stop).Source
  $cygpath = (Get-Command cygpath -ErrorAction Stop).Source
  # A complete MSYS/Cygwin Perl is required. Git's reduced Perl is missing build
  # modules; native Windows Perl rejects OpenSSL's Unix Android build targets.
  $perlRoot = Split-Path -Parent (Split-Path -Parent $perl)
  $perlLibraries = @("$perlRoot/share/perl5/core_perl", "$perlRoot/lib/perl5/core_perl") |
    ForEach-Object { (& $cygpath -u $_).Trim() }
  Set-BuildEnvironment PERL5LIB ($perlLibraries -join ':')
  Invoke-Build $perl @('-MIPC::Cmd', '-e', 'die "Unix Perl required\n" if $^O eq "MSWin32";') (Join-Path $buildRoot 'perl-check.log')
  Set-BuildEnvironment CC 'clang.exe'
  Set-BuildEnvironment AR 'llvm-ar.exe'
  Set-BuildEnvironment RANLIB 'llvm-ranlib.exe'
  Set-BuildEnvironment CARGO_ENCODED_RUSTFLAGS '-Clink-arg=-Wl,-z,max-page-size=16384'
  Set-BuildEnvironment CARGO_TARGET_DIR (Join-Path $buildRoot 'cargo')
  Set-BuildEnvironment OPENSSL_NO_VENDOR '1'
  Set-BuildEnvironment OPENSSL_STATIC '1'
  Set-BuildEnvironment OPENSSL_USE_STATIC_LIBS '1'
  Set-BuildEnvironment PICOQUIC_AUTO_BUILD '0'
  Set-BuildEnvironment ANDROID_NDK_HOME $AndroidNdk
  Set-BuildEnvironment ANDROID_PLATFORM "android-$($pin.android_min_api)"

  Push-Location $SourceDirectory
  try {
    $metadataText = & $cargo metadata --locked --format-version 1 --features openssl-vendored
    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the pinned Cargo dependency sources.' }
    $metadata = $metadataText | ConvertFrom-Json -Depth 100
    $opensslPackage = $metadata.packages | Where-Object name -EQ 'openssl-src'
    $opensslSource = Join-Path (Split-Path -Parent $opensslPackage.manifest_path) 'openssl'
    # Keep source and build on the same Windows drive. Otherwise Unix Perl's
    # relative source paths cannot be consumed by the native NDK clang.
    $opensslStage = Join-Path $buildRoot "openssl-src-$($opensslPackage.version)"
    if (-not (Test-Path -LiteralPath $opensslStage -PathType Container)) {
      Copy-Item -LiteralPath $opensslSource -Destination $opensslStage -Recurse
    }
    $opensslSource = $opensslStage
    $targets = @{
      'armeabi-v7a' = @('armv7-linux-androideabi', 'armv7a-linux-androideabi', 'linux-armv4', 'ARM')
      'arm64-v8a' = @('aarch64-linux-android', 'aarch64-linux-android', 'linux-aarch64', 'AArch64')
      'x86_64' = @('x86_64-linux-android', 'x86_64-linux-android', 'linux-x86_64', 'Advanced Micro Devices X86-64')
    }
    foreach ($abi in $Abis) {
      $rustTarget, $clangTarget, $opensslTarget, $elfMachine = $targets[$abi]
      $abiBuild = Join-Path $buildRoot $abi
      $opensslBuild = Join-Path $abiBuild 'openssl-build'
      $opensslInstall = Join-Path $abiBuild 'openssl'
      $picoquicBuild = Join-Path $abiBuild 'picoquic'
      New-Item -ItemType Directory -Force -Path $opensslBuild | Out-Null
      Write-Host "Building Slipstream native CLI: $abi"
      $compiler = Join-Path $ndkBin "$clangTarget$($pin.android_min_api)-clang.cmd"
      Set-BuildEnvironment "CARGO_TARGET_$($rustTarget.Replace('-', '_').ToUpperInvariant())_LINKER" $compiler
      Set-BuildEnvironment RUST_ANDROID_GRADLE_CC $compiler
      Set-BuildEnvironment RUST_ANDROID_GRADLE_AR (Join-Path $ndkBin 'llvm-ar.exe')
      Set-BuildEnvironment ANDROID_ABI $abi
      Push-Location $opensslBuild
      try {
        $configurePath = (& $cygpath -u (Join-Path $opensslSource 'Configure')).Trim()
        $configure = @($configurePath, "--prefix=$($opensslInstall.Replace('\', '/'))",
          '--openssldir=/usr/local/ssl', '--libdir=lib', 'no-shared', 'no-module', 'no-tests', 'no-comp',
          'no-zlib', 'no-zlib-dynamic', 'no-ssl3', 'no-md2', 'no-rc5', 'no-weak-ssl-ciphers',
          'no-camellia', 'no-idea', 'no-seed', 'no-stdio', $opensslTarget,
          "--target=$clangTarget$($pin.android_min_api)", '-O2', '-DANDROID', '-fPIC', '-ffunction-sections', '-fdata-sections')
        Invoke-Build $perl $configure (Join-Path $abiBuild 'openssl-configure.log')
        Invoke-Build $make @('--jobs=8', 'build_libs') (Join-Path $abiBuild 'openssl-build.log')
        Invoke-Build $make @('install_dev') (Join-Path $abiBuild 'openssl-install.log')
      } finally { Pop-Location }
      foreach ($entry in @{
        OPENSSL_DIR = $opensslInstall; OPENSSL_ROOT_DIR = $opensslInstall
        OPENSSL_INCLUDE_DIR = "$opensslInstall/include"; OPENSSL_LIB_DIR = "$opensslInstall/lib"
        OPENSSL_SSL_LIBRARY = "$opensslInstall/lib/libssl.a"; OPENSSL_CRYPTO_LIBRARY = "$opensslInstall/lib/libcrypto.a"
        PICOQUIC_BUILD_DIR = $picoquicBuild; PICOQUIC_LIB_DIR = $picoquicBuild
        PICOQUIC_INCLUDE_DIR = "$SourceDirectory/vendor/picoquic/picoquic"
        PICOTLS_INCLUDE_DIR = "$picoquicBuild/_deps/picotls-src/include"
      }.GetEnumerator()) { Set-BuildEnvironment $entry.Key $entry.Value }
      $cmakeArguments = @('-S', "$SourceDirectory/vendor/picoquic", '-B', $picoquicBuild, '-G', 'Ninja',
        "-DCMAKE_MAKE_PROGRAM=$ninja", "-DCMAKE_TOOLCHAIN_FILE=$AndroidNdk/build/cmake/android.toolchain.cmake",
        "-DANDROID_ABI=$abi", "-DANDROID_PLATFORM=android-$($pin.android_min_api)", '-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_POSITION_INDEPENDENT_CODE=ON', '-DPICOQUIC_FETCH_PTLS=ON', '-DPTLS_WITH_FUSION=OFF', '-DWITH_FUSION=OFF',
        '-DBUILD_DEMO=OFF', '-DBUILD_HTTP=OFF', '-DBUILD_LOGLIB=OFF', '-DBUILD_LOGREADER=OFF', '-Dpicoquic_BUILD_TESTS=OFF',
        "-DPKG_CONFIG_EXECUTABLE=$pkgconf", "-DOPENSSL_ROOT_DIR=$opensslInstall", "-DOPENSSL_INCLUDE_DIR=$opensslInstall/include",
        "-DOPENSSL_SSL_LIBRARY=$opensslInstall/lib/libssl.a", "-DOPENSSL_CRYPTO_LIBRARY=$opensslInstall/lib/libcrypto.a",
        '-DOPENSSL_USE_STATIC_LIBS=TRUE')
      Invoke-Build $cmake $cmakeArguments (Join-Path $abiBuild 'picoquic-configure.log')
      Invoke-Build $cmake @('--build', $picoquicBuild, '--target', 'picoquic-core', '--parallel', '8') (Join-Path $abiBuild 'picoquic-build.log')
      Invoke-Build $cargo @('build', '--locked', '--release', '-p', 'slipstream-client', '--bin', 'slipstream-client',
        '--target', $rustTarget, '--features', $pin.android_features) (Join-Path $abiBuild 'cargo-build.log')
      $client = Join-Path $env:CARGO_TARGET_DIR "$rustTarget/release/slipstream-client"
      $elf = (& (Join-Path $ndkBin 'llvm-readelf.exe') -h -l -d $client) -join "`n"
      if ($LASTEXITCODE -ne 0 -or $elf -notmatch ('Machine:\s+' + [regex]::Escape($elfMachine)) -or $elf -notmatch '\(FLAGS_1\).*\bPIE\b') {
        throw "Slipstream $abi output is not the expected Android PIE executable."
      }
      foreach ($load in [regex]::Matches($elf, '(?m)^\s*LOAD\s+.*$')) {
        $alignment = ($load.Value.Trim() -split '\s+')[-1]
        if ([Convert]::ToInt64($alignment.Substring(2), 16) -lt 16384) { throw "$abi ELF is not 16 KiB aligned." }
      }
      foreach ($dependency in [regex]::Matches($elf, '\(NEEDED\).*\[([^\]]+)\]')) {
        if ($dependency.Groups[1].Value -notin @('libc.so', 'libdl.so', 'libm.so')) { throw "$abi has an unbundled native dependency." }
      }
      $abiOutput = Join-Path $OutputDirectory $abi
      New-Item -ItemType Directory -Force -Path $abiOutput | Out-Null
      Copy-Item -Force -LiteralPath $client -Destination (Join-Path $abiOutput 'libslipstream.so')
      Write-Host "Built $abi/libslipstream.so; Android PIE and 16 KiB alignment verified."
    }
  } finally { Pop-Location }
} finally {
  foreach ($entry in $savedEnvironment.GetEnumerator()) {
    [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value)
  }
}
