[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet("android", "windows", "apple")]
  [string]$Lane,
  [Parameter(Mandatory)]
  [string]$FirstBuildRoot,
  [Parameter(Mandatory)]
  [string]$SecondBuildRoot,
  [Parameter(Mandatory)]
  [string]$Output,
  [string]$RepositoryRoot,
  [string[]]$Sbom = @(),
  [switch]$RequireCleanSource
)

$ErrorActionPreference = "Stop"
if (-not $RepositoryRoot) {
  $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)
$FirstBuildRoot = [System.IO.Path]::GetFullPath($FirstBuildRoot)
$SecondBuildRoot = [System.IO.Path]::GetFullPath($SecondBuildRoot)
$Output = [System.IO.Path]::GetFullPath($Output)

function Get-Sha256([string]$Path) {
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-ArtifactManifest([string]$Root) {
  if (Test-Path -LiteralPath $Root -PathType Leaf) {
    $file = Get-Item -LiteralPath $Root
    return @(
      [ordered]@{
        path = $file.Name
        size = [int64]$file.Length
        sha256 = Get-Sha256 $file.FullName
      }
    )
  }
  if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw "Artifact root does not exist: $Root"
  }
  return @(
    Get-ChildItem -LiteralPath $Root -Recurse -File |
      ForEach-Object {
        [ordered]@{
          path = [System.IO.Path]::GetRelativePath($Root, $_.FullName).Replace("\", "/")
          size = [int64]$_.Length
          sha256 = Get-Sha256 $_.FullName
        }
      } |
      Sort-Object -Property path
  )
}

function Get-ManifestDigest([object[]]$Manifest) {
  $canonical = (($Manifest | ForEach-Object {
    "$($_.path)`t$($_.size)`t$($_.sha256)"
  }) -join "`n") + "`n"
  $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($canonical)
  return [Convert]::ToHexString(
    [System.Security.Cryptography.SHA256]::HashData($bytes)
  ).ToLowerInvariant()
}

$first = @(Get-ArtifactManifest $FirstBuildRoot)
$second = @(Get-ArtifactManifest $SecondBuildRoot)
if ($first.Count -eq 0) {
  throw "The first build contains no artifact files."
}
$firstCanonical = $first | ConvertTo-Json -Depth 5 -Compress
$secondCanonical = $second | ConvertTo-Json -Depth 5 -Compress
if ($firstCanonical -cne $secondCanonical) {
  $firstLines = @($first | ForEach-Object { "$($_.path)`t$($_.size)`t$($_.sha256)" })
  $secondLines = @($second | ForEach-Object { "$($_.path)`t$($_.size)`t$($_.sha256)" })
  $differences = Compare-Object $firstLines $secondLines
  $detail = ($differences | Out-String).Trim()
  throw "The two $Lane build trees are not byte-identical.`n$detail"
}

$git = Get-Command git -ErrorAction Stop
$sourceCommit = (& $git.Source -C $RepositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
  throw "Could not resolve the exact source revision."
}
$dirty = @(& $git.Source -C $RepositoryRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0) {
  throw "Could not inspect source cleanliness."
}
if ($RequireCleanSource -and $dirty.Count -gt 0) {
  throw "Release artifact evidence requires a clean source checkout."
}

$releasePath = Join-Path $RepositoryRoot "config\release.json"
$release = Get-Content -Raw -LiteralPath $releasePath | ConvertFrom-Json
if ($release.state -ne "PRE_CANDIDATE_LOCAL" -or $release.candidate_created -ne $false) {
  throw "This CI evidence writer is restricted to honest pre-candidate source state."
}
$goCommand = Get-Command go -ErrorAction Stop
$goVersion = (& $goCommand.Source env GOVERSION).Trim()
if ($LASTEXITCODE -ne 0 -or $goVersion -ne $release.go_toolchain) {
  throw "Expected $($release.go_toolchain), got '$goVersion'."
}

$contractHashes = [ordered]@{}
foreach ($relative in @(
  "config/release.json",
  "config/abi-contract.json",
  "config/core-event-abi.json",
  "config/awg2-capability.json",
  "config/awg31-capability.json",
  "go.sum",
  "engine/sing-box/go.sum"
)) {
  $path = Join-Path $RepositoryRoot $relative
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Required release input is missing: $relative"
  }
  $contractHashes[$relative] = Get-Sha256 $path
}

$sbomEvidence = @()
foreach ($sbomPath in $Sbom) {
  $resolved = [System.IO.Path]::GetFullPath($sbomPath)
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "SBOM does not exist: $resolved"
  }
  $null = Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json
  $file = Get-Item -LiteralPath $resolved
  $sbomEvidence += [ordered]@{
    name = $file.Name
    size = [int64]$file.Length
    sha256 = Get-Sha256 $resolved
  }
}

$manifestDigest = Get-ManifestDigest $first
$report = [ordered]@{
  schema = "pokrov.core.pre-candidate-artifact-evidence/v1"
  lane = $Lane
  state = "PRE_CANDIDATE_LOCAL"
  candidate_created = $false
  candidate_proven = $false
  promotion_authorized = $false
  provenance_status = "UNSIGNED_CI_BUILD_EVIDENCE"
  source = [ordered]@{
    commit = $sourceCommit
    clean = ($dirty.Count -eq 0)
  }
  toolchain = [ordered]@{
    go = $goVersion
    runner_os = [string]$env:RUNNER_OS
  }
  workflow = [ordered]@{
    run_id = [string]$env:GITHUB_RUN_ID
    run_attempt = [string]$env:GITHUB_RUN_ATTEMPT
  }
  contracts = $contractHashes
  reproducibility = [ordered]@{
    result = "PASS_BYTE_IDENTICAL_TWO_BUILDS"
    file_count = $first.Count
    tree_sha256 = $manifestDigest
    files = $first
  }
  sbom = $sbomEvidence
  evidence_ceiling = "LOCAL_OR_HOSTED_PRE_CANDIDATE_CI"
}

$parent = Split-Path -Parent $Output
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$json = $report | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText(
  $Output,
  $json + "`n",
  [System.Text.UTF8Encoding]::new($false)
)
Write-Host "$Lane artifact evidence OK: two byte-identical builds, $($first.Count) files, tree SHA-256 $manifestDigest." -ForegroundColor Green
