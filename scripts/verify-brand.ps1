param()

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$forbidden = -join ([char[]](104, 105, 100, 100, 105, 102, 121))

$pathMatches = Get-ChildItem -LiteralPath $root -Recurse -Force |
  Where-Object {
    $_.FullName -notlike "*\.git\*" -and
    $_.Name.IndexOf($forbidden, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
  }
if ($pathMatches) {
  $pathMatches.FullName | Write-Error
  throw "Forbidden legacy brand found in repository paths."
}

$rg = Get-Command rg -ErrorAction SilentlyContinue
if (-not $rg) {
  throw "rg is required for the repository brand check."
}

Push-Location $root
try {
  $contentMatches = @(& $rg.Source -n -i --hidden -g "!.git/**" $forbidden ".")
  if ($LASTEXITCODE -gt 1) {
    throw "Brand scan failed."
  }
  if ($contentMatches.Count -gt 0) {
    $contentMatches | Write-Error
    throw "Forbidden legacy brand found in repository content."
  }
} finally {
  Pop-Location
}

Write-Host "Brand check OK." -ForegroundColor Green
