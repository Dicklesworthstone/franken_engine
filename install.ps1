# frankenctl PowerShell installer (franken_engine)
#
# Usage:
#   irm https://raw.githubusercontent.com/Dicklesworthstone/franken_engine/main/install.ps1 | iex
#
# With options (download, then invoke as a scriptblock):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Dicklesworthstone/franken_engine/main/install.ps1))) -Version v0.1.0 -EasyMode
#
# Options:
#   -Version vX.Y.Z   Install a specific release tag (default: latest)
#   -Dest DIR         Install dir (default: %USERPROFILE%\.local\bin)
#   -EasyMode         Add the install dir to your User PATH
#   -Verify           Run `frankenctl version` after install
#   -NoVerify         Skip checksum + signature verification (testing only)
#
# Release asset: frankenctl-x86_64-pc-windows-msvc.zip (+ .sha256, + .sigstore.json)
#
Param(
  [string]$Version = "",
  [string]$Dest = "$HOME\.local\bin",
  [string]$Owner = "Dicklesworthstone",
  [string]$Repo = "franken_engine",
  [string]$Checksum = "",
  [string]$ChecksumUrl = "",
  [string]$SigstoreBundleUrl = "",
  [string]$CosignIdentityRegex = "",
  [string]$CosignOidcIssuer = "",
  [string]$ArtifactUrl = "",
  [switch]$EasyMode,
  [switch]$Verify,
  [switch]$NoVerify
)

$ErrorActionPreference = "Stop"
$BinaryName = "frankenctl"

function Write-Info { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok   { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err  { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

function Test-UserPathContains {
  param([string]$PathValue, [string]$PathToFind)
  if ([string]::IsNullOrEmpty($PathValue)) { return $false }
  foreach ($entry in $PathValue.Split(';')) {
    if ($entry.TrimEnd('\') -ieq $PathToFind.TrimEnd('\')) { return $true }
  }
  return $false
}

Write-Host ""
Write-Host "frankenctl installer" -ForegroundColor Green
Write-Host "franken_engine control-plane CLI" -ForegroundColor DarkGray
Write-Host ""

# Resolve latest version if not specified
if ((-not $Version) -and (-not $ArtifactUrl)) {
  Write-Info "Resolving latest version..."
  try {
    $apiUrl = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    $release = Invoke-RestMethod -Uri $apiUrl -Headers @{"Accept"="application/vnd.github.v3+json"} -ErrorAction Stop
    $Version = $release.tag_name
    Write-Info "Resolved latest version: $Version"
  } catch {
    try {
      $redirectUrl = "https://github.com/$Owner/$Repo/releases/latest"
      Invoke-WebRequest -Uri $redirectUrl -MaximumRedirection 0 -ErrorAction Stop | Out-Null
    } catch {
      if ($_.Exception.Response.Headers.Location) {
        $location = $_.Exception.Response.Headers.Location.ToString()
        $extracted = $location -replace ".*/tag/", ""
        if ($extracted -match "^v[0-9]" -and $extracted -notmatch "/") {
          $Version = $extracted
          Write-Info "Resolved latest version via redirect: $Version"
        }
      }
    }
    if (-not $Version) {
      Write-Err "Could not resolve latest release. Re-run with -Version vX.Y.Z or -ArtifactUrl."
      exit 1
    }
  }
}

# Determine target
if (-not [Environment]::Is64BitProcess) {
  Write-Err "32-bit Windows is not supported. Please use a 64-bit system."
  exit 1
}
$target = "x86_64-pc-windows-msvc"
$zip = "$BinaryName-$target.zip"

if (-not $CosignIdentityRegex) {
  $CosignIdentityRegex = "^https://github.com/$Owner/$Repo/.github/workflows/.*@refs/tags/.*$"
}
if (-not $CosignOidcIssuer) {
  $CosignOidcIssuer = "https://token.actions.githubusercontent.com"
}

if ($ArtifactUrl) {
  $url = $ArtifactUrl
} else {
  $url = "https://github.com/$Owner/$Repo/releases/download/$Version/$zip"
}

# Unique temp dir so concurrent installers cannot collide
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("frankenctl_install_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
$zipFile = Join-Path $tmp $zip

Write-Info "Downloading $url"
try {
  Invoke-WebRequest -Uri $url -OutFile $zipFile -UseBasicParsing
} catch {
  Write-Err "Failed to download artifact: $_"
  Write-Err "No prebuilt Windows asset for $Version? See the Releases page or build from source."
  exit 1
}

# Verify checksum (unless -NoVerify)
if (-not $NoVerify) {
  $checksumToUse = $Checksum
  if (-not $checksumToUse) {
    if (-not $ChecksumUrl) { $ChecksumUrl = "$url.sha256" }
    Write-Info "Fetching checksum from $ChecksumUrl"
    try {
      $checksumToUse = (Invoke-WebRequest -Uri $ChecksumUrl -UseBasicParsing).Content.Trim().Split(' ')[0]
    } catch {
      Write-Err "Checksum file not found or invalid; refusing to install."
      exit 1
    }
  }
  $hash = Get-FileHash $zipFile -Algorithm SHA256
  if ($hash.Hash.ToLower() -ne $checksumToUse.ToLower()) {
    Write-Err "Checksum mismatch! Expected $checksumToUse, got $($hash.Hash.ToLower())"
    exit 1
  }
  Write-Ok "Checksum verified"

  # Sigstore/cosign (best-effort)
  if (Get-Command cosign -ErrorAction SilentlyContinue) {
    if (-not $SigstoreBundleUrl) { $SigstoreBundleUrl = "$url.sigstore.json" }
    $bundleFile = Join-Path $tmp ([System.IO.Path]::GetFileName($SigstoreBundleUrl))
    try {
      Invoke-WebRequest -Uri $SigstoreBundleUrl -OutFile $bundleFile -UseBasicParsing
      & cosign verify-blob --bundle $bundleFile --certificate-identity-regexp $CosignIdentityRegex --certificate-oidc-issuer $CosignOidcIssuer $zipFile | Out-Null
      if ($LASTEXITCODE -ne 0) { Write-Err "Signature verification failed"; exit 1 }
      Write-Ok "Signature verified (cosign)"
    } catch {
      Write-Warn "Sigstore bundle not found; skipping signature verification"
    }
  } else {
    Write-Warn "cosign not found; skipping signature verification"
  }
} else {
  Write-Warn "Verification skipped (-NoVerify)"
}

# Extract
Write-Info "Extracting..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
$extractDir = Join-Path $tmp "extract"
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $extractDir)

$bin = Get-ChildItem -Path $extractDir -Recurse -Filter "$BinaryName.exe" | Select-Object -First 1
if (-not $bin) {
  Write-Err "Binary $BinaryName.exe not found in archive"
  exit 1
}

# Install
if (-not (Test-Path $Dest)) { New-Item -ItemType Directory -Force -Path $Dest | Out-Null }
$installed = Join-Path $Dest "$BinaryName.exe"
Copy-Item $bin.FullName $installed -Force
Write-Ok "Installed $BinaryName -> $installed"

# PATH management
$path = [Environment]::GetEnvironmentVariable("PATH", "User")
if (-not (Test-UserPathContains -PathValue $path -PathToFind $Dest)) {
  if ($EasyMode) {
    if ([string]::IsNullOrEmpty($path)) {
      [Environment]::SetEnvironmentVariable("PATH", $Dest, "User")
    } else {
      [Environment]::SetEnvironmentVariable("PATH", "$path;$Dest", "User")
    }
    Write-Ok "Added $Dest to User PATH (restart your shell)"
  } else {
    Write-Warn "$Dest is not on PATH. Add it, or re-run with -EasyMode"
  }
}

# Cleanup
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

# Self-test
if ($Verify) {
  Write-Info "Running self-test..."
  try { & $installed version | Out-Null; Write-Ok "Self-test passed" }
  catch { Write-Warn "Self-test could not run $BinaryName" }
}

Write-Host ""
Write-Ok "Done. frankenctl installed at: $installed"
Write-Info "Run 'frankenctl --help' to get started."
Write-Info "Uninstall: Remove-Item '$installed'"
