#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build script for ykcrypt with version information embedded and cross-platform support.

.DESCRIPTION
    This script builds ykcrypt with build metadata (version, git commit, build time, Go version)
    embedded via ldflags. 
    
    Note: ykcrypt uses piv-go which requires Windows Smart Card API (WinSCard). 
    Cross-compilation to Linux/macOS is not supported due to platform-specific dependencies.

.PARAMETER Version
    The version string to embed (e.g., "1.0.0"). Defaults to git tag or "dev".

.PARAMETER Platforms
    Comma-separated list of target platforms (e.g., "windows/amd64,windows/arm64").
    Use "all" to build for all supported platforms (Windows only). Defaults to current platform.

.PARAMETER Clean
    Clean build artifacts before building.

.PARAMETER SkipVersionInfo
    Skip generating Windows version info resource (faster builds).

.EXAMPLE
    .\build.ps1
    Build for current platform only.

.EXAMPLE
    .\build.ps1 -Version "1.2.0" -Platforms "all"
    Build version 1.2.0 for all supported platforms.

.EXAMPLE
    .\build.ps1 -Platforms "windows/amd64,windows/arm64"
    Build for Windows AMD64 and ARM64.

.EXAMPLE
    .\build.ps1 -Clean
    Clean and rebuild for current platform.
#>

param(
    [string]$Version = "",
    [string]$Platforms = "",
    [switch]$Clean,
    [switch]$SkipVersionInfo
)

$ErrorActionPreference = "Stop"

# Package path for ldflags
$pkg = "ykcrypt/cmd"

# Supported platforms (note: piv-go only supports Windows)
$allPlatforms = @(
    "windows/amd64",
    "windows/arm64"
)

# Determine target platforms
if (-not $Platforms) {
    # Default to current platform
    $goos = if ($IsWindows -or $env:OS -match "Windows") { "windows" } 
            elseif ($IsLinux) { "linux" } 
            elseif ($IsMacOS) { "darwin" } 
            else { "windows" }
    $goarch = $env:PROCESSOR_ARCHITECTURE
    if ($goarch -eq "AMD64") { $goarch = "amd64" }
    elseif ($goarch -match "ARM") { $goarch = "arm64" }
    else { $goarch = "amd64" }
    $targetPlatforms = @("$goos/$goarch")
} elseif ($Platforms -eq "all") {
    $targetPlatforms = $allPlatforms
} else {
    $targetPlatforms = $Platforms -split ","
}

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    if (Test-Path "bin") {
        Remove-Item "bin" -Recurse -Force
    }
    if (Test-Path "resource.syso") {
        Remove-Item "resource.syso" -Force
    }
    go clean
    Write-Host ""
}

# Get version from git tag if not specified
if (-not $Version) {
    try {
        $Version = (git describe --tags --always 2>$null)
        if (-not $Version) {
            $Version = "dev"
        }
    } catch {
        $Version = "dev"
    }
}

# Get git commit hash
try {
    $GitCommit = (git rev-parse --short HEAD 2>$null)
    if (-not $GitCommit) {
        $GitCommit = "unknown"
    }
} catch {
    $GitCommit = "unknown"
}

# Check for dirty working tree
try {
    $dirty = (git status --porcelain 2>$null)
    if ($dirty) {
        $GitCommit = "$GitCommit-dirty"
    }
} catch {
    # Ignore errors
}

# Get build time in UTC
$BuildTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Get Go version
try {
    $GoVersion = (go version) -replace "go version ", ""
} catch {
    $GoVersion = "unknown"
}

# Build ldflags
$ldflags = @(
    "-X '$pkg.Version=$Version'"
    "-X '$pkg.GitCommit=$GitCommit'"
    "-X '$pkg.BuildTime=$BuildTime'"
    "-X '$pkg.GoVersion=$GoVersion'"
    "-s -w"  # Strip debug info for smaller binary
) -join " "

Write-Host "Building ykcrypt..." -ForegroundColor Cyan
Write-Host "  Version:    $Version" -ForegroundColor Gray
Write-Host "  Git Commit: $GitCommit" -ForegroundColor Gray
Write-Host "  Build Time: $BuildTime" -ForegroundColor Gray
Write-Host "  Go Version: $GoVersion" -ForegroundColor Gray
Write-Host "  Platforms:  $($targetPlatforms -join ', ')" -ForegroundColor Gray
Write-Host ""

# Generate Windows version info if building for Windows
function New-WindowsVersionInfo {
    param($Version, $Arch)
    
    # Parse version (handle dev/non-semantic versions)
    $versionParts = $Version -replace '^v', '' -split '\.'
    $major = if ($versionParts.Length -ge 1 -and $versionParts[0] -match '^\d+$') { $versionParts[0] } else { "0" }
    $minor = if ($versionParts.Length -ge 2 -and $versionParts[1] -match '^\d+$') { $versionParts[1] } else { "0" }
    $patch = if ($versionParts.Length -ge 3 -and $versionParts[2] -match '^\d+$') { $versionParts[2] } else { "0" }
    $build = "0"
    
    # Read and update versioninfo.json template
    if (Test-Path "versioninfo.json") {
        $versionInfo = Get-Content "versioninfo.json" | ConvertFrom-Json
        
        # Update version numbers
        $versionInfo.FixedFileInfo.FileVersion.Major = [int]$major
        $versionInfo.FixedFileInfo.FileVersion.Minor = [int]$minor
        $versionInfo.FixedFileInfo.FileVersion.Patch = [int]$patch
        $versionInfo.FixedFileInfo.FileVersion.Build = [int]$build
        
        $versionInfo.FixedFileInfo.ProductVersion.Major = [int]$major
        $versionInfo.FixedFileInfo.ProductVersion.Minor = [int]$minor
        $versionInfo.FixedFileInfo.ProductVersion.Patch = [int]$patch
        $versionInfo.FixedFileInfo.ProductVersion.Build = [int]$build
        
        $versionInfo.StringFileInfo.FileVersion = $Version
        $versionInfo.StringFileInfo.ProductVersion = $Version
        
        # Update copyright year
        $currentYear = (Get-Date).Year
        $versionInfo.StringFileInfo.LegalCopyright = "Copyright © 2024-$currentYear Logicos Software"
        
        # Save updated version
        $versionInfo | ConvertTo-Json -Depth 10 | Set-Content "versioninfo.json.tmp"
        Move-Item "versioninfo.json.tmp" "versioninfo.json" -Force
    } else {
        Write-Warning "versioninfo.json not found, skipping version info generation"
        return
    }
    
    # Check if goversioninfo is installed
    $hasGoVersionInfo = $null -ne (Get-Command "goversioninfo" -ErrorAction SilentlyContinue)
    if (-not $hasGoVersionInfo) {
        Write-Host "  Installing goversioninfo..." -ForegroundColor Yellow
        go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
    }
    
    Write-Host "  Generating Windows version resource..." -ForegroundColor Gray
    
    # Use appropriate flags for architecture
    $goversioninfoFlags = if ($Arch -eq "amd64") { "-64" } else { "" }
    & goversioninfo $goversioninfoFlags -o resource.syso
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to generate Windows version info, continuing without it..."
        if (Test-Path "resource.syso") { Remove-Item "resource.syso" -Force }
    }
}

$buildResults = @()

foreach ($platform in $targetPlatforms) {
    $parts = $platform -split "/"
    $goos = $parts[0]
    $goarch = $parts[1]
    
    $exeSuffix = if ($goos -eq "windows") { ".exe" } else { "" }
    $outDir = "bin/$goos/$goarch"
    $outFile = "$outDir/ykcrypt$exeSuffix"
    
    # Create output directory
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    
    Write-Host "Building for $goos/$goarch..." -ForegroundColor Cyan
    
    # Generate Windows version info for Windows builds
    # Note: goversioninfo doesn't support ARM64 yet, skip for non-amd64
    if ($goos -eq "windows" -and $goarch -eq "amd64" -and -not $SkipVersionInfo) {
        # Clean up any existing resource file
        if (Test-Path "resource.syso") { Remove-Item "resource.syso" -Force }
        New-WindowsVersionInfo -Version $Version -Arch $goarch
    }
    
    # Build
    $env:GOOS = $goos
    $env:GOARCH = $goarch
    $env:CGO_ENABLED = "0"
    
    $buildCmd = "go build -ldflags `"$ldflags`" -o `"$outFile`" ."
    $output = & cmd /c "$buildCmd 2>&1"
    
    if ($LASTEXITCODE -eq 0) {
        $size = (Get-Item $outFile).Length / 1KB
        Write-Host "  ✓ Success: $outFile ($([math]::Round($size, 2)) KB)" -ForegroundColor Green
        $buildResults += @{
            Platform = $platform
            Success = $true
            Output = $outFile
            Size = $size
        }
    } else {
        Write-Host "  ✗ Failed: $platform" -ForegroundColor Red
        Write-Host "  Error: $output" -ForegroundColor DarkRed
        $buildResults += @{
            Platform = $platform
            Success = $false
            Error = $output
        }
    }
    
    # Clean up Windows version resource after each Windows build
    if ($goos -eq "windows" -and (Test-Path "resource.syso")) {
        Remove-Item "resource.syso" -Force
    }
    
    Write-Host ""
}

# Summary
Write-Host "Build Summary:" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Gray
$successful = $buildResults | Where-Object { $_.Success }
$failed = $buildResults | Where-Object { -not $_.Success }

if ($successful) {
    Write-Host "Successful builds:" -ForegroundColor Green
    foreach ($result in $successful) {
        Write-Host "  ✓ $($result.Platform.PadRight(20)) → $($result.Output) ($([math]::Round($result.Size, 2)) KB)" -ForegroundColor Gray
    }
}

if ($failed) {
    Write-Host ""
    Write-Host "Failed builds:" -ForegroundColor Red
    foreach ($result in $failed) {
        Write-Host "  ✗ $($result.Platform)" -ForegroundColor DarkRed
    }
}

Write-Host ""
if ($failed) {
    Write-Host "Build completed with errors!" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "All builds successful!" -ForegroundColor Green
}
