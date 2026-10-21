# Build libhat_scan.dll and copy it next to the Python package.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/build_native.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/build_native.ps1 -Configuration Debug
#
# Requirements:
#   - CMake 3.23+
#   - Visual Studio 2022/2026 C++ toolchain (or another CMake C++20 generator)
#   - The sibling libhat checkout, or network access for FetchContent

[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [string]$BuildDir = "",

    [string]$LibhatSource = "",

    [string]$Generator = "",

    [string]$Architecture = "x64",

    [switch]$NoCopy
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$nativeDir = Join-Path $repoRoot "native"
$packageDir = Join-Path $repoRoot "src\libhat_sigmaker"

if (-not $BuildDir) {
    $BuildDir = Join-Path $repoRoot "build\native"
}

if (-not $LibhatSource) {
    $sibling = Join-Path (Split-Path -Parent $repoRoot) "libhat"
    if (Test-Path (Join-Path $sibling "CMakeLists.txt")) {
        $LibhatSource = (Resolve-Path $sibling).Path
        Write-Host "Using sibling libhat: $LibhatSource"
    } else {
        Write-Host "No sibling libhat checkout found; CMake will fetch BasedInc/libhat v0.11.1."
    }
}

$configureArgs = @("-S", $nativeDir, "-B", $BuildDir)
if ($Generator) {
    $configureArgs += @("-G", $Generator)
}
$configureArgs += @("-A", $Architecture)
if ($LibhatSource) {
    $configureArgs += "-DLIBHAT_SOURCE_DIR=$LibhatSource"
}

Write-Host "Configuring native bridge..."
& cmake @configureArgs
if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed with exit code $LASTEXITCODE"
}

Write-Host "Building libhat_scan ($Configuration)..."
& cmake --build $BuildDir --config $Configuration --parallel
if ($LASTEXITCODE -ne 0) {
    throw "CMake build failed with exit code $LASTEXITCODE"
}

$builtDll = Join-Path $BuildDir "bin\$Configuration\libhat_scan.dll"
if (-not (Test-Path $builtDll)) {
    throw "Build succeeded but $builtDll was not produced."
}

if (-not $NoCopy) {
    New-Item -ItemType Directory -Force -Path $packageDir | Out-Null
    Copy-Item -Force $builtDll (Join-Path $packageDir "libhat_scan.dll")
    Write-Host "Copied libhat_scan.dll to $packageDir"
}

Write-Host "Done: $builtDll"
