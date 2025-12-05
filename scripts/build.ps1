# Build script for Network Intrusion Detection System

# Parameters
param (
    [ValidateSet("Debug", "Release")]
    [string]$BuildType = "Release",
    [switch]$Clean = $false
)

# Set build directory
$BuildDir = "..\build"

# Clean build if requested
if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "Cleaning build directory..."
    Remove-Item -Path $BuildDir -Recurse -Force
}

# Create build directory if it doesn't exist
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

# Navigate to build directory
Push-Location $BuildDir

try {
    # Configure with CMake
    Write-Host "Configuring CMake for $BuildType build..."
    cmake -G "Visual Studio 17 2022" -A x64 "-DCMAKE_BUILD_TYPE=$BuildType" ..

    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed!"
    }

    # Build the project
    Write-Host "Building project..."
    cmake --build . --config $BuildType

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed!"
    }

    Write-Host "Build completed successfully!"
} catch {
    Write-Error $_.Exception.Message
    exit 1
} finally {
    # Return to original directory
    Pop-Location
}
