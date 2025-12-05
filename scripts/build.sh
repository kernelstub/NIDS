#!/bin/bash

# Build script for Network Intrusion Detection System

# Default build type
BUILD_TYPE="Release"
CLEAN=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--debug] [--clean]"
            exit 1
            ;;
    esac
done

# Set build directory
BUILD_DIR="../build"

# Clean build if requested
if [ "$CLEAN" = true ] && [ -d "$BUILD_DIR" ]; then
    echo "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

# Create build directory if it doesn't exist
if [ ! -d "$BUILD_DIR" ]; then
    mkdir -p "$BUILD_DIR"
fi

# Navigate to build directory
cd "$BUILD_DIR" || exit 1

# Configure with CMake
echo "Configuring CMake for $BUILD_TYPE build..."
if ! cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" ..; then
    echo "CMake configuration failed!"
    exit 1
fi

# Build the project
echo "Building project..."
if ! cmake --build . --config "$BUILD_TYPE"; then
    echo "Build failed!"
    exit 1
fi

echo "Build completed successfully!"
