#!/bin/bash
# Vultisig wallet-core build script
# Builds TrustWallet's wallet-core for Vultisig integration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WALLET_CORE_DIR="$SCRIPT_DIR/third_party/wallet-core"
BUILD_DIR="$SCRIPT_DIR/target/wallet-core-build"
INSTALL_DIR="$SCRIPT_DIR/target/wallet-core-install"

echo "🔧 Building wallet-core for Vultisig integration..."

# Check if wallet-core exists
if [ ! -d "$WALLET_CORE_DIR" ]; then
    echo "❌ Error: wallet-core directory not found at $WALLET_CORE_DIR"
    echo "Run: git submodule update --init --recursive"
    exit 1
fi

# Create build directories
mkdir -p "$BUILD_DIR"
mkdir -p "$INSTALL_DIR"

# Detect platform
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    CMAKE_OSX_DEPLOYMENT_TARGET="10.14"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
else
    echo "❌ Unsupported platform: $OSTYPE"
    exit 1
fi

echo "🖥️  Building for platform: $PLATFORM"

# Build wallet-core with CMake
cd "$BUILD_DIR"

cmake "$WALLET_CORE_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    -DBUILD_SHARED_LIBS=OFF \
    -DTW_BUILD_EXAMPLES=OFF \
    -DTW_BUILD_TESTS=OFF \
    -DTW_ENABLE_PVS_STUDIO=OFF \
    -DTW_ENABLE_CLANG_TIDY=OFF \
    ${CMAKE_OSX_DEPLOYMENT_TARGET:+-DCMAKE_OSX_DEPLOYMENT_TARGET=$CMAKE_OSX_DEPLOYMENT_TARGET}

echo "🔨 Compiling wallet-core..."
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo "📦 Installing wallet-core..."
make install

echo "✅ wallet-core build completed successfully!"
echo "📍 Installation directory: $INSTALL_DIR"

# Create a summary
echo ""
echo "📊 Build Summary:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Platform:     $PLATFORM"
echo "Build Type:   Release"  
echo "Source:       $WALLET_CORE_DIR"
echo "Build:        $BUILD_DIR"
echo "Install:      $INSTALL_DIR"
echo ""

# List installed libraries
if [ -d "$INSTALL_DIR/lib" ]; then
    echo "📚 Installed Libraries:"
    ls -la "$INSTALL_DIR/lib/" | grep -E '\.(a|dylib|so)$' || echo "None found"
fi

echo ""
echo "🚀 To use in Rust, add to Cargo.toml:"
echo "   [build-dependencies]"
echo "   cmake = \"0.1\""
echo ""
echo "   [dependencies] "
echo "   # Add wallet-core FFI bindings here"
echo ""
echo "✨ Ready for Vultisig integration!"